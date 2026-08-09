#!/usr/bin/env bash
#
# tcgcov-report.sh - drive the full tcgcov pipeline end to end:
#
#   <raw>/*.cov
#     -> <out>/symbolized/*.jsonl        (tcgcov symbolize)
#     -> <out>/coverable/*.jsonl         (tcgcov coverable, cached per ELF)
#     -> <out>/lcov/per-test/*.info      (tcgcov lcov)
#     -> <out>/lcov/aggregate-<arch>.info (tcgcov merge)
#     -> <out>/html/index.html           (genhtml)
#
# The ELF for each .cov is read from that .cov's own embedded metadata, so no
# separate manifest is required. The toolchain prefix supplies addr2line and
# objdump; leave it empty to use the host toolchain.
#
# Usage:
#   tcgcov-report.sh --raw-dir DIR --out-dir DIR \
#       [--source-root SRC] [--toolchain-prefix PREFIX] [--arch ARCH] \
#       [--all-paths] [--keep MARKER ...] [--exclude GLOB ...] \
#       [--preset NAME] [--no-branches]
#
# Example (cross target):
#   tcgcov-report.sh --raw-dir coverage/raw --out-dir coverage \
#       --source-root ~/src/myproject \
#       --toolchain-prefix riscv64-unknown-elf- --arch riscv
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run the package from the repo checkout unless it is already importable.
if python3 -c "import tcgcov" 2>/dev/null; then
  TCGCOV=(python3 -m tcgcov)
else
  TCGCOV=(env "PYTHONPATH=$HERE${PYTHONPATH:+:$PYTHONPATH}" python3 -m tcgcov)
fi

RAW_DIR=""
SOURCE_ROOT=""
OUT_DIR=""
PREFIX=""
ARCH=""
BRANCHES=1
ALL_PATHS=()
KEEP_ARGS=()
EXCLUDE_ARGS=()
PRESET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --raw-dir)          RAW_DIR="$2"; shift 2 ;;
    --source-root)      SOURCE_ROOT="$2"; shift 2 ;;
    --out-dir)          OUT_DIR="$2"; shift 2 ;;
    --toolchain-prefix) PREFIX="$2"; shift 2 ;;
    --arch)             ARCH="$2"; shift 2 ;;
    --all-paths)        ALL_PATHS=(--all-paths); shift ;;
    --keep)             KEEP_ARGS+=(--keep "$2"); shift 2 ;;
    --exclude)          EXCLUDE_ARGS+=(--exclude "$2"); shift 2 ;;
    --preset)           PRESET="$2"; shift 2 ;;
    --no-branches)      BRANCHES=0; shift ;;
    -h|--help)          sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$RAW_DIR" && -n "$OUT_DIR" ]] || {
  echo "usage: tcgcov-report.sh --raw-dir DIR --out-dir DIR [--source-root SRC]" >&2
  echo "       [--toolchain-prefix PREFIX] [--arch ARCH] [--all-paths]" >&2
  echo "       [--keep MARKER ...] [--exclude GLOB ...] [--preset NAME]" >&2
  echo "       [--no-branches]" >&2
  exit 2
}

# --source-root is optional, but without it (and without --keep/--all-paths)
# the tools fall back to absolute source paths and warn: absolute paths defeat
# merge-by-source, so an aggregate across several binaries needs a source root.
SRC_OPT=()
[[ -n "$SOURCE_ROOT" ]] && SRC_OPT=(--source-root "$SOURCE_ROOT")
PREFIX_OPT=(--toolchain-prefix "$PREFIX")
OBJDUMP="${PREFIX}objdump"

# Path-selection options passed through to every producer, so the covered and
# coverable sides derive identical keys. They must agree or the merge is wrong.
#
# Note the ${arr[@]+"${arr[@]}"} idiom used for every possibly-empty array
# below: bash before 4.4 -- which includes the 3.2 that macOS still ships --
# treats "${arr[@]}" on an empty array as an unbound variable under `set -u`.
PATH_OPTS=(${SRC_OPT[@]+"${SRC_OPT[@]}"} ${ALL_PATHS[@]+"${ALL_PATHS[@]}"} ${KEEP_ARGS[@]+"${KEEP_ARGS[@]}"} \
          ${EXCLUDE_ARGS[@]+"${EXCLUDE_ARGS[@]}"})
[[ -n "$PRESET" ]] && PATH_OPTS+=(--preset "$PRESET")

read_meta() {  # read_meta <cov> <key>
  "${TCGCOV[@]}" dump --metadata-only --key "$2" "$1" 2>/dev/null || true
}

shopt -s nullglob
covs=("$RAW_DIR"/*.cov)
[[ ${#covs[@]} -gt 0 ]] || { echo "no .cov files in $RAW_DIR" >&2; exit 1; }

# Default the arch label to the target recorded by the plugin.
if [[ -z "$ARCH" ]]; then
  ARCH="$(read_meta "${covs[0]}" target_name)"
  ARCH="${ARCH:-unknown}"
  echo "arch not given; using target from .cov metadata: $ARCH" >&2
fi

SYM_DIR="$OUT_DIR/symbolized"
CAB_DIR="$OUT_DIR/coverable"
PT_DIR="$OUT_DIR/lcov/per-test"
AGG="$OUT_DIR/lcov/aggregate-$ARCH.info"
HTML_DIR="$OUT_DIR/html"
mkdir -p "$SYM_DIR" "$CAB_DIR" "$PT_DIR" "$HTML_DIR"

DIS_DIR="$OUT_DIR/disasm"
mkdir -p "$DIS_DIR" "$OUT_DIR/branches"

# Cache keys must include the path options: the coverable inventory is keyed by
# NORMALIZED source path, so the same ELF analysed with a different
# --source-root/--keep/--exclude yields a different, incompatible denominator.
# Keying on the ELF path alone silently reused the wrong one across runs.
opt_sig="$(printf '%s\0' "$ARCH" ${PATH_OPTS[@]+"${PATH_OPTS[@]}"} \
           | cksum | cut -d' ' -f1)"

# One artifact at a time was the whole pipeline's wall clock, and the per-.cov
# work is independent. Default to the CPU count; JOBS=1 restores serial order.
if [[ -z "${JOBS:-}" ]]; then
  JOBS="$( { nproc || sysctl -n hw.ncpu; } 2>/dev/null || echo 4)"
fi

process_one() {  # process_one <cov>
  local cov="$1" base elf safe dis cab br br_rc
  local -a BR_OPT=()
  base="$(basename "$cov" .cov)"
  elf="$(read_meta "$cov" elf)"
  if [[ ! -f "$elf" ]]; then
    echo "WARNING: ELF not found for $base ($elf); skipping" >&2
    return 0
  fi
  safe="${elf//\//_}"; safe="${safe//./_}"
  dis="$DIS_DIR/$safe.txt"
  cab="$CAB_DIR/$safe.$opt_sig.jsonl"

  # Disassemble each ELF ONCE. Both the coverable inventory and the branch
  # inventory parse the same `objdump -d` output; running it twice per artifact
  # was pure duplicated work, and doubly so across a suite that links the same
  # ELF into many tests.
  if [[ ! -s "$dis" ]]; then
    "${OBJDUMP}" -d "$elf" > "$dis.$base.tmp" && mv "$dis.$base.tmp" "$dis"
  fi

  # Covered lines: what actually ran.
  "${TCGCOV[@]}" symbolize --cov "$cov" --elf "$elf" \
    "${PREFIX_OPT[@]}" ${PATH_OPTS[@]+"${PATH_OPTS[@]}"} --arch "$ARCH" \
    --out "$SYM_DIR/$base.jsonl"

  # Coverable lines: the denominator. Test-agnostic, so cache it per ELF.
  if [[ ! -s "$cab" ]]; then
    "${TCGCOV[@]}" coverable --elf "$elf" --disasm "$dis" \
      "${PREFIX_OPT[@]}" ${PATH_OPTS[@]+"${PATH_OPTS[@]}"} --arch "$ARCH" \
      --out "$cab.$base.tmp" && mv "$cab.$base.tmp" "$cab"
  fi

  # Branch outcomes, when the plugin recorded edges (edges=on).
  if [[ "$BRANCHES" == 1 ]]; then
    br="$OUT_DIR/branches/$base.jsonl"
    set +e
    "${TCGCOV[@]}" branches --cov "$cov" --elf "$elf" --disasm "$dis" \
      "${PREFIX_OPT[@]}" ${PATH_OPTS[@]+"${PATH_OPTS[@]}"} --arch "$ARCH" \
      --out "$br" 2>"$br.log"
    br_rc=$?
    set -e
    # Exit 2 means this architecture has no branch profile -- an expected,
    # benign gap, so carry on with line coverage only. Anything else is a real
    # failure (an unparseable disassembly, a corrupt .cov) and must not be
    # downgraded to a note: silently dropping branch data looks exactly like a
    # genuine coverage regression.
    if [[ $br_rc -eq 0 ]]; then
      BR_OPT=(--branches "$br")
    elif [[ $br_rc -eq 2 ]]; then
      echo "note: no branch profile for arch '$ARCH'; line coverage only" >&2
    else
      echo "error: branch analysis failed for $base (rc=$br_rc):" >&2
      sed 's/^/  /' "$br.log" >&2
      return 1
    fi
  fi

  "${TCGCOV[@]}" lcov "$SYM_DIR/$base.jsonl" \
    --coverable "$cab" ${BR_OPT[@]+"${BR_OPT[@]}"} --out "$PT_DIR/$base.info"
}

# Warm the per-ELF caches serially first. Running cold in parallel would have N
# jobs disassemble and symbolize the SAME ELF concurrently -- duplicated work,
# and a torn cache file without the atomic rename above.
declare -a warmed=()
for cov in "${covs[@]}"; do
  elf="$(read_meta "$cov" elf)"
  [[ -f "$elf" ]] || continue
  case " ${warmed[*]-} " in *" $elf "*) continue ;; esac
  warmed+=("$elf")
  safe="${elf//\//_}"; safe="${safe//./_}"
  [[ -s "$DIS_DIR/$safe.txt" ]] || \
    { "${OBJDUMP}" -d "$elf" > "$DIS_DIR/$safe.txt.tmp" && \
      mv "$DIS_DIR/$safe.txt.tmp" "$DIS_DIR/$safe.txt"; }
done

have_wait_n=0
if [[ ${BASH_VERSINFO[0]:-0} -gt 4 ]] || \
   { [[ ${BASH_VERSINFO[0]:-0} -eq 4 ]] && [[ ${BASH_VERSINFO[1]:-0} -ge 3 ]]; }; then
  have_wait_n=1
fi
if [[ "$JOBS" -gt 1 && ${#covs[@]} -gt 1 && $have_wait_n -eq 1 ]]; then
  echo "processing ${#covs[@]} artifacts with $JOBS parallel jobs" >&2
  pids=()
  for cov in "${covs[@]}"; do
    while [[ "$(jobs -rp | wc -l)" -ge "$JOBS" ]]; do wait -n 2>/dev/null || break; done
    process_one "$cov" & pids+=($!)
  done
  rc=0
  for p in "${pids[@]}"; do wait "$p" || rc=1; done
  [[ $rc -eq 0 ]] || { echo "error: one or more artifacts failed" >&2; exit 1; }
else
  [[ "$JOBS" -gt 1 && $have_wait_n -eq 0 ]] && \
    echo "note: bash ${BASH_VERSION%%(*} lacks 'wait -n'; running serially" >&2
  for cov in "${covs[@]}"; do process_one "$cov"; done
fi

"${TCGCOV[@]}" merge "$PT_DIR"/*.info --name "$ARCH" --out "$AGG"

# genhtml resolves relative SF paths against cwd; absolute paths (--all-paths)
# resolve anywhere, so fall back to '/' when no source root was given.
GENHTML_OPTS=(--quiet --ignore-errors source)
[[ "$BRANCHES" == 1 ]] && GENHTML_OPTS+=(--branch-coverage)
( cd "${SOURCE_ROOT:-/}" && genhtml "$AGG" --output-directory "$HTML_DIR" \
    "${GENHTML_OPTS[@]}" )

echo "report: $HTML_DIR/index.html"
echo "aggregate: $AGG"
