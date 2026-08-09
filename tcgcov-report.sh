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
#       [--all-paths] [--keep MARKER ...] [--no-branches]
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
ALL_PATHS=""
KEEP_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --raw-dir)          RAW_DIR="$2"; shift 2 ;;
    --source-root)      SOURCE_ROOT="$2"; shift 2 ;;
    --out-dir)          OUT_DIR="$2"; shift 2 ;;
    --toolchain-prefix) PREFIX="$2"; shift 2 ;;
    --arch)             ARCH="$2"; shift 2 ;;
    --all-paths)        ALL_PATHS="--all-paths"; shift ;;
    --keep)             KEEP_ARGS+=(--keep "$2"); shift 2 ;;
    --no-branches)      BRANCHES=0; shift ;;
    -h|--help)          sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$RAW_DIR" && -n "$OUT_DIR" ]] || {
  echo "usage: tcgcov-report.sh --raw-dir DIR --out-dir DIR [--source-root SRC]" >&2
  echo "       [--toolchain-prefix PREFIX] [--arch ARCH] [--all-paths]" >&2
  echo "       [--keep MARKER ...] [--no-branches]" >&2
  exit 2
}

# --source-root is optional; without it, --all-paths (absolute paths) or marker
# matching must supply usable SF paths.
SRC_OPT=()
[[ -n "$SOURCE_ROOT" ]] && SRC_OPT=(--source-root "$SOURCE_ROOT")
PREFIX_OPT=(--toolchain-prefix "$PREFIX")

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

for cov in "${covs[@]}"; do
  base="$(basename "$cov" .cov)"
  elf="$(read_meta "$cov" elf)"
  if [[ ! -f "$elf" ]]; then
    echo "WARNING: ELF not found for $base ($elf); skipping" >&2
    continue
  fi

  # Covered lines: what actually ran.
  "${TCGCOV[@]}" symbolize --cov "$cov" --elf "$elf" \
    "${PREFIX_OPT[@]}" "${SRC_OPT[@]}" --arch "$ARCH" \
    $ALL_PATHS "${KEEP_ARGS[@]}" --out "$SYM_DIR/$base.jsonl"

  # Coverable lines: the denominator. Test-agnostic, so cache it per ELF.
  cab="$CAB_DIR/$(echo "$elf" | sed 's#[/.]#_#g').jsonl"
  if [[ ! -s "$cab" ]]; then
    "${TCGCOV[@]}" coverable --elf "$elf" \
      "${PREFIX_OPT[@]}" "${SRC_OPT[@]}" --arch "$ARCH" \
      $ALL_PATHS "${KEEP_ARGS[@]}" --out "$cab"
  fi

  # Branch outcomes, when the plugin recorded edges (edges=1).
  BR_OPT=()
  if [[ "$BRANCHES" == 1 ]]; then
    br="$OUT_DIR/branches/$base.jsonl"
    mkdir -p "$OUT_DIR/branches"
    if "${TCGCOV[@]}" branches --cov "$cov" --elf "$elf" \
         "${PREFIX_OPT[@]}" "${SRC_OPT[@]}" --arch "$ARCH" \
         $ALL_PATHS "${KEEP_ARGS[@]}" --out "$br" 2>"$br.log"; then
      BR_OPT=(--branches "$br")
    else
      echo "note: no branch data for $base (see $br.log)" >&2
    fi
  fi

  "${TCGCOV[@]}" lcov "$SYM_DIR/$base.jsonl" \
    --coverable "$cab" "${BR_OPT[@]}" --out "$PT_DIR/$base.info"
done

"${TCGCOV[@]}" merge "$PT_DIR"/*.info --name "$ARCH" --out "$AGG"

# genhtml resolves relative SF paths against cwd; absolute paths (--all-paths)
# resolve anywhere, so fall back to '/' when no source root was given.
GENHTML_OPTS=(--quiet --ignore-errors source)
[[ "$BRANCHES" == 1 ]] && GENHTML_OPTS+=(--branch-coverage)
( cd "${SOURCE_ROOT:-/}" && genhtml "$AGG" --output-directory "$HTML_DIR" \
    "${GENHTML_OPTS[@]}" )

echo "report: $HTML_DIR/index.html"
echo "aggregate: $AGG"
