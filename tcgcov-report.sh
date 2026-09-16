#!/usr/bin/env bash
#
# tcgcov-report.sh - compatibility wrapper for `tcgcov report`.
#
# The pipeline this script used to drive by hand now lives in the package, as
# the `tcgcov report` subcommand: same steps, same output tree, same options,
# but installed with the wheel (this script is not) and runnable anywhere
# Python runs rather than only where bash and GNU coreutils are.
#
# Every option this script accepted is an option of `tcgcov report`, so the
# invocation below is a pass-through. The one difference is HTML: `tcgcov
# report` emits LCOV only unless asked, and this script always rendered it, so
# --html is added here to keep existing callers' output identical.
#
# Prefer calling the subcommand directly in new work:
#
#   tcgcov report --raw-dir coverage/raw --out-dir coverage --html \
#       --source-root /path/to/src \
#       --toolchain-prefix riscv64-unknown-elf- --arch riscv
#
# Run `tcgcov report --help` for the full option list.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run the package from the repo checkout unless it is already importable.
if python3 -c "import tcgcov" 2>/dev/null; then
  TCGCOV=(python3 -m tcgcov)
else
  TCGCOV=(env "PYTHONPATH=$HERE${PYTHONPATH:+:$PYTHONPATH}" python3 -m tcgcov)
fi

# JOBS was this script's parallelism knob; it is --jobs on the subcommand.
JOBS_OPT=()
[[ -n "${JOBS:-}" ]] && JOBS_OPT=(--jobs "$JOBS")

exec "${TCGCOV[@]}" report --html ${JOBS_OPT[@]+"${JOBS_OPT[@]}"} "$@"
