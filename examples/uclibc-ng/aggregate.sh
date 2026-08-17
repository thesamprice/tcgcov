#!/bin/bash
# Per-test .cov -> per-test LCOV -> merged, library-only report + HTML.
#
# Each test is symbolized against ITS OWN binary (static libc code sits at a
# different address per binary), then tcgcov merge unions them BY SOURCE LINE.
# Coverage is restricted to the uClibc library: the harness's own .c is
# excluded on the way in, and only SF blocks under the library source root are
# kept on the way out (preserving BRDA, which lcov --extract drops).
set -u
here=$(cd "$(dirname "$0")" && pwd); source "$here/env.sh"
LIBPREFIX=$(basename "$UCLIBC_SRC")/          # e.g. uClibc-ng-1.0.55/
SR=$(dirname "$UCLIBC_SRC")                    # source-root the paths normalize against
rm -rf "$AGGDIR"; mkdir -p "$AGGDIR/info"

ok=0; n=0
for C in "$COVDIR"/*.cov; do
  base=$(basename "$C" .cov); sub=${base%%__*}; tst=${base#*__}
  E="$TESTDIR/$sub/$tst"; [ -f "$E" ] || continue
  n=$((n+1))
  $TCGCOV symbolize --cov "$C" --elf "$E" --toolchain-prefix "$TOOLCHAIN_PREFIX" \
      --source-root "$SR" --exclude uclibc-ng-test --test-id "$base" \
      --out "$AGGDIR/$base.cov.jsonl"  || continue
  $TCGCOV coverable --elf "$E" --toolchain-prefix "$TOOLCHAIN_PREFIX" \
      --source-root "$SR" --exclude uclibc-ng-test \
      --out "$AGGDIR/$base.able.jsonl" || continue
  $TCGCOV branches  --elf "$E" --cov "$C" --toolchain-prefix "$TOOLCHAIN_PREFIX" \
      --source-root "$SR" --exclude uclibc-ng-test \
      --out "$AGGDIR/$base.br.jsonl"   || true
  $TCGCOV lcov "$AGGDIR/$base.cov.jsonl" --coverable "$AGGDIR/$base.able.jsonl" \
      $( [ -s "$AGGDIR/$base.br.jsonl" ] && echo --branches "$AGGDIR/$base.br.jsonl" ) \
      --test-name "$sub/$tst" --out "$AGGDIR/info/$base.info" || continue
  ok=$((ok+1))
done
echo "symbolized ok=$ok / n=$n"

$TCGCOV merge "$AGGDIR"/info/*.info --name uclibc-ng-suite --out "$AGGDIR/merged.info"

# Keep only the uClibc library SF-blocks, preserving DA/FN/BRDA verbatim.
# (lcov --extract silently drops branch records here, so filter directly.)
python3 - "$AGGDIR/merged.info" "$OUTINFO" "$LIBPREFIX" <<'PY'
import sys
src, dst, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
out=[]; block=[]; keep=False
for line in open(src):
    block.append(line)
    if line.startswith("SF:"): keep = line[3:].strip().startswith(prefix)
    if line.startswith("end_of_record"):
        if keep: out.extend(block)
        block=[]; keep=False
open(dst,"w").writelines(out)
PY
sed -i.bak 's/^TN:.*/TN:uclibc-ng-suite/' "$OUTINFO" && rm -f "$OUTINFO.bak"

RC="--rc lcov_branch_coverage=1"
lcov $RC --summary "$OUTINFO" 2>&1 | grep -iE 'lines|functions|branches'
( cd "$SR" && genhtml --quiet --branch-coverage $RC --legend \
    --title 'uClibc-ng under QEMU + tcgcov, microblazeel static' \
    -o "$HTMLDIR" "$OUTINFO" )
echo "HTML: $HTMLDIR/index.html"
