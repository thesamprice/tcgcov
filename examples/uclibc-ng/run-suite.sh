#!/bin/bash
# Build + run a curated subset of uClibc-ng-test under qemu-user + tcgcov.
# Compiles each subdir against the static uClibc, then runs it: the harness's
# .exe "run" targets do NOT rebuild, so compile must come first. -k keeps a
# subdir going past a failing test (a nonzero return still leaves a valid .cov,
# written before the harness checks the exit code).
set -u
here=$(cd "$(dirname "$0")" && pwd); source "$here/env.sh"
chmod +x "$UCLIBC_GCC" "$here/qemu-cov"

# Subdirs that link statically without threads / shared objects / locale data.
SUBDIRS="string stdlib stdio ctype math malloc misc time setjmp signal regex \
         inet silly args assert stat termios mmap crypt pwd_grp"

MK=(CC="$UCLIBC_GCC" TARGET_ARCH=microblaze CROSS_COMPILE="$TOOLCHAIN_PREFIX"
    SIMULATOR="$here/qemu-cov")

rm -rf "$COVDIR"; mkdir -p "$COVDIR"
: > "$here/run-summary.txt"
for s in $SUBDIRS; do
  [ -d "$TESTDIR/$s" ] || continue
  make -C "$TESTDIR/$s" clean            >/dev/null 2>&1
  make -k -C "$TESTDIR/$s" compile "${MK[@]}" >/dev/null 2>&1
  make -k -C "$TESTDIR/$s" run     "${MK[@]}" >/dev/null 2>&1   # nonzero is fine
  built=$(find "$TESTDIR/$s" -maxdepth 1 -type f -executable ! -name '*.sh' ! -name '*.c' | wc -l)
  covs=$(ls "$COVDIR" 2>/dev/null | grep -c "^${s}__" || true)
  printf '%-10s built=%-4s covs=%s\n' "$s" "$built" "$covs" | tee -a "$here/run-summary.txt"
done
echo "cov files: $(ls "$COVDIR" | wc -l)"
