# Shared configuration for the uClibc-ng coverage example.
# Point these at your own tree; every path below is machine-local by design,
# so nothing here is committed with an absolute developer path baked in.
#
#   source env.sh
#
# The example was produced with a Buildroot microblazeel *glibc* cross gcc
# retargeted at a freshly built static uClibc-ng via --sysroot; see README.md.

# --- toolchain -------------------------------------------------------------
: "${TOOLCHAIN_PREFIX:=microblazeel-linux-}"        # cross binutils/gcc prefix
: "${CROSS_GCC:=${TOOLCHAIN_PREFIX}gcc}"            # the real (glibc) cross gcc

# --- uClibc-ng build products ---------------------------------------------
: "${UCLIBC_SRC:=$PWD/uClibc-ng-1.0.55}"           # library source (for --source-root)
: "${UCLIBC_SYSROOT:=$PWD/uc-install/usr/microblaze-linux-uclibc}"  # make install PREFIX sysroot
: "${KERNEL_HEADERS:=/usr/include}"                # a tree with linux/*.h + asm/*.h

# --- the test suite (github.com/wbx-github/uclibc-ng-test) ----------------
: "${TESTROOT:=$PWD/uclibc-ng-test}"
: "${TESTDIR:=$TESTROOT/test}"

# --- QEMU + tcgcov plugin (built for the SAME qemu; see plugin/Makefile) ---
: "${QEMU:=qemu-microblazeel}"                     # linux-user, --enable-plugins
: "${PLUGIN:=$PWD/libtcgcov.so}"
: "${TCGCOV:=python3 -m tcgcov}"                   # or the installed 'tcgcov'

# --- output ----------------------------------------------------------------
: "${COVDIR:=$PWD/cov}"                            # per-test .cov files
: "${AGGDIR:=$PWD/agg}"                            # per-test JSONL + .info
: "${OUTINFO:=$PWD/uclibc-ng.info}"               # merged, library-only LCOV
: "${HTMLDIR:=$PWD/html}"

# The uClibc-targeted compile driver this example generates (see README).
: "${UCLIBC_GCC:=$PWD/mb-uclibc-gcc}"

export TOOLCHAIN_PREFIX CROSS_GCC UCLIBC_SRC UCLIBC_SYSROOT KERNEL_HEADERS \
       TESTROOT TESTDIR QEMU PLUGIN TCGCOV COVDIR AGGDIR OUTINFO HTMLDIR UCLIBC_GCC
