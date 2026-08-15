#!/bin/bash
# Build the cross-object reuse fixture against an RTEMS mbv build tree.
# Two-pass link, like the dl testsuite: link .pre, generate the runtime
# symbol table with rtems-syms, relink with it.
#
# Usage: build-reuse-fixture.sh <rtems-src> <rtems-build/riscv/mbv> \
#          <toolchain-bin> <out-dir>
set -euo pipefail
SRC=$1; BLD=$2; TOOLS=$3; OUT=$4
HERE=$(cd "$(dirname "$0")" && pwd)

CC=$TOOLS/riscv-rtems7-gcc
SYMS=$TOOLS/rtems-syms
ARCH="-march=rv32imafc_zicsr_zifencei -mabi=ilp32f"
INC="-I$BLD/cpukit/include -I$BLD/bsps/include \
     -I$SRC/cpukit/include -I$SRC/cpukit/contrib/include -I$SRC/cpukit/score/cpu/riscv/include -I$SRC/contrib/cpukit/riscv-opcodes -I$SRC/contrib/cpukit/zlib -I$SRC/bsps/include \
     -I$SRC/bsps/riscv/include -I$SRC/bsps/riscv/mbv/include"
LINK="-qrtems $ARCH -Wl,--gc-sections \
      -L$SRC/bsps/riscv/shared/start -L$SRC/bsps/riscv/mbv/start \
      -B$BLD -L$BLD"

mkdir -p "$OUT"
cd "$OUT"

# Payloads: -O0 -g for line fidelity, function-sections like the dl tests.
$CC $ARCH -O0 -g -ffunction-sections -fdata-sections -c "$HERE/pay_a.c" -o pay_a.o
$CC $ARCH -O0 -g -ffunction-sections -fdata-sections -c "$HERE/pay_b.c" -o pay_b.o
tar cf payload.tar pay_a.o pay_b.o
python3 - <<'EOF'
data = open("payload.tar", "rb").read()
with open("payload-tar.c", "w") as f:
    f.write("#include <stddef.h>\n")
    f.write("const unsigned char payload_tar[] = {\n")
    for i in range(0, len(data), 12):
        f.write("  " + ",".join(str(b) for b in data[i:i+12]) + ",\n")
    f.write("};\nconst size_t payload_tar_size = sizeof(payload_tar);\n")
with open("payload-tar.h", "w") as f:
    f.write("#include <stddef.h>\n")
    f.write("extern const unsigned char payload_tar[];\n")
    f.write("extern const size_t payload_tar_size;\n")
EOF

$CC $ARCH -O2 -g $INC -I"$OUT" -c "$HERE/reuse-init.c"    -o reuse-init.o
$CC $ARCH -O2 -g $INC        -c "$HERE/rtl-map-dump.c"    -o rtl-map-dump.o
$CC $ARCH -O2 -g             -c payload-tar.c             -o payload-tar.o

$CC $LINK reuse-init.o rtl-map-dump.o payload-tar.o \
    -Wl,--start-group -lrtemsbsp -lrtemscpu -Wl,--end-group -o reuse.pre
$SYMS -e -C "$CC" -c "$ARCH" -o reuse-sym.o reuse.pre
$CC $LINK reuse-init.o rtl-map-dump.o payload-tar.o reuse-sym.o \
    -Wl,--start-group -lrtemsbsp -lrtemscpu -Wl,--end-group -o reuse.exe
echo "built: $OUT/reuse.exe"
