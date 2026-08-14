# Tier 2: coverage of one userspace binary in a Linux guest

Measured 2026-08-14: QEMU 11.0.2, Buildroot `qemu_microblazeel_mmu`,
Linux 6.12.81, stock busybox rootfs. See `docs/LINUX-VM.md` §3 Tier 2.

Build the test **static, with debug info, at a distinctive base** — busybox
already owns the default ET_EXEC base (0x10000000 on MicroBlaze), and the
shared-object mmap region sits around 0x48000000:

    microblazeel-buildroot-linux-gnu-gcc -O0 -g -static \
        -Wl,-Ttext-segment=0x30000000 covtest.c -o output/target/usr/bin/covtest
    install -m0755 S99covtest output/target/etc/init.d/
    make    # regenerates the initramfs and kernel image

Boot under the plugin, then symbolize against the *test binary's* ELF; the
match-rate line fences everything else out:

    covtest.cov: 53923 addrs: 844 within ELF text, 53079 outside, 187 resolved

Result for `covtest.c`: LF:21 LH:11, BRF:6 BRH:4 — the taken/untaken pair of
`if (v > 10)` appears as BRDA outcomes 1 and 0, `never_called()` is absent,
and the loop body carries its true execution count (`DA:9,8`).

Caveat this example is built to demonstrate: at `-O2` the arithmetic
constant-folds away and those lines *correctly* vanish from the binary —
coverage of optimized builds measures the binary that exists, not the source
you imagine.
