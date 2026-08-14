# Tier 1: kernel-module coverage via the procfs sidecar

Measured 2026-08-14: QEMU 11.0.2, Buildroot `qemu_microblazeel_mmu`,
Linux 6.12.81 (`CONFIG_DEBUG_INFO=y`), `CONFIG_DUMMY=m`. See
`docs/LINUX-VM.md` §3 Tier 1.

**Guest side** (`S98covmod`): load the module, exercise it, and print the
map between markers — the console log *is* the sidecar transport:

    dummy 12288 0 - Live 0xf0073000
    /sys/module/dummy/sections/.text 0xf0073000

Exercising matters: `.init.text` is freed after load, so attribute only what
runs afterwards. `ip link add d0 type dummy && ip link set d0 up` drives the
core `.text` — the kernel's IPv6 router solicitations even reach
`dummy_xmit`.

**Host side**: window + rebase + section-relative symbolize (a `.ko` is
ET_REL, every section links at 0, so addr2line needs `-j`):

    tcgcov rebase --cov modtest.cov --base 0xf0073000 --size 0x4000 \
        --out dummy-rebased.cov
    tcgcov symbolize --cov dummy-rebased.cov --elf dummy.ko --section .text \
        --addr2line microblazeel-…-addr2line --all-paths --out dummy.jsonl

Result: `kept 13/55611 records, 2/70356 edges` (the fence line — everything
else in the boot is outside the module window), then **13/13 addrs resolved
→ 18 covered source lines**: 14 in `drivers/net/dummy.c`
(`set_multicast_list`, `dummy_get_stats64`, `dummy_xmit` count=4) and
inlined frames in `etherdevice.h`/`skbuff.h`.
