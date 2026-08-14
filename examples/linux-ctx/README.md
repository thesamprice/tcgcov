# Tier 3: separately attributed coverage of two binaries at the same VA base

Measured 2026-08-14: the PoC QEMU (10.2.4 + the context-visibility patches,
`patches/qemu/`), Buildroot `qemu_microblazeel_mmu`, Linux 6.12.81. This is
the Tier-3 acceptance experiment from `docs/LINUX-VM.md` §3: **two
concurrently running different binaries at the same VA base produce
separately attributed coverage** — the case that is impossible in principle
without context records, because every address belongs to both programs.

## Setup

`covtest_a.c` and `covtest_b.c` are deliberately different programs
(A: 8-iteration loop, branch arm `v > 10` taken; B: 13-iteration loop, the
*other* arm taken) built static at the **same** `-Ttext-segment=0x30000000`.
The one VA-range difference is a per-binary `.beacon` section
(A: `0x30f00000`, B: `0x31000000`) holding one function called at startup —
the test-discipline hook that lets the host join context → binary when the
ranges otherwise collide:

    GCC=microblazeel-buildroot-linux-gnu-gcc
    $GCC -O0 -g -static -Wl,-Ttext-segment=0x30000000 \
        -Wl,--section-start=.beacon=0x30f00000 covtest_a.c -o .../usr/bin/cov_a
    $GCC -O0 -g -static -Wl,-Ttext-segment=0x30000000 \
        -Wl,--section-start=.beacon=0x31000000 covtest_b.c -o .../usr/bin/cov_b
    install -m0755 S98covab .../etc/init.d/    # starts both, backgrounded
    make linux-rebuild all                     # re-embed the initramfs

Each binary loops with `sleep(1)` inside `main`, so each is **one
long-lived process** — one address-space context — and the two are alive
simultaneously.

## Run

    qemu-system-microblazeel -M petalogix-s3adsp1800 -kernel linux.bin \
        -display none -serial file:serial.log \
        -plugin libtcgcov.so,out=ctx3.cov,ctx=on,mode=tb,edges=on

Both `COV-A-DONE`/`cov-b: done` markers appeared; 90 s, clean SIGTERM.
The artifact: TCGCOV2, 58.7 MB, **113 contexts, 177,839 switches**.

## Attribution

`tcgcov contexts ctx3.cov --elf cov_a.elf` range-scoring alone nearly ties
across the three same-base contexts (872–875 addrs each — the collision is
real), and the beacons break the tie exactly:

    ctx 0x54: beacon 0x30f00000 present, 0x31000000 absent  -> cov_a
    ctx 0x56: beacon 0x31000000 present, 0x30f00000 absent  -> cov_b
    ctx 0x62: neither beacon                                -> covtest (Tier-2 leftover)

## Separately attributed results

    tcgcov contexts ctx3.cov --extract 0x54 -o a.cov   # then the normal
    tcgcov contexts ctx3.cov --extract 0x56 -o b.cov   # v1 pipeline each

| | cov_a (ctx 0x54) | cov_b (ctx 0x56) |
|---|---|---|
| loop body count | `DA:19,80` (8 × 10 runs) | `DA:17,130` (13 × 10 runs) |
| branch at the `if` | `v>10` arm 10, other **0** | `v>10` arm **0**, other 10 |
| functions | beacon_a, accumulate, taken_branch, main | beacon_b, collect, low_branch, main |

And the direct proof the context axis carries information no v1 artifact
has: of the user-range addresses, **87 are covered in both contexts, 23
with different counts** — e.g. `0x300009c8` executed 70 times in cov_a's
context and 280 in cov_b's. A TCGCOV1 run would have recorded a single
blended 350.

## Caveat

Hardware context IDs are per-boot and recycled; the beacon join (or a
guest-side map dump) must come from the same boot as the artifact. And a
context is an *address space*, not a privilege level: the 5,986
kernel-range addresses inside cov_a's context are the kernel working on
cov_a's behalf — filter by VA range (as symbolize's ELF fencing already
does) when only user code is wanted.
