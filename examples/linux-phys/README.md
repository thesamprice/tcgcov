# phys=on: guest-physical address records

Measured 2026-08-14 (PoC QEMU 10.2.4 tree, `petalogix-s3adsp1800`, the
Tier-3 Buildroot image). Closes the "guest-physical address for
instructions" issue with a finding rather than a QEMU patch:

**No QEMU modification is needed.** `qemu_plugin_translate_vaddr()` (upstream
since part-way through plugin API v5, QEMU ≥ 10.1 — probed as
`TCGCOV_HAVE_XLATE`, present in stock Homebrew QEMU 11) performs a debug MMU
walk from vCPU context, and translation-time callbacks are vCPU context. The
plugin translates each recorded address once, at translation time, where the
code's page is necessarily mapped — the CPU just fetched it.

## Usage

    -plugin libtcgcov.so,out=phys.cov,phys=on[,ctx=on][,mode=tb|tb-insn|tb-insn-fast]

Records (addresses, edge endpoints, all modes) become guest-physical;
`metadata.address_kind` is `"paddr"` and `phys_translate_failures` counts
fallbacks (a failed walk records the vaddr rather than dropping coverage).
Filter ranges still apply to **virtual** addresses. Requires system
emulation; refused in user mode, where every walk would fail.

## Measured

One 90 s boot, `ctx=on,phys=on,mode=tb,edges=on`: 1,003,576 records,
`phys_translate_failures: 0`. 56,397 of 56,400 distinct addresses fall in
the board's RAM at `0x90000000`; the 3 below it are the phys-0x0
reset/exception vectors, executed before the MMU is on — visible only in a
physical artifact.

Direct-map check against the build's System.map
(`phys = virt - 0xC0000000 + 0x90000000`):

    _start        c0000000 -> 90000000: HIT count=1
    do_IRQ        c04c04c8 -> 904c04c8: HIT count=13926
    do_page_fault c00066e8 -> 900066e8: HIT count=7254   (software TLB misses)

And the pipeline stays closed: `tcgcov rebase --base 0x90000000 --size
0x8000000 --to 0xC0000000` maps the RAM window back to kernel vaddrs, and
symbolize against `vmlinux` resolves **39,559/39,561** kernel-text
addresses to **31,505 covered kernel source lines**. The 16,836 fenced
addresses are user pages scattered through RAM — correctly excluded by the
ELF-range match.

## When to use it, honestly

* **Kernel text**: works trivially (linear direct map, one rebase).
* **Dedup same-code-different-VA** (shared libraries under ASLR, the same
  page-cache text pages mapped into many processes): phys is the natural
  key. This rootfs is all static same-base binaries, so that benefit is
  not demonstrated here.
* **Kernel modules**: phys does NOT simplify attribution — vmalloc'd module
  text is virtually contiguous but physically scattered, so the per-module
  window rebase of `examples/linux-module/` (virtual, from
  `/sys/module/*/sections/.text`) remains the right tool.
* **Interplay with ctx beacons**: beacon attribution (`examples/linux-ctx/`)
  keys on distinctive *virtual* ranges, which phys=on erases. Attribute
  contexts from a vaddr run, or extend the join to physical beacon pages.
