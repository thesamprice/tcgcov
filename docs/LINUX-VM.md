# Coverage of Linux guests with virtual memory

> **STATUS: PLAN, with one measured experiment.**
>
> Sections marked **verified** were run on 2026-08-14 against real artifacts
> (QEMU 11.0.2, a Buildroot `qemu_microblazeel_mmu` Linux 6.12.81 guest,
> tcgcov main at the time of writing). Everything else is design. Proposed
> interfaces are proposals.

---

## 1. The problem

tcgcov's whole offline pipeline rests on the assumption stated in
[DYNAMIC-OBJECTS.md](DYNAMIC-OBJECTS.md): *the address the plugin observed is
the address the DWARF line table describes*. A Linux guest with an MMU breaks
that assumption at four separate levels, each strictly harder than the last:

| level | what breaks | why |
|---|---|---|
| L0 kernel text | nothing, almost | kernel VAs are a **static** mapping (MicroBlaze: `0xC0000000` direct map), so `vmlinux` DWARF describes the observed addresses as-is |
| L1 kernel modules | runtime ≠ link address | `module_alloc` places `.ko` text at run time |
| L2 user, static/no-ASLR | address **ambiguity** | every process reuses the same VA range; the artifact cannot say *which* binary a user-mode address belongs to |
| L3 user, dynamic/ASLR | runtime ≠ link address **and** ambiguity | ld.so + per-exec randomization |

The plugin records `qemu_plugin_insn_vaddr()`/`tb_vaddr` only. It has no
notion of privilege level, address-space identity, or physical address, and
the `TCGCOV1` format has no field to carry one.

## 2. Verified: what already works today

One experiment, unmodified tcgcov, unmodified QEMU 11.0.2 (Homebrew), the
Buildroot LE image from the PR 121432 work
(`-M petalogix-s3adsp1800,endianness=little`):

* The plugin **loads and runs against a full Linux boot** — guest reaches the
  login prompt with the plugin attached, no crash, no measurable interference.
* A valid 2.3 MB `TCGCOV1` artifact is produced: **52,801 TB records** with
  counts and edges; `tcgcov dump` parses it.
* `tcgcov symbolize --elf vmlinux` runs mechanically — and produced
  **0 covered lines**, because the Buildroot defconfig `vmlinux` has **zero
  `.debug_*` sections** (`readelf -S | grep -c debug_` → 0). The pipeline is
  fine; the input had no DWARF.

So L0 is blocked today only by a kernel config, not by tcgcov.

## 3. The plan, tier by tier

### Tier 0 — kernel text coverage (no code changes expected)

1. Build the guest kernel with `CONFIG_DEBUG_INFO=y`
   (Buildroot: `BR2_LINUX_KERNEL` + kernel config fragment).
2. Re-run the §2 experiment; symbolize against the debug `vmlinux`.
3. The artifact mixes kernel and user VAs. Symbolize must handle out-of-ELF
   addresses gracefully and *say what it dropped* — a match-rate line
   ("52,801 addrs, 31,204 within ELF ranges, 0 unresolved") so a wrong-ELF
   run is distinguishable from a no-DWARF run. (The §2 experiment printed
   only `-> 0 covered source lines`, which cannot distinguish the two.)
4. Optional plugin nicety: a `filter=` range covering the kernel window
   shrinks the artifact and the symbolize time.

Acceptance: LCOV report for the guest kernel from one boot, with a
documented example in `examples/`.

### Tier 1 — kernel modules

Sidecar mapping, no QEMU changes: after the workload, the guest dumps
`/proc/modules` and `/sys/module/*/sections/.text` (a five-line shell
snippet); the host rebases module addresses to each `.ko`'s link addresses
using the runtime→link translation already designed in DYNAMIC-OBJECTS.md §
(the r_debug machinery generalizes; here the map source is procfs instead of
the dynamic linker).

Acceptance: coverage attributed to a `.ko`'s sources from a boot that loads
it.

**Verified 2026-08-14** — see `examples/linux-module/`: `CONFIG_DUMMY=m`, a
sidecar init script printing `/proc/modules` + `/sys/module/*/sections/.text`
between console markers, and two new host-side pieces this tier produced:
`tcgcov rebase` (runtime→link windowing with printed drop counts) and
`--section` on symbolize (ET_REL objects need `addr2line -j`). 13/13
module-window addrs resolved to 18 lines of `dummy.c` and its inlined
headers, `dummy_xmit` carrying the real transmit count.

### Tier 2 — one user binary, statically linked, ASLR off

The bare-metal discipline transplanted: boot with `norandmaps`, run **one**
static test binary (as init or from init). Its ET_EXEC VAs are link-time
constant, so symbolize-against-that-ELF works exactly like bare metal. The
ambiguity of L2 is avoided by test discipline rather than solved — same VA
range executed by *other* processes (shell, busybox) must be excluded, which
falls out of symbolize's ELF-range matching from Tier 0 step 3 **only if**
no other process's text overlaps the test binary's ranges; document that
busybox-based rootfs images place init at the same default base, so the
test binary should be linked at a distinctive base address.

Acceptance: line+branch coverage for a userspace test binary running under a
stock Buildroot rootfs.

**Verified 2026-08-14** — see `examples/linux-userspace/`: a static `-O0 -g`
binary at `-Wl,-Ttext-segment=0x30000000` (busybox owns the 0x10000000
default; the DSO mmap region is ~0x48000000), auto-run from an init script.
The match-rate line fenced 53,079 foreign addresses out of 53,923; the
result: LF:21 LH:11, BRF:6 BRH:4, with the designed taken/untaken branch
pair and a loop line carrying its true count of 8.

### Tier 3 — process-aware coverage (format v2 + QEMU changes)

The real feature. Requirements:

* **Context identity per record.** `TCGCOV2` adds an address-space/context
  field to address and edge records, plus a metadata table mapping context
  IDs to whatever the guest side can name them with.
* **QEMU: expose the MMU context to plugins.** Nothing in the plugin API
  reports the current address-space (MicroBlaze: the PID in `RPID`; ARM:
  TTBR/ASID; RISC-V: `satp.ASID`). Two candidate shapes, both upstreamable:
  1. extend `qemu_plugin_read_register()` coverage to the relevant system
     registers per target, and poll per-TB (works, costs a callback read per
     TB exec);
  2. a context-change callback (`qemu_plugin_register_vcpu_ctx_switch_cb`)
     so the plugin only records transitions — cheaper and more honest about
     what coverage needs.
* **Guest-side map export.** Context IDs alone don't name binaries. A tiny
  guest agent (or an init-script `cat /proc/*/maps` at end of test) gives
  the host the pid→file→VA-range table to join against.

Acceptance: two concurrently running copies of different binaries at the
same VA base produce separately attributed coverage.

### Tier 4 — dynamic linking and ASLR

The DYNAMIC-OBJECTS.md `r_debug`/`link_map` design applies to glibc/musl
ld.so unchanged in concept: the rendezvous structure is standard ELF, and the
gdbstub-breakpoint prototype in that document ports to a Linux guest
directly. Combining Tier 3 context identity with per-context link maps gives
full attribution. This tier should not start until Tier 3's format exists.

## 4. QEMU modifications, summarized

| mod | needed by | upstream posture |
|---|---|---|
| context/ASID visibility for plugins (register coverage or new callback) | Tier 3 | RFC to qemu-devel; generic API, per-target enablement |
| guest-physical address for *instructions* (`qemu_plugin_insn_phys()` — mem ops have `qemu_plugin_hwaddr`, insns do not) | optional; dedups same-code-different-VA and helps L1 | small, self-contained |
| none | Tiers 0–2 | — |

## 5. Non-goals

* SMP context juggling beyond per-vcpu bookkeeping (the plugin is already
  per-vcpu; Tier 3's format carries vcpu index implicitly today).
* KVM guests — TCG plugins are TCG-only by definition.
* Guest agents with kernel modules; procfs text dumps are enough.
