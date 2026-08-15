# Coverage of RTEMS dynamically loaded objects — execution plan

> **STATUS: PLAN.** Design basis: [DYNAMIC-OBJECTS.md](DYNAMIC-OBJECTS.md)
> (the RTL analysis there is verified against RTEMS source and is not
> repeated here). This document updates its staging for what has landed in
> tcgcov since it was written — the Linux Tier-1 module machinery and the
> TCGCOV2 context records — both of which shorten the path considerably.

## 0. What an RTEMS ".so" actually is

RTEMS libdl **refuses ET_DYN**: `rtems_rtl_elf_file_check()` errors with
"unsupported ELF file type" on `e_type == ET_DYN` and also rejects any file
with program headers (`cpukit/libdl/rtl-elf.c:1597,1603`). Whatever the file
is named, a loadable RTEMS object is **ET_REL** (a `.o`, an archive member,
or a RAP container of the same). Three consequences drive the whole design:

1. **There is no load base.** Each section is allocated independently
   (`obj->text_base`, `const_base`, `data_base`, `bss_base`, and per-section
   bases in `obj->sections`). Translation is per-section, not per-object.
2. **DWARF is 0-based per section**, so symbolization is `addr2line -j
   SECTION` against the original `.o` — byte-identical to the Linux `.ko`
   case that `examples/linux-module/` already solved and verified (13/13
   addresses of `dummy.ko` → `dummy.c` lines, via `tcgcov rebase` +
   `symbolize --section`).
3. **No MMU, one address space** — no ASID/context to disambiguate, but
   also no page protection: the only ambiguity is *temporal* (unload A,
   load B into the reused allocation), and RTL's allocator makes reuse
   likely, not just possible.

## 1. What exists today

| side | fact | status |
|---|---|---|
| RTEMS | `obj->sections` holds every section's base/size; `_rtld_linkmap_add()` copies the four aggregate bases into a GDB-shaped `link_map` with `sec_detail[]` (name/offset/size — file offsets, not runtime addrs) | verified in source |
| RTEMS | `_rtld_debug`/`_rtld_debug_state()` exist and are called around `dlopen`/`dlclose`, but the SVR4 handshake is inert (no `r_brk`, wrong layout, wrong symbol name) — DYNAMIC-OBJECTS §3.2 | verified |
| tcgcov | out-of-ELF reporting (match-rate line), `rebase` (single window), `symbolize --section` for ET_REL | **landed** (Linux Tier 1) |
| tcgcov | TCGCOV2: per-record 64-bit tag + metadata table, plugin plumbing for a per-vCPU "current tag" updated by rare events, `contexts` list/extract tooling | **landed** (Linux Tier 3) |
| tcgcov | plugin patterns for insn-exec callbacks on chosen addresses and guest-memory reads (`qemu_plugin_read_memory_vaddr`, register reads) | verified against QEMU 10.2 headers; exercised in the PoC work |
| tcgcov | a pure-Python DWARF reader (`dwarfline.py`) | landed — this answers DYNAMIC-OBJECTS' open question #1 (struct offsets for guest walks) offline, from the base image's own DWARF |

## 2. The key design update: generations, not a new format

DYNAMIC-OBJECTS §7 assumed the temporal ambiguity would need a "format v3
module table". TCGCOV2 already provides the mechanism: the per-record
context field is an **opaque 64-bit tag whose only promise is that two
different things get different values**. On Linux it carries the MMU ASID.
On RTEMS — which has no ASID — it carries a **loader generation**: a
counter the plugin bumps every time it observes a load or unload event.

* An address executed while module A occupied a range is recorded under
  generation N; after unload/reload, the same address under generation
  N+2. The artifact keeps them apart — the exact mechanism that separated
  two same-base Linux processes in `examples/linux-ctx/`.
* The host joins generation → module map snapshot (one snapshot per
  generation, captured at the event).
* Metadata gains `"ctx_kind": "loader-generation"` (vs `"asid"`) so
  consumers know what the tag means. Reader/extract tooling is unchanged.

Nothing about TCGCOV2 changes; RTEMS is just its second producer semantics.

## 3. Stages

### Stage R0 — sidecar map, load-once workloads *(no RTEMS or QEMU changes)*

**Verified 2026-08-15** — see `examples/rtems-dl/`: `tcgcov modmap` landed
(per-(object,section) slicing, loud overlap refusal), and the `dl01` test
on the riscv/mbv BSP produced line coverage of its loaded object matching
ground truth exactly (entry count 2 = the two calls, loop count 5 = argc
2+3 iterations, corroborated by the serial log). The map was captured with
zero RTEMS changes via a GDB batch script at the existing
`_rtld_debug_state()` RT_CONSISTENT notification — which also means the R2
no-modification variant is no longer a hypothesis.

The `--module-map FILE` cut of DYNAMIC-OBJECTS §7.2(a), sized honestly:

* JSON map: `[{object, file, sections: [{name, addr, size}]}, ...]`,
  captured by the test harness (from `rtl` shell output plus a small
  target-side dumper — see R1 — or hand-written for a fixture).
* Host: generalize `rebase` from one window to N (object, section) windows
  → per-object TCGCOV1 slices rebased to section offsets → the existing
  `symbolize --section` pipeline per object. New subcommand or
  `rebase --module-map`; **fails loudly** if map windows overlap.
* Fixture: an RTEMS QEMU BSP running a `dl01`-style test (testsuites'
  `dl*` tests are ready-made: they load a `.o`, call into it, unload).
* Acceptance: line+branch coverage attributed to the loaded object's
  sources from one boot, with the base image's coverage unaffected.
* Explicit limitation, documented in output: valid only when no window was
  ever reused — one map, no time axis (this is what R3 removes).

### Stage R1 — target-side section dumper *(small RTEMS addition, fork-first)*

`rtl list -m`-style output does not print per-section runtime bases; the
data is in `obj->sections`. A ~30-line routine (shell command or callable
helper) walks the object list and prints `OBJ <name> SECTION <name> <addr>
<size>` between console markers — the `S98covmod` sidecar pattern
transplanted. Lands on the GitLab fork first; upstreamable independently
of everything else as a debugging aid.

### Stage R2 — the two hooks *(the only RTEMS modification in the plan —
optional, prepared on the fork; NOT sent anywhere without explicit approval)*

**A no-modification variant exists and should be tried first.** Unlike the
`r_brk` machinery, `_rtld_debug_state()` is *real*: `dlfcn.c` calls it with
`r_state = RT_ADD` before a load, `RT_CONSISTENT` after, `RT_DELETE` before
an unload (`dlfcn.c:69-106`), and `_rtld_linkmap_add()` maintains the
`r_map` chain. A plugin (or GDB) can watch `_rtld_debug_state`'s address —
resolved from the base ELF — read `r_state`, and diff the `r_map` chain in
guest memory. That yields load/unload events and per-object aggregate
section bases **with zero RTEMS changes**. Its real gaps, from
DYNAMIC-OBJECTS §5.2/§5.4:

* per-`dlopen`, not per-object — the consumer diffs the chain itself;
* constructors run *before* the `RT_CONSISTENT` notification, so ctor
  coverage lands one generation early — it shows up as *unattributed*
  (loud, not silently wrong), and is small;
* the shell `rtl obj load` path bypasses `dlfcn.c` and is invisible.

`rtems_rtl_debugger_load(obj)` / `rtems_rtl_debugger_unload(obj)` exactly
as specified in DYNAMIC-OBJECTS §5 — empty, noinline, per-object, placed
after cache-sync/before ctors and before teardown — close those three gaps,
and the GDB Python script from §6.1 is the second consumer that validates
the design. But they are an upgrade, not a prerequisite: the plan works
end-to-end without touching RTEMS.

### Stage R3 — plugin observes the loader; generations go live

* At install: resolve the watch address from the base ELF symbol table —
  `_rtld_debug_state` for the no-modification variant, or the R2 hooks
  when present (no guest cooperation needed either way).
* `vcpu_tb_trans`: when a TB contains a hook address, register an
  insn-exec callback on it (pattern proven; conditional-callback
  scoreboard if arm/disarm is ever needed).
* In the callback: read the argument register (MicroBlaze: `r5`) for the
  `rtems_rtl_obj*`, walk `obj->sections` via `qemu_plugin_read_memory_vaddr`
  using struct offsets extracted offline by `dwarfline.py` from the base
  image's DWARF and passed as plugin arguments; append a load/unload event
  (object name, section bases, generation) to the artifact metadata; bump
  the generation tag (per-vCPU current-tag plumbing already exists).
* Ordering guarantee for free: the load hook runs before the object's
  ctors, on the loading CPU, so the generation is current before the first
  instruction of the new object executes there. SMP: other CPUs cannot be
  executing the object before `dlopen` returns on the loader — record the
  caveat, assert single-core for the PoC.

### Stage R4 — acceptance: the reuse case

Load A, exercise, `dlclose`, load B (forcing allocator reuse — the `dl`
tests can be arranged to do this), exercise, stop. One artifact. The
acceptance mirrors Linux Tier 3's: **two objects that occupied the same
addresses at different times produce separately attributed, correct
reports** — A's lines from generation N, B's from N+2, with the collision
demonstrated by showing the shared address range carrying different counts
per generation.

## 4. Non-goals and open questions

* **RAP containers**: RAP repackages sections; DWARF stays with the
  original `.o`. R0's map schema carries `file` per object so the host
  symbolizes against the right file; compressed-RAP specifics are out of
  scope until someone needs them.
* **True `.so` support** would require RTEMS to grow an ET_DYN loader —
  not a coverage problem.
* **Upstream appetite** for the R2 hooks (vs fixing `r_debug` properly) is
  DYNAMIC-OBJECTS §8's question and stands; the plan only requires the
  hooks to exist on the fork.
* **Unload-while-executing** (another task inside a module during
  `dlclose`) is an application bug in RTEMS; the plan does not try to
  attribute it sanely, only to not crash.

## 5. Effort shape

R0 is host-side Python against fixtures we can build today, and it carries
almost all of the reusable value (the map model and multi-window
translation are what R3 consumes). R1 is trivial. R2 is small but needs
review care since it touches libdl. R3 is the substantial piece — mostly
plugin C — but every individual mechanism in it has already been exercised
somewhere in this repository. R4 is a test, not new machinery.
