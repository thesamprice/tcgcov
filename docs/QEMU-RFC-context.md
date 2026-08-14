# DRAFT — NOT SENT

> RFC draft for tcgcov issue #6. **This has not been posted to qemu-devel.**
> Before sending: run `scripts/get_maintainer.pl -f plugins/` in a QEMU
> checkout for the real To/Cc list (do not guess names), re-verify the API
> claims against the QEMU version being targeted, and decide whether to
> attach the MicroBlaze proof-of-concept patch — proposals with working code
> travel better.

---

```
Subject: [RFC] plugins: expose the guest address-space context to TCG plugins
To: qemu-devel@nongnu.org
Cc: <plugins maintainers per scripts/get_maintainer.pl -f plugins/>
```

## Summary

TCG plugins observe virtual addresses with no way to learn which guest
address space produced them. For a full-system guest with an MMU this makes
per-process attribution impossible: the same VA range is every process, and
a plugin cannot tell them apart. I propose a small, target-enabled API that
reports an opaque address-space context ID — a change callback plus a pull
accessor — with MicroBlaze as the first enabled target.

## The problem, concretely

I maintain tcgcov, a coverage tool built on the plugin API: a plugin records
executed TB addresses; host-side tooling symbolizes them against DWARF. On
bare metal this works end to end. On a Linux guest, a measured boot artifact
(QEMU 11.0.2, MicroBlaze `petalogix-s3adsp1800`, Buildroot guest) contained
52,940 distinct TB addresses of which 14,282 were user-space — and those
14,282 are unattributable in principle: nothing in the artifact, and nothing
available to the plugin at record time, says which process (hence which
binary, hence which DWARF) each belongs to.

Workarounds exist and are unsatisfying: we currently link the one binary
under test at a distinctive base address and fence everything else out by
ELF-range matching. That measures exactly one process per boot and collapses
the moment two binaries share a VA range.

What is missing is not the mapping (a guest-side `/proc/PID/maps` dump joins
context→binary after the fact) but the **context identity per recorded
address**, which only the emulator knows at execution time.

## Existing API, and why it does not cover this

* `qemu_plugin_read_register()` reads registers by GDB feature name. The
  registers that carry address-space identity (MicroBlaze `RPID`, Arm
  `TTBRn`/`CONTEXTIDR`, RISC-V `satp`) are system registers that are not
  reliably present in the default gdbstub feature sets across targets, and
  polling a register on every TB execution is the wrong cost model for an
  event that changes on the order of context switches. *(Per-target gdbstub
  coverage should be re-verified against current master before sending.)*
* `qemu_plugin_get_hwaddr()` exists for memory operands only; instructions
  expose a vaddr and a host pointer. Physical keying would deduplicate
  same-code-different-VA but does not name the address space either, and is
  a separate (smaller) proposal.

## Proposed API

Two entry points, independently useful, both returning an **opaque,
target-defined** 64-bit context ID whose only guaranteed property is:
*two simultaneously-live address spaces with different code mappings have
different IDs on the same vcpu*.

```c
/* Pull: the current context of a vcpu. Targets without enablement return
 * QEMU_PLUGIN_CTX_UNAVAILABLE (all-ones). In user-mode emulation the
 * context is constant for the process's lifetime. */
uint64_t qemu_plugin_vcpu_ctx_id(unsigned int vcpu_index);

/* Push: called after the vcpu's context changes and before the first TB
 * executes in the new context on that vcpu. */
typedef void (*qemu_plugin_vcpu_ctx_changed_cb_t)(qemu_plugin_id_t id,
                                                  unsigned int vcpu_index,
                                                  uint64_t ctx_id);
void qemu_plugin_register_vcpu_ctx_changed_cb(
    qemu_plugin_id_t id, qemu_plugin_vcpu_ctx_changed_cb_t cb);
```

The callback form is the one coverage actually wants: a plugin records
`(ctx_id, tb_addr)` transitions instead of paying a query per TB. The pull
form exists for plugins with coarser needs and as the building block the
callback is implemented on.

### Target enablement

A target opts in by implementing one hook and calling one notifier:

```c
/* target/<arch>/: current address-space identity, e.g. the PID/ASID. */
uint64_t cpu_get_ctx_id(CPUState *cs);

/* called from the existing context-switch choke points -- the same places
 * that already invalidate TLBs / jump caches on context change. */
void qemu_plugin_vcpu_ctx_changed(CPUState *cs);
```

MicroBlaze first: the context is the 8-bit PID in the MMU's RPID register,
and the write path (`mmu_write` for RPID, which already flushes) is a single
call site. Arm and RISC-V sketches belong in the series but raise questions
I would rather have reviewers answer (below).

## Questions for reviewers

1. **ID semantics.** Raw register value vs target-cooked? An Arm context
   could be TTBR0 ASID, CONTEXTIDR, or a combination under VHE; RISC-V has
   `satp.ASID` optionally width-zero. "Opaque, target-defined, documented
   per target" is my proposal; is that acceptable, or should the API commit
   to "hardware ASID as written"?
2. **Ordering guarantee.** "Delivered before the first tb_exec in the new
   context on that vcpu" — is that implementable uniformly, including under
   icount and record/replay, or should the guarantee be weakened to
   per-vcpu ordering only?
3. **Kernel/user distinction.** This proposal deliberately reports address
   *space*, not privilege. A guest kernel mapped in every context reports
   the process's ID while executing kernel code. Is a separate
   privilege-level accessor wanted, or is VA-range filtering (which works
   today) the accepted answer there?
4. **Scope.** Is there appetite for this in plugins at all, or is the
   preferred answer "extend gdbstub register coverage per target and let
   plugins poll"? I believe the cost model argues for the event, but the
   register route touches less new API.

## Prototype status

Not yet implemented; a MicroBlaze proof of concept (target hook + notifier
call + the two API functions + a `contrib/plugins` demo recording
per-context TB counts) will accompany the PATCH version if the shape is
agreeable. The consumer is real and measurable today: with this API,
tcgcov's format gains a context field and a Linux guest's user-space
coverage becomes attributable per process by joining a guest-side maps dump
— the design is written up in
https://github.com/thesamprice/tcgcov/blob/main/docs/LINUX-VM.md (§3 Tier 3).
```

---

## Notes kept out of the mail

* The measured numbers (52,940 / 14,282) come from the Tier-0 experiment
  logged in issue #1; re-run against the QEMU version current at send time
  if it has moved.
* If review prefers the register-polling route, tcgcov can live with it:
  a per-TB-exec `qemu_plugin_read_register` of one 8-bit register is
  measurable overhead but not disqualifying — worth saying in-thread rather
  than conceding pre-emptively in the RFC.
* Issue #7 (instruction physical address) is intentionally not in this RFC.
  One proposal per thread.
