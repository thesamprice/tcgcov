# Verifying the MicroBlaze entry.S ABI fix with coverage

The "GCC 15 regression" kernel fix (PR 121432 / the v5 entry.S patch)
reserves a MicroBlaze argument save area at **15 call sites** in
`arch/microblaze/kernel/entry.S`, one before each C call (or the syscall
dispatch) on a kernel-entry path. "Does the patch have a test?" — the
honest answer is a workload that drives every one of those sites plus a
coverage run proving it did.

## What drives what

`mb-abi-stress.c` is a single static userspace binary; each stanza targets
the entry.S callee named beside it (design borrowed from RTEMS
`spcontext01`'s register-integrity idea and the x86/arm64 selftests for
signals and syscalls):

| stanza | entry.S callee(s) | sites |
|---|---|---|
| every syscall | `bra r12` dispatch | 1 |
| fork + demand-fault pages | `schedule_tail`, `do_page_fault` (data) | 3 |
| jump through a null-ish pointer | `do_page_fault` (instruction) | — |
| privileged `mts rmsr` from user | `full_exception` | 1 |
| ptrace `PTRACE_SYSCALL` a child | `do_syscall_trace_enter/leave` | 2 |
| `brki r16, 0x18` software breakpoint | `sw_exception` (dbtrap) | 1 |
| `setitimer` storm + busy loop | `do_IRQ`, `do_notify_resume` | 4 |

The one site not driven is `microblaze_kgdb_break` — it is inside
`#ifdef CONFIG_KGDB`, off in this config, so it is **absent from the
build**, not merely uncovered. That is a legitimate "N/A", and the
verifier reports it as such.

## Running it

Build the binary into a Buildroot rootfs (`S95mbstress` runs it at boot),
rebuild the kernel image, and boot under tcgcov with the kernel windows
filtered — **both** the virtual base (`0xc0000000`) and its physical alias
(`0x90000000` on petalogix), because the exception and interrupt entry
paths execute in **real mode at physical addresses** while the syscall
path runs virtual:

    qemu-system-microblazeel -M petalogix-s3adsp1800 -kernel linux.bin \
      -plugin libtcgcov.so,out=mbstress.cov,mode=tb-insn,edges=off,\
        filter=0x90000000-0x9000c000,filter=0xc0000000-0xc000c000

`mode=tb-insn` is required: the reserve `addik r1,r1,-32` sits mid-block,
so TB-entry-only coverage (`mode=tb`) never records it.

## Verifying

`verify-sites.py` decodes the disassembly directly (no DWARF — the reserve
instruction's address is what matters, not its source line): for every
`addik r1,r1,-32`, it resolves the following branch's target and matches
it to the entry.S callee at that address, then checks coverage at either
the virtual or physical alias.

    python3 verify-sites.py <build-out-dir> mbstress.cov

## Result (2026-08-15)

**14/14 reserve sites executed** — every argument-save-area site the v5
patch touches, from a single userspace binary in one boot:

```
  COVERED  0xc0004dc4  do_syscall_trace_enter
  COVERED  0xc0004e1c  bra_r12_dispatch
  COVERED  0xc0004e60  do_syscall_trace_leave
  COVERED  0xc0004ea0  do_notify_resume
  COVERED  0xc0005030  schedule_tail
  COVERED  0xc0005050  schedule_tail
  COVERED  0xc0005218  full_exception        (real-mode/phys)
  COVERED  0xc0005560  do_page_fault         (real-mode/phys)
  COVERED  0xc0005700  do_page_fault         (real-mode/phys)
  COVERED  0xc0005754  do_notify_resume
  COVERED  0xc0005aac  do_notify_resume
  COVERED  0xc0005a5c  do_IRQ                (real-mode/phys)
  COVERED  0xc0005de0  sw_exception          (real-mode/phys)
  COVERED  0xc0005e2c  do_notify_resume
  14/14 reserve sites executed
  (microblaze_kgdb_break site absent: CONFIG_KGDB not set -- expected)
```

The five `(real-mode/phys)` sites are the exception/interrupt entry paths,
confirmed executed at the `0x90000000` physical alias — a detail the
coverage run surfaced that source review would miss.

## Regression canary (fails on an unpatched kernel)

Beyond coverage, `mb-abi-stress` asserts the bug is *absent*.
`sp_checked_syscall()` issues a raw MicroBlaze syscall (`brki r14, 8`) and
reads the stack pointer `r1` immediately before and after the trap in one
asm block. The bug spills a kernel-entry callee's first argument to
`caller_sp+4`, which on an unpatched kernel **is** `PT_R1` (the saved user
SP) -- so a syscall silently rewrites the user SP to a syscall-argument
value (init originally died getting `AT_FDCWD` as its SP). A mismatch is
the bug, caught deterministically. The binary prints `CANARY PASS` + exits
0 only if every checked syscall preserved SP; a harness keys on that.

### A/B, measured 2026-08-15

Same workload, same GCC 15, same Buildroot rootfs; only `entry.S` differs.

| kernel | entry.S | result |
|---|---|---|
| **patched (v5)** | 38 `C_ARG_SIZE` reserves | boots, 60,000 SP-checked syscalls clean, **`CANARY PASS`**, exit 0 |
| **pristine 6.12.81** | 0 reserves (stock) | **hangs at `Run /init as init process`** -- init's SP corrupted on its first syscalls, the exact PR 121432 symptom; the test binary is never reached |

On the unpatched kernel the failure is so early that the system never
reaches userspace -- which is itself the clearest possible red. The
per-syscall SP check exists for the subtler case where a future
regression lets init survive but still corrupts SP on some path.

## Why this matters for the patch

Coverage turns "the tests pass" into "the tests pass *and executed every
site the patch changed*". Notably the QEMU boots during the original
debugging never exercised the unaligned path — a coverage run would have
said so in one line. The same artifact is upstreamable evidence for the
LKML thread: a reviewer can see each reserved site was exercised, not just
asserted.


## The kselftest form, and what "fails on unpatched" really means

`entry_abi.c` is the mergeable kselftest (TAP harness, arch-gated) that
ships as [PATCH v6 2/2]; it asserts just the SP-preservation property.
Its before/after behaviour was verified directly:

* **fixed kernel:** `ok 1 user stack pointer preserved across ... syscalls`,
  pass:1 (booted with `init=/usr/bin/entry_abi` so the test runs first).
* **reverted kernel (stock entry.S, same GCC 15):** the test's own
  `faccessat(AT_FDCWD, ...)` syscall corrupts the saved SP -- the fault
  dump reports `r1=0xFFFFFF9C`, which is AT_FDCWD (-100), the syscall's
  first argument written over the stack pointer -- and the process dies on
  it (`Attempted to kill init`).

So the test's syscall provably triggers the bug (no false pass -- the
corrupted value is unmistakably the test's own argument). But note the
honest limitation: this bug corrupts the SP of *any* process that makes a
spilling syscall, so a reverted kernel cannot reach a working userspace at
all -- init panics before, or as, the test runs. There is no graceful
"not ok" to be had; the failure signal is "the system does not boot / the
test never emits ok", which every CI records as failure. That is as strong
as a total-boot-failure bug allows.
