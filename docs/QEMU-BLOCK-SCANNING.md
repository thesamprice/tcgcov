# Getting the denominator from QEMU's own decoders

> **STATUS: DESIGN PROPOSAL. Nothing described here is implemented.**
>
> No code in this repository, and no code in QEMU, does what this document
> proposes. It describes a change to **QEMU** — a new way to decode guest code
> without executing it — and what tcgcov would do with it. The QEMU API
> sketched in §4 is a proposal; it does not exist and has not been posted
> anywhere.
>
> Claims marked **verified** were checked against real source at the version
> cited. Claims marked **unverified** are reasoning that has not been
> confirmed, and §10 lists everything the author could not check. Treat the
> line numbers in `tcgcov/` as approximate: that file is under concurrent edit,
> so symbol names are given alongside and the symbol name is authoritative.

**Source versions used throughout.** QEMU is `/Users/sprice5/src/qemu-upstream`,
whose `VERSION` file reads **10.2.4** (`build/config-host.h:494`). That
checkout has no `.git`, so no commit hash, tag or `git log` evidence is
available anywhere in this document — see §10. tcgcov is this repository at the
current working tree.

---

## 1. Why the denominator cannot come from execution

Coverage is a fraction. It needs a **numerator** — what executed — and a
**denominator** — what could have executed. tcgcov gets these from two
completely different places, and the asymmetry is the whole subject of this
document.

The numerator is nearly free. QEMU translates guest code before running it, and
a TCG plugin gets a callback for every translated block
(`qemu_plugin_register_vcpu_tb_trans_cb`, `include/qemu/qemu-plugin.h:391-405`).
tcgcov registers one (`plugin/tcgcov.c:1491`), walks the block's instructions
(`qemu_plugin_tb_n_insns`, `plugin/tcgcov.c:683`; `qemu_plugin_tb_get_insn`,
`:686`, `:717`, `:737`; `qemu_plugin_insn_vaddr`, `:705`, `:718`, `:738`) and
records addresses. Nothing is rebuilt, nothing is instrumented, the guest never
knows.

The denominator is where all the work is. QEMU **translates lazily, driven by
execution**. The only two calls to `tb_gen_code()` in the entire tree are on
the TB-cache-miss path of the execution loop — `accel/tcg/cpu-exec.c:577`
(inside `cpu_exec_step_atomic`, after `tb_lookup()` missed at `:574`) and
`accel/tcg/cpu-exec.c:970` (inside `cpu_exec_loop`, after `tb_lookup()` missed
at `:964`). **Verified** by a tree-wide grep: every other match is the
definition (`accel/tcg/translate-all.c:261`), the prototype
(`accel/tcg/internal-common.h:50`), or a trace string.

The consequence is exact and unavoidable:

> **A function that never runs is never translated. It has no `TranslationBlock`,
> no `qemu_plugin_tb`, no plugin callback, and no representation of any kind
> inside QEMU. It is not "translated and unexecuted"; it does not exist.**

So a plugin cannot see the denominator, no matter how clever the plugin is.
Nothing observed at run time can enumerate the code that did *not* run. The
denominator must come from **static analysis of the binary**, and today tcgcov
does that with the target toolchain:

* `objdump -d` enumerates every instruction address in the executable sections
  (`tcgcov/coverable.py`, `disassemble_addresses`/`objdump_addresses`), parsed
  by the shared line matcher `cfg.match_insn_line`;
* for branch coverage, `tcgcov/cfg.py` reconstructs a control-flow graph from
  the **disassembly text**, using one `ArchProfile` per ISA
  (`tcgcov/cfg.py:119`, `class ArchProfile`) — a set of case-insensitive
  `re.match` regexes applied to `"<mnemonic> <operands>"`.

Nine profile objects are registered for eight ISA families, spanning roughly
`tcgcov/cfg.py:239-548`; with the classification machinery, the target parser
and the disassembly-format handling around them, this is the largest and by a
wide margin the most fragile part of the tool. `docs/ARCHITECTURES.md` §4 and
§5 are a list of the ways it has broken, and every item in that list is a bug
this project shipped.

### 1.1 The failure mode that makes this urgent

A missing denominator does not produce an error. It produces **100%**.

`tcgcov/coverable.py`, in `objdump_addresses`, says so in its own docstring:

```
Raises RuntimeError when no address could be parsed. That is never a
benign result: an empty coverable inventory makes `lcov` use the covered
lines as their own denominator and report 100%.
```

That guard exists because the bug happened. The same class of failure hit
branch coverage independently: `cfg.py` required a **tab** after the address
colon, GNU objdump emits a tab and llvm-objdump emits a **space**, so against
llvm-objdump input the branch inventory parsed **zero** instructions, wrote a
0-byte file, and exited 0 — while line coverage, using a different and correct
regex, kept working perfectly (`docs/ARCHITECTURES.md` §5.1). Branch coverage
silently disappeared and nothing downstream could tell.

A coverage tool whose denominator can quietly become empty is a coverage tool
that can quietly report success. That is the worst failure mode the tool has,
it lives entirely in the static-analysis half, and it is the argument for
moving that half onto machinery that is maintained by someone else and
validated by an emulator that has to get it right or the guest crashes.

---

## 2. What the plugin API offers today, and why it is not enough

**All facts in this section are verified against QEMU 10.2.4.**

### 2.1 What a plugin can see, per instruction

Everything below requires a live `struct qemu_plugin_insn *` handle, which
exists **only** inside a translation callback:

| API | Header | Implementation | What it gives |
|---|---|---|---|
| `qemu_plugin_tb_n_insns` | `include/qemu/qemu-plugin.h:540-541` | `plugins/api.c:227-230` | instruction count in this TB |
| `qemu_plugin_tb_vaddr` | `:549-550` | `plugins/api.c:232-236` | TB start vaddr |
| `qemu_plugin_tb_get_insn` | `:563-565` | `plugins/api.c:238-245` | the *i*-th instruction handle |
| `qemu_plugin_insn_vaddr` | `:594-595` | `plugins/api.c:268-271` | guest vaddr |
| `qemu_plugin_insn_size` | `:585-586` | `plugins/api.c:263-266` | **length in bytes** |
| `qemu_plugin_insn_data` | `:575-577` | `plugins/api.c:254-261` | copies raw bytes into a caller buffer |
| `qemu_plugin_insn_disas` | `:822-823` | `plugins/api.c:301-305` | disassembly text |
| `qemu_plugin_insn_haddr` | `:603-604` | `plugins/api.c:273-299` | host address |
| `qemu_plugin_insn_symbol` | `:832-833` | `plugins/api.c:307-311` | `lookup_symbol(vaddr)`, single address |

This is genuinely good data. `qemu_plugin_insn_size()` is QEMU's *own*
authoritative instruction length — the value the translator computed while
decoding, not a guess from address deltas. §8 argues tcgcov should be using it
already.

But note the binding. `qemu_plugin_insn_data()` reads through
`tcg_ctx->plugin_db` (`plugins/api.c:257`), the **in-flight** `DisasContextBase`
of the translation happening right now, using the internal `translator_st()`
(`include/exec/translator.h:256`). `tcg_ctx->plugin_db` is set in
`plugin_gen_tb_start()` (`accel/tcg/plugin-gen.c:423`) and cleared to NULL in
`plugin_gen_tb_end()` (`:508`). `qemu_plugin_tb_vaddr` (`api.c:234`),
`qemu_plugin_insn_haddr` (`:275`) and `qemu_plugin_insn_disas` (`:303`) are
bound the same way.

**There is no way to point any of these at an arbitrary address.** They answer
questions about code QEMU is translating because the guest is about to run it.

### 2.2 `qemu_plugin_translate_vaddr()` is not what its name suggests

This is an easy and consequential misreading, so it is worth settling.

```c
/**
 * qemu_plugin_translate_vaddr() - translate virtual address for current vCPU
 * ...
 */
QEMU_PLUGIN_API
bool qemu_plugin_translate_vaddr(uint64_t vaddr, uint64_t *hwaddr);
```
— `include/qemu/qemu-plugin.h:1128-1140`

The implementation (`plugins/api.c:575-592`) is:

```c
uint64_t res = cpu_get_phys_page_debug(current_cpu, vaddr);
if (res == (uint64_t)-1) { return false; }
*hwaddr = res | (vaddr & ~TARGET_PAGE_MASK);
```

It is **virtual-to-physical address translation** — an MMU page-table query. It
emits no TCG, touches no `DisasContextBase`, and returns a single 64-bit
physical address. It is grouped in the header (lines 1006-1140) with
`qemu_plugin_read_memory_vaddr` / `write_memory_vaddr` /
`read_memory_hwaddr` / `write_memory_hwaddr`, which is the correct company for
it: they are all data-plane operations. "Translate" here means what it means in
"address translation", not what it means in "Tiny Code Generator".

### 2.3 There is no decode-without-execute API. At all.

**Verified, four independent ways:**

**(a) The exported symbol list is mechanically complete.**
`plugins/meson.build:5-9` generates `qemu-plugin.symbols` by running
`scripts/qemu-plugin-symbols.py` over `include/qemu/qemu-plugin.h`, and that
generated list is the linker export list (`plugins/meson.build:19`, `:24`).
`build/plugins/qemu-plugin.symbols` holds **63 symbols**, and that is
exhaustively everything a plugin may call. None of them scans, decodes, lifts,
or translates a range.

**(b) Keyword sweeps of the header** (all 1213 lines) for `scan`, `decode`,
`section`, `elf`, `region`, `enumerate`, `range`, `lift`, `analy`,
`disassemble_range`, `static_analysis`, `probe`, `force_translate`, `walk`,
`iterate_code`, `code_range`, `maps`, `symtab`, `objfile`, `dwarf` produced
**one** hit — the English word "static" in the `qemu_plugin_insn_symbol` doc
comment at `:829`. Zero API hits.

**(c) A sweep of the whole `plugins/` directory** for the same terms produced
three hits, all irrelevant: two `case MEMTX_DECODE_ERROR:` arms
(`plugins/api.c:526`, `:563`) and one comment (`plugins/core.c:269`).

**(d) The internal primitives are not exported.** `translator_st`
(`include/exec/translator.h:256`), `translator_st_len` (`:266`),
`plugin_disas` (`include/disas/disas.h:14`) and `translator_loop`
(`include/exec/translator.h:148`) all live in headers plugins do not include,
and none is in the export list.

The nearest neighbour is `qemu_plugin_write_memory_hwaddr`, and the header
frames it as code *patching*, explicitly warning against writing instruction
memory inside a translation callback (`include/qemu/qemu-plugin.h:1107-1117`).
Patching still requires subsequent **execution** to be observed.

### 2.4 There is also no module, section, or symbol-table API

For completeness, since a scanner needs to know *what range to scan*:

* `qemu_plugin_path_to_binary()` (`include/qemu/qemu-plugin.h:902-903`),
  `qemu_plugin_start_code()` (`:911-912`), `qemu_plugin_end_code()`
  (`:920-921`), `qemu_plugin_entry_code()` (`:929-930`) — three scalars and a
  path, **user-mode only**.
* The system-mode implementations are hard-coded stubs, with the comment at
  `plugins/api-system.c:21-24`: *"In system mode we cannot trace the binary
  being executed so the helpers all return NULL/0."*

There is no section table, no program-header list, no module list, no
`MemoryRegion` iteration, no symbol-table iteration. §6 and §9 return to this:
it means even a perfect scan API leaves the host holding the ELF.

### 2.5 Translation callbacks fire only as a side effect of execution

The full chain, **verified**, bottom-up:

| Step | Location |
|---|---|
| guest needs code, TB cache misses | `accel/tcg/cpu-exec.c:964` |
| `tb_gen_code(cpu, s)` | `accel/tcg/cpu-exec.c:970` (and `:577`) |
| `setjmp_gen_code()` → `tcg_ops->translate_code()` | `accel/tcg/translate-all.c:251` |
| per-target `<t>_translate_code()` → `translator_loop()` | e.g. `target/microblaze/translate.c:1787` |
| `plugin_gen_tb_start(cpu, db)` | `accel/tcg/translator.c:154` |
| `plugin_gen_insn_start` / `_end` per insn | `accel/tcg/translator.c:167`, `:188` |
| `plugin_gen_tb_end(cpu, db->num_insns)` | `accel/tcg/translator.c:228` |
| `qemu_plugin_tb_trans_cb(cpu, ptb)` | `accel/tcg/plugin-gen.c:502` |
| dispatch to registered plugin callbacks | `plugins/core.c:500-514`, call at `:511` |

`plugin_gen_tb_start()` returns false and the whole path is skipped unless
`QEMU_PLUGIN_EV_VCPU_TB_TRANS` is set in the vCPU's event mask
(`accel/tcg/plugin-gen.c:417-420`).

There is exactly one door into `translator_loop`, and the guest is the only one
holding a key.

---

## 3. The generic translator loop, and why a TB is not a basic block

Any decode-only path is going to reuse this machinery, so it has to be
described precisely — including the ways its block boundaries are *wrong* for a
CFG. **All verified against QEMU 10.2.4.**

### 3.1 `DisasContextBase`

`include/exec/translator.h:67-91` (doc `:51-66`):

```c
struct DisasContextBase {
    TranslationBlock *tb;
    vaddr pc_first;
    vaddr pc_next;
    DisasJumpType is_jmp;
    int num_insns;
    int max_insns;
    bool plugin_enabled;
    bool fake_insn;
    uint8_t code_mmuidx;
    struct TCGOp *insn_start;
    void *host_addr[2];
    int record_start;
    int record_len;
    uint8_t record[32];
};
```

The fields that matter here:

| Field | Role | Notes |
|---|---|---|
| `pc_first` | first insn vaddr; anchor for page checks and `translator_st` offsets | set `translator.c:133` |
| `pc_next` | vaddr of the *current* insn during `translate_insn`; the target hook **must advance it** to the next insn before returning | `translator.c:134`, consumed `:224` |
| `is_jmp` | why to stop | asserted `DISAS_NEXT` after `init_disas_context` (`:147`), `tb_start` (`:152`), `insn_start` (`:164`) |
| `num_insns` / `max_insns` | the budget | `max_insns` can be **lowered mid-translation** (`:311`) |
| `host_addr[2]` | cached host pointers to code page 0 and 1 | the fast path that bypasses softmmu entirely |
| `record[32]` | insn bytes not readable from host memory: executing from I/O, or a synthetic s390x `EX` insn | doc `translator.h:80-87` |

Note what is *absent*: there is no field describing what kind of instruction
was just decoded. §4.4 is about adding one.

### 3.2 `DisasJumpType`

`include/exec/translator.h:33-49`:

```c
typedef enum DisasJumpType {
    DISAS_NEXT,        /* Next instruction in program order. */
    DISAS_TOO_MANY,    /* Too many instructions translated. */
    DISAS_NORETURN,    /* Following code is dead. */
    DISAS_TARGET_0, ... DISAS_TARGET_11,
} DisasJumpType;
```

Twelve target-defined slots, not six. Targets `#define` their own names over
them — i386 at `target/i386/tcg/translate.c:150-174`
(`DISAS_EOB_NEXT`, `DISAS_EOB_INHIBIT_IRQ`, `DISAS_EOB_ONLY`, `DISAS_JUMP`,
`DISAS_EOB_RECHECK_TF`), ARM at `target/arm/tcg/translate.h:331-358`,
MicroBlaze at `target/microblaze/translate.c:41-48`.

**This is the first reason `is_jmp` is not a control-flow classification**: the
same numeric value means different things on different targets, and the
meanings that exist are about *how to leave the TB*, not about *what kind of
branch this was*.

### 3.3 `TranslatorOps`

`include/exec/translator.h:117-124`, contract at `:93-116`. Six callbacks and
no others:

```c
typedef struct TranslatorOps {
    void (*init_disas_context)(DisasContextBase *db, CPUState *cpu);
    void (*tb_start)(DisasContextBase *db, CPUState *cpu);
    void (*insn_start)(DisasContextBase *db, CPUState *cpu);
    void (*translate_insn)(DisasContextBase *db, CPUState *cpu);
    void (*tb_stop)(DisasContextBase *db, CPUState *cpu);
    bool (*disas_log)(const DisasContextBase *db, CPUState *cpu, FILE *f);
} TranslatorOps;
```

`translate_insn`'s documented contract (`:106-109`) is the one that matters:
*"Disassemble one instruction and set `db->pc_next` for the start of the
following instruction. Set `db->is_jmp` as necessary to terminate the main
loop."* Note that the hook is required to produce **length** and **stop/go**,
and nothing else. There is no obligation to say *why* it stopped.

`disas_log` is optional and overridden by only two targets
(`target/s390x/tcg/translate.c:6479`, `target/hppa/translate.c:4893`).

### 3.4 Every reason a TB ends

`translator_loop()` is `accel/tcg/translator.c:122-246`. The main loop is
`:157-202`. It terminates for these reasons, **and a coverage tool must not
treat any of them as a basic-block boundary**:

| # | Reason | Line | Is it a real CFG edge? |
|---|---|---|---|
| 1 | `db->is_jmp != DISAS_NEXT` — target decided to stop | `:192-194` | **usually yes**, but see §3.5 |
| 2 | `tcg_op_buf_full()` — TCG op buffer hit 4000 ops | `:198`; `include/tcg/tcg.h:634-644` | **no** — an artifact of host codegen |
| 3 | `db->num_insns >= db->max_insns` | `:198` | **no** |
| 4 | `max_insns` lowered because code page 2 is MMIO | `:307-313` (`db->max_insns = db->num_insns` at `:311`) | **no** |
| 5 | Page crossing | **not generic** — see below | **no** |
| 6 | `translator_io_start()` forces the I/O insn last in the TB | `:31-41` | **no** |
| 7 | Instruction-fetch fault (non-local exit) | `:301` → `cputlb.c:1536-1537` | **no** |

On (3), the budget originates at `accel/tcg/translate-all.c:281-284`, defaulting
to `TCG_MAX_INSNS` = 512 (`include/tcg/tcg.h:131`) but forced to **1** in a
long list of ordinary situations: single-step and `-one-insn-per-tb`
(`accel/tcg/cpu-exec-common.c:49-55`), a breakpoint on the same page
(`accel/tcg/cpu-exec.c:354`), MMIO on the first page
(`accel/tcg/translate-all.c:276-279`), watchpoints (`accel/tcg/watchpoint.c:104`,
`:134`), self-modifying code (`accel/tcg/tb-maint.c:1099`, `:1171`), and an
icount budget remainder (`accel/tcg/cpu-exec.c:922-925`). And on a "code too
large" retry it is simply **halved** (`accel/tcg/translate-all.c:356-357`).

On (5): the "only single-insn TBs may cross a page" rule is **not enforced by
`translator_loop`**. The generic helper `translator_is_same_page()` is
`accel/tcg/translator.c:106-109`, and each target's `translate_insn` applies it
itself — RISC-V at `target/riscv/translate.c:1386`, `:1396`; i386 at
`target/i386/tcg/translate.c:3875-3877`; s390x at
`target/s390x/tcg/translate.c:6424-6425`; ARM does its own arithmetic at
`target/arm/tcg/translate.c:6371`, `:6719-6720`; MicroBlaze caps `max_insns` up
front in `mb_tr_init_disas_context` (`target/microblaze/translate.c:1621-1622`).

> **Design consequence.** A TB is a *unit of translation*, sized by host
> codegen convenience, MMIO layout, page geometry and debugger state. A basic
> block is a *unit of control flow*. Any design that assumes "TB boundary =
> block boundary" is wrong, and tcgcov already knows this: its edge matcher
> deliberately accepts any source address at or after a branch inside its
> block, and its summary line counts *"edges: ignored (source block does not
> end in a conditional branch)"* as **expected and benign** precisely because a
> QEMU translation block can be shorter than a basic block
> (`docs/ARCHITECTURES.md` §8.1).

### 3.5 How instruction bytes get read — and why the fetch path is wrong for a scanner

`translator_ld()` (`accel/tcg/translator.c:248-368`) is the fast path: a direct
host-pointer read from `db->host_addr[0]`, seeded from
`get_page_addr_code_hostp()` in `tb_gen_code` (`accel/tcg/translate-all.c:274`),
with `host_addr[1]` resolved lazily at `:301`. That path cannot fault.

The other two paths can:

* the **slow path**, when `translator_ld` returns false —
  `translator_ldub`/`lduw`/`ldl`/`ldq` fall back to `cpu_ld*_code_mmu()`
  (`accel/tcg/translator.c:458-516` → `accel/tcg/cputlb.c:2900-2922`), full
  softmmu with TLB fill, which will raise a guest exception;
* the **page-1 resolution** at `accel/tcg/translator.c:301`, which calls
  `get_page_addr_code_hostp()`, whose own comment at
  `accel/tcg/cputlb.c:1534-1537` says: *"NOTE: This function will trigger an
  exception if the page is not executable."* That unwinds out of translation
  entirely via `cpu_loop_exit` and is **not** catchable by the target
  front-end.

A scanner that walks a `.text` range must never inject a guest exception
because it wandered into an unmapped or non-executable page. This is a hard
constraint on the design and §4.5 addresses it explicitly.

### 3.6 QEMU already carries two decoders per target

Worth stating because it changes the upstreaming argument (§9).

`-d in_asm` does **not** log the TCG front-end's view. At the end of
`translator_loop` (`accel/tcg/translator.c:231-245`) it calls the optional
`ops->disas_log` and otherwise falls back to `target_disas()`
(`disas/disas-target.c:20-60`), which re-disassembles with an entirely separate
decoder — Capstone (`disas/capstone.c`, selected via `info->cap_arch`, used by
arm, i386, ppc, s390x), or a libopcodes-derived decoder under `disas/`
(`alpha.c`, `hexagon.c`, `hppa.c`, `m68k.c`, `microblaze.c`, `mips.c`,
`nanomips.c`, `riscv.c`, `sh4.c`, `sparc.c`, `xtensa.c`; wiring at
`disas/meson.build:1-14`), or a QEMU-native second decoder at
`target/<t>/disas.c` (avr, loongarch, openrisc, rx), or — for TriCore —
nothing at all, falling back to a raw hexdump (`disas/objdump.c:34`).

And QEMU knows the two can disagree. `disas/disas-target.c:52-58` prints:

```
Disassembler disagrees with translator over instruction decoding
Please report this to qemu-devel@nongnu.org
```

`qemu_plugin_insn_disas()` goes through this second decoder too
(`plugin_disas`, `disas/disas-target.c:73-98`). So the disassembly text a
plugin can already get is **not** the authoritative TCG-front-end view; it is
the same family of libopcodes code that GNU objdump uses. That matters for §8.

### 3.7 The existing precedent: decodetree reuse

There is one thing in-tree that already does "decode without emitting TCG", and
it is the strongest argument that the proposed change is idiomatic rather than
novel.

Three targets compile the **same generated decodetree decoder twice** — once
against TCG-emitting `trans_*` functions, once against printing `trans_*`
functions:

* LoongArch: `target/loongarch/disas.c:134` includes `decode-insns.c.inc`;
  `print_insn_loongarch` calls `decode(&ctx, insn)` at `:155`; generated from
  `insns.decode` at `target/loongarch/meson.build:1`, linked into `disas.c` at
  `:18`.
* OpenRISC: `target/openrisc/disas.c:27-28`, `print_insn_or1k` at `:34`;
  `target/openrisc/meson.build:1`, `:7`.
* RX: `target/rx/disas.c:1424`.

That is precisely the shape of what §4 proposes, generalised: run the decoder,
do something other than emit code. What those three do not have is a way to
drive it from a plugin, or a control-flow classification, or coverage of the
other sixteen targets.

---

## 4. The circularity problem

Before proposing an API, the hard part has to be stated honestly, because it is
the reason this is not simply "call the decoder in a loop".

> **QEMU's translator is control-flow driven. It decodes linearly from a known
> start address until a control transfer, then stops. To pre-translate "all
> code", you must already know where the blocks start — which is exactly the
> static analysis you were trying to avoid.**

`translator_loop` needs a `pc_first`. `tb_gen_code` gets one from the guest PC.
A scanner has to get one from somewhere else, and there are only four
somewheres.

### 4.1 Linear sweep of executable sections

Take `.text`, decode at `base`, `base + w`, `base + 2w`, …

**Works** on a fixed-width ISA. MicroBlaze is the clean case:
`mb_tr_translate_insn` advances `dc->base.pc_next += 4` unconditionally
(`target/microblaze/translate.c:1662`), full stop. No computation.

**Fails** on a variable-length ISA, for a reason that is not a limitation but a
theorem: you cannot find instruction boundaries without decoding, and you
cannot decode without a boundary. i386 has no length function at all — length
emerges from how many bytes `disas_insn` consumed
(`target/i386/tcg/decode-new.c.inc:2536`, prefix loop `:2559-2678`, lazy ModRM
fetch `get_modrm` `:282-289`), read back as
`dc->base.pc_next = dc->pc` (`target/i386/tcg/translate.c:3864`). The only
a-priori fact is an upper bound: `X86_MAX_INSN_LENGTH 15`
(`target/i386/tcg/translate.c:1661`), enforced by `advance_pc`
(`:1663-1688`).

**Fails also on data in `.text`**, on every ISA. Literal pools, jump tables,
ARM constant islands and alignment padding all decode as *something*. They will
produce plausible-looking instructions with plausible-looking branch targets,
and a fabricated target that happens to land on a real instruction address
becomes a basic-block leader — which is exactly the bug documented at
`docs/ARCHITECTURES.md` §4.1, *"a corrupt block map, reported with no error and
exit status 0"*.

**Cost**: trivial to implement, `O(size / w)`, no seeds needed. Correct only
for fixed-width ISAs with no data in `.text`.

### 4.2 Incremental walk using the decoder itself

Decode at `X`, take the size the decoder reports, continue at `X + size`.

This is **self-synchronising**, which is a real property: on x86 a misaligned
start typically resynchronises with the true instruction stream within a few
instructions. It is what every linear-sweep disassembler does, including
objdump.

RISC-V shows how cheap the length question *can* be:

```c
static inline int insn_len(uint16_t first_word)
{
    return (first_word & 3) == 3 ? 4 : 2;
}
```
— `target/riscv/internals.h:231-234`

with `MAX_INSN_LEN 4` (`target/riscv/translate.c:1225-1226`) and the decision
taken at `target/riscv/translate.c:1261`.

ARM shows how expensive it can be. `thumb_insn_is_16bit`
(`target/arm/tcg/translate.c:6121-6158`) depends on **CPU features** (`:6137`,
`ARM_FEATURE_THUMB2` / `ARM_FEATURE_M`) *and on position within the page*
(`:6145`: a BL/BLX prefix at the very end of a page is treated as a standalone
16-bit instruction on Thumb-1 cores). Instruction length is not a function of
the instruction bytes.

**Still defeated by data in `.text`.** Self-synchronisation gets you back onto
the instruction stream *after* the data; it does not tell you the data was
data, and it emits a run of garbage "instructions" first.

**Cost**: needs the decoder — which is the whole point of doing this inside
QEMU. Still needs a seed, still needs a code/data oracle.

### 4.3 Recursive-descent CFG discovery

Seed from the ELF entry point, the symbol table (`FUNC` symbols), and
relocations; decode forward; when a static branch target is found, queue it;
stop at returns and unconditional transfers with no static target.

**Most accurate.** It only ever decodes bytes it has a reason to believe are
code, so data in `.text` is largely avoided — the literal pool sitting after a
`bx lr` is never entered because nothing branches to it.

**Most work.** It needs an ELF reader (QEMU has no plugin-facing symbol or
section API — §2.4), a worklist, a visited set, and a decision about what to do
at indirect transfers.

**Still incomplete.** It misses everything reachable only through an indirect
transfer: jump tables, vtables, function pointers, interrupt vector tables
whose contents are computed, and any function whose address is only ever taken
into a register. On bare-metal firmware — tcgcov's primary target — the vector
table is often the *only* entry into large parts of the image.

**Cost**: the largest implementation effort, and it re-imports exactly the
static-analysis complexity this whole exercise is meant to delete — except now
it is ISA-independent complexity (a worklist over decoder output) rather than
per-ISA regex complexity, which is a real improvement even though it is not
zero.

### 4.4 Hybrid

Run recursive descent from all available seeds, then linear-sweep the *gaps*
between discovered code and mark those instructions with lower confidence. Or:
recursive descent, plus the addresses the plugin actually observed executing —
which are ground truth for "this is code" and are free.

The last variant is attractive for tcgcov specifically, because the numerator
is already a set of known-good code addresses, and every one of them is a valid
seed for a scan of the *unexecuted* code around it.

### 4.5 Summary of the ways out

| Approach | Needs seeds | Fixed-width | Variable-length | Data in `.text` | Indirect targets | Effort |
|---|---|---|---|---|---|---|
| Linear sweep | no | correct | broken | garbage instructions | n/a | trivial |
| Incremental decode walk | one | correct | self-syncing | garbage, then resync | n/a | small |
| Recursive descent | entry + symtab + relocs | correct | correct | avoided | **missed** | large |
| Hybrid (+ executed addrs) | as above | correct | correct | mostly avoided | partly recovered | large |

**None of these removes the need for a seed set, and none of them recovers
indirect targets.** That is a property of the problem, not of QEMU. What the
proposal in §5 changes is *who decodes* — moving that from tcgcov's regexes to
QEMU's front-ends — not *what is knowable*.

---

## 5. Proposed QEMU change

### 5.1 The three options are not at the same layer

The brief for this document weighed three options. Examining them, they are not
alternatives: two are mechanisms and one is a surface, and one of the
"mechanisms" is really both.

| Option | Layer | Verdict |
|---|---|---|
| (A) plugin API `qemu_plugin_scan_range()` | **surface** | the right surface for tcgcov |
| (B) decode-only mode of `translator_loop` | **mechanism** | required by (A) and (C) both |
| (C) QMP/HMP command dumping an inventory | **surface** | nearly free once (B) exists; the right *test* surface |

**Recommendation: implement (B) as the mechanism, expose it through (A) as the
primary surface, and add (C) as a thin second consumer.**

The reason to be explicit about the layering is that it determines the patch
order and therefore the upstreaming story (§9). (B) alone is unreviewable —
"here is a decode-only translator with no users". (A) alone is impossible.
(C) is what makes (B) testable from QEMU's own test suite without committing
the plugin ABI, and a maintainer will ask for that.

### 5.2 The mechanism: decode and discard, not decode without emitting

The obvious design is "run `translate_insn` with TCG generation suppressed".
**That design is wrong**, and the reason is worth spelling out because it is
the single biggest thing that makes this patch smaller than it looks.

Target front-ends do not merely *emit* TCG during decode; some of them
**depend on a live `tcg_ctx`** and manipulate the op list as part of decoding:

* **s390x emits a TCG store during decode.** `extract_insn`
  (`target/s390x/tcg/translate.c:6116-6156`) executes
  `tcg_gen_st_i64(tcg_constant_i64(0), tcg_env, offsetof(CPUS390XState, ex_value))`
  at `:6126-6127` — clearing the EXECUTE staging register. And at `:6136` it
  calls `translator_fake_ld()` because the instruction being decoded **is not
  in memory at all**; it was synthesised by a previous `EXECUTE`.
* **RISC-V rewinds the emit cursor mid-decode.**
  `tcg_ctx->emit_before_op = QTAILQ_NEXT(ctx->base.insn_start, link)` at
  `target/riscv/translate.c:1375`, to retroactively insert a CFI exception
  before already-emitted code.
* **i386 deletes already-emitted ops.** `tcg_remove_ops_after(dc->prev_insn_end)`
  at `target/i386/tcg/translate.c:3852`, on the page-crossing `siglongjmp` path.

Making emission optional across nineteen targets means auditing and patching
all of that. **Decoding into a scratch `tcg_ctx` and throwing the ops away
costs nothing** by comparison: the op buffer is bounded at 4000 ops
(`include/tcg/tcg.h:634-644`), the ops are never handed to `tcg_gen_code()`, no
host code is generated, no `TranslationBlock` is allocated and nothing is
linked into the TB cache. The proposal is therefore:

> **`translator_scan()` — a sibling of `translator_loop()` that runs the same
> `TranslatorOps` against a scratch TCG context, never calls `tcg_gen_code()`,
> never allocates or registers a `TranslationBlock`, and reports what it
> decoded instead of what it emitted.**

What it must do differently from `translator_loop()`:

1. **Non-faulting instruction fetch.** Replace the `get_page_addr_code_hostp`
   path (which raises on non-executable pages,
   `accel/tcg/cputlb.c:1534-1537`) and the `cpu_ld*_code_mmu` slow path
   (`accel/tcg/translator.c:458-516`) with a probing read in the style of
   `qemu_plugin_read_memory_vaddr` (`plugins/api.c:460-478`, via
   `cpu_memory_rw_debug`). An unreadable address ends the scan of that range
   and is reported, never injected into the guest.
2. **Do not stop for the wrong reasons.** Suppress terminations 2, 3, 4 and 6
   from the table in §3.4 — op-buffer pressure, instruction budget, MMIO on
   page 2, `translator_io_start` — because none of them is a control-flow fact.
   Page crossing (5) must be allowed to continue if the next page is readable,
   which means the `translator_is_same_page` checks inside targets need a way
   to be told "keep going". This is the ugliest part of the patch and §7.2
   revisits it.
3. **Surface the decoder's own failure signal.** decodetree's generated
   `decode()` returns `false` when no pattern matched
   (`scripts/decodetree.py:1641`) — that is the honest "this is not an
   instruction" answer, and every front-end currently **swallows** it and
   converts it into an emitted exception instead. See §7.5.
4. **Report per instruction**, not per block.

### 5.3 The surface: `qemu_plugin_scan_range()`

Proposed addition to `include/qemu/qemu-plugin.h`. **This does not exist.**

```c
/* What kind of control flow, if any, an instruction performs. */
enum qemu_plugin_cf_kind {
    QEMU_PLUGIN_CF_NONE = 0,      /* falls through to vaddr + size          */
    QEMU_PLUGIN_CF_COND_BRANCH,   /* two successors: target and fall-through*/
    QEMU_PLUGIN_CF_BRANCH,        /* unconditional, one successor           */
    QEMU_PLUGIN_CF_CALL,          /* transfers, expects to return           */
    QEMU_PLUGIN_CF_RETURN,        /* returns to a dynamic address           */
    QEMU_PLUGIN_CF_TRAP,          /* syscall/break/exception-raising        */
    QEMU_PLUGIN_CF_UNKNOWN,       /* transfers, kind not modelled by target */
};

enum {
    QEMU_PLUGIN_CF_F_INDIRECT   = 1 << 0, /* target computed at run time    */
    QEMU_PLUGIN_CF_F_HAS_TARGET = 1 << 1, /* .target is valid               */
    QEMU_PLUGIN_CF_F_DELAY_SLOT = 1 << 2, /* next insn runs before transfer */
    QEMU_PLUGIN_CF_F_UNDECODED  = 1 << 3, /* no pattern matched; see below  */
};

struct qemu_plugin_scan_insn {
    uint64_t vaddr;
    uint32_t size;
    uint16_t cf_kind;    /* enum qemu_plugin_cf_kind */
    uint16_t cf_flags;
    uint64_t target;     /* valid iff QEMU_PLUGIN_CF_F_HAS_TARGET */
};

enum qemu_plugin_scan_action {
    QEMU_PLUGIN_SCAN_CONTINUE,  /* decode at vaddr + size                  */
    QEMU_PLUGIN_SCAN_STOP,      /* end this scan                           */
    QEMU_PLUGIN_SCAN_SKIP,      /* stop this run; caller resumes elsewhere */
};

typedef enum qemu_plugin_scan_action
    (*qemu_plugin_scan_cb_t)(qemu_plugin_id_t id,
                             const struct qemu_plugin_scan_insn *insn,
                             void *userdata);

enum {
    QEMU_PLUGIN_SCAN_LINEAR = 1 << 0, /* keep decoding past a transfer     */
    QEMU_PLUGIN_SCAN_PHYS   = 1 << 1, /* start/end are physical addresses  */
};

/* Opaque decode-mode token; see below. */
struct qemu_plugin_scan_mode;

QEMU_PLUGIN_API
struct qemu_plugin_scan_mode *qemu_plugin_scan_mode_current(void);
QEMU_PLUGIN_API
struct qemu_plugin_scan_mode *qemu_plugin_insn_scan_mode(
                                  const struct qemu_plugin_insn *insn);

/* Returns instructions decoded, or a negative errno-style code. */
QEMU_PLUGIN_API
int64_t qemu_plugin_scan_range(uint64_t start, uint64_t end,
                               const struct qemu_plugin_scan_mode *mode,
                               uint32_t scan_flags,
                               qemu_plugin_scan_cb_t cb, void *userdata);
```

### 5.4 Why each field is there

This is not a wish list. Every field below maps to a specific thing tcgcov does
today with a regex, and to a specific bug in `docs/ARCHITECTURES.md`.

| Field | Why a coverage tool needs it | What it replaces |
|---|---|---|
| `vaddr` | **the denominator key** — fed to `addr2line` to produce `(source, line)`, which is tcgcov's merge identity (README, *"Why merge by source + line"*) | `coverable.parse_addresses` over objdump text |
| `size` | next instruction, block extent, and the fall-through address | the `insn_size` profile key, and address-delta inference from objdump columns (`docs/ARCHITECTURES.md` §5.2, §5.3) |
| `cf_kind` | ends the block; and **only `COND_BRANCH` becomes a coverage point** — tcgcov builds a `BranchPoint` for COND alone | the `conditional` / `unconditional` / `call` / `return` regexes in every profile |
| `cf_flags & INDIRECT` | branch points with no statically knowable outcome must be **excluded**, not reported uncovered — reporting them uncovered is a lie, nothing can ever cover them | the `indirect` regex, absent from several profiles (`docs/ARCHITECTURES.md` §3, §4.4) |
| `target` | the "taken" outcome address — one of the two LCOV `BRDA` outcomes | `cfg._parse_target`, its four trust-ranked sources, and the whole PC-relative-vs-absolute problem (`docs/ARCHITECTURES.md` §4.1) |
| `cf_flags & DELAY_SLOT` | fall-through is `vaddr + size + next_size`, **not** `vaddr + size`; and a delay-slot instruction must never become a block leader | `has_delay_slot` + the `delay_slot` regex (`docs/ARCHITECTURES.md` §4.2) |
| `cf_flags & UNDECODED` | lets the consumer **exclude data-in-`.text` from the denominator** rather than inventing coverable lines for it | nothing — tcgcov has no way to detect this today |

The `DELAY_SLOT` entry deserves emphasis, because getting it wrong is
undetectable:

> *"Getting this wrong means the 'not taken' outcome is attributed to the
> delay-slot instruction, which executes on **both** paths — so the branch reads
> as fully covered no matter what the program did."*
> — `docs/ARCHITECTURES.md` §4.2

A field carrying that fact from the target front-end, which knows it for
certain, replaces a regex that must guess it from a mnemonic suffix.

### 5.5 The decode-mode token

Decoding is **not** a pure function of the instruction bytes. This is the
single most under-appreciated fact in the whole design, and it is why the API
takes a mode token rather than just an address range. **Verified examples:**

* **i386**: `dc->flags = dc->base.tb->flags` (`target/i386/tcg/translate.c:3760`)
  carries `CODE32` (CS.D) and `CODE64` (long mode), which select `s->dflag` /
  `s->aflag` (`target/i386/tcg/decode-new.c.inc:2697-2712`), decide whether
  `0x40..0x4f` is a REX prefix or `INC`/`DEC` (`:2606-2615`), and decide whether
  `C4`/`C5` is VEX or `LES`/`LDS` (`:2623`, `:2629`).
* **ARM**: `dc->thumb = EX_TBFLAG_AM32(tb_flags, THUMB)`
  (`target/arm/tcg/translate.c:6291`); the entire `TranslatorOps` differs
  (`arm_tr_translate_insn` at `:6499` vs `thumb_tr_translate_insn` at `:6589`).
* **MicroBlaze**: `dc->tb_flags = dc->base.tb->flags` and
  `dc->ext_imm = dc->base.tb->cs_base`
  (`target/microblaze/translate.c:1615-1616`), and see §7.4.
* **RISC-V**: ~30 fields from `tb_flags` in `riscv_tr_init_disas_context`
  (`target/riscv/translate.c:1293-1339`), including `ctx->xl` (XLEN) at `:1320`.

So the caller must supply a mode. Two constructors are proposed:

* `qemu_plugin_scan_mode_current()` — snapshot the mode of the vCPU right now,
  the same way `get_tb_cpu_state` does for `tb_gen_code`;
* `qemu_plugin_insn_scan_mode(insn)` — **snapshot the mode under which an
  observed instruction was translated.**

The second is the interesting one. A coverage tool has already watched real
code execute. If `main()` was translated in ARM state, the mode token taken
from any instruction in `main()` is the right mode to scan the rest of that
function's address range with. It converts a static-analysis problem (*"is this
region ARM or Thumb?"*) into an observation. It does not solve the problem —
§7.6 — but it is strictly better than asking the caller to guess.

### 5.6 What each target must expose that it does not today

This is the load-bearing question for upstreamability, and the answer is better
than expected: **for at least one target, all the information already exists and
is merely target-private.**

**`is_jmp` is not usable as a classification.** Two verified counterexamples:

* **RISC-V collapses everything.** `gen_jal` sets `DISAS_NORETURN`
  (`target/riscv/translate.c:643`); `trans_jalr` sets `DISAS_NORETURN`
  (`target/riscv/insn_trans/trans_rvi.c.inc:192`); `gen_branch` — a
  *conditional* branch — also sets `DISAS_NORETURN`
  (`trans_rvi.c.inc:328`). And `riscv_tr_tb_stop` accepts only
  `DISAS_TOO_MANY` and `DISAS_NORETURN`, with `g_assert_not_reached()` for
  anything else (`target/riscv/translate.c:1404-1417`). Conditionality is
  expressed *only* as emitted TCG structure — two `goto_tb` slots.
* **MicroBlaze does not set it in branch handlers at all.** `do_branch`
  (`target/microblaze/translate.c:1059-1086`), `do_bcc` (`:1101-1135`) and
  `do_rts` (`:1268-1284`) set `dc->jmp_cond` and `dc->jmp_dest` and leave
  `is_jmp` alone; the value is decided much later, in the delay-slot state
  machine at `:1660-1706`.

But look at what MicroBlaze *does* set:

| Target-private field | Value | Maps to |
|---|---|---|
| `dc->jmp_cond = TCG_COND_ALWAYS` (`:1084`, `:1280-1282`) | unconditional / return | `CF_BRANCH` / `CF_RETURN` |
| `dc->jmp_cond = cond` (`:1113`) | a real `TCGCond` | `CF_COND_BRANCH` |
| `dc->jmp_dest = -1` (`:1078`) vs an absolute value (`:1081`, `:1120`, `:1123`) | indirect vs direct | `CF_F_INDIRECT` / `CF_F_HAS_TARGET` + `target` |
| `setup_dslot()` → `D_FLAG` (`:1051-1057`; flag at `target/microblaze/cpu.h:267-281`) | has a delay slot | `CF_F_DELAY_SLOT` |

**That is the entire proposed structure, already computed, already correct,
already re-read downstream** (`mb_tr_tb_stop` consults
`dc->jmp_cond != TCG_COND_ALWAYS` at `:1740`). The MicroBlaze patch is
therefore on the order of a handful of lines: publish four values that the
front-end already has.

The proposed mechanism is a new optional member of `DisasContextBase`:

```c
struct DisasContextBase {
    ...
    /* Filled in by translate_insn when the target supports it.
     * Zero-initialised per instruction; CF_NONE/no flags means
     * "falls through", CF_UNKNOWN means "transfers, kind not modelled". */
    struct DisasControlFlow cf;
};
```

with a per-target adoption gradient:

| Target class | Effort | Result if not adopted |
|---|---|---|
| MicroBlaze | ~6 lines; all four values already computed | — |
| RISC-V, and decodetree targets generally | a line per `trans_*` in `insn_trans/*.c.inc` | `CF_UNKNOWN` |
| i386, ARM | harder — classification is spread across `emit.c.inc` (`gen_JMP` at `target/i386/tcg/emit.c.inc:2313-2317`, `gen_Jcc` at `:2295-2302`) and `gen_jmp_rel` (`target/i386/tcg/translate.c:2325-2380`) | `CF_UNKNOWN` |
| the 7 fully hand-written targets (alpha, i386, m68k, s390x, sh4, tricore, xtensa) | per-target judgement | `CF_UNKNOWN` |

**Graceful degradation is the point.** A target that never adopts CF
annotation still yields `vaddr` and `size` for every instruction, which is a
complete and authoritative **line-coverage denominator** — the thing §1.1 says
fails catastrophically when it goes missing. Branch coverage is the part that
needs per-target work, and it can land one target per patch, which is exactly
the shape QEMU review prefers.

### 5.7 The QMP surface, briefly

Once `translator_scan()` exists, a `query-code-inventory` QMP command (or an
HMP `info code-inventory`) taking a range and returning the same per-instruction
records is a small amount of additional code. It is worth having for three
reasons, none of them tcgcov's:

1. it makes the mechanism testable from `tests/qtest` without any plugin;
2. it gives non-plugin consumers (§9) a stable, versioned, introspectable
   interface with QMP's own compatibility rules rather than the plugin ABI's;
3. it turns the existing *"Disassembler disagrees with translator over
   instruction decoding"* warning (`disas/disas-target.c:52-58`) from an
   incident report into a sweep you can run over a whole image.

It cannot replace the plugin API for tcgcov, because it cannot be seeded from a
plugin's observed decode modes (§5.5) or from the addresses the plugin watched
execute (§4.4).

---

## 6. Difficulties, honestly

Each of these is a reason the patch is harder than the API sketch suggests.
None of them is fatal; several change the design.

### 6.1 Decoders have side effects and assume a live CPU

Beyond the TCG-manipulation cases in §5.2, front-ends read live CPU state
during decode, not just `tb->flags`:

* **i386 reads CPUID feature words directly from `env`**
  (`target/i386/tcg/translate.c:3783-3790`), consumed by `has_cpuid_feature`
  (`target/i386/tcg/decode-new.c.inc:2300`, checked at `:2725`).
* **i386 checks the CPU vendor mid-decode**: `IS_INTEL_CPU(env)` at
  `target/i386/tcg/decode-new.c.inc:2735` and `:2742` — the same byte stream is
  a legal instruction or `#UD` depending on whether the emulated CPU is Intel or
  AMD.
* **MicroBlaze reads CPU config at fetch time** for endianness
  (`mb_cpu_is_big_endian(cs)`, `target/microblaze/translate.c:1650`;
  `target/microblaze/cpu.h:416-421`) and consults `dc->cfg` for
  `illegal_opcode_exception` (`:139`) and `opcode_0_illegal` (`:1298`).
* **RISC-V takes its decoder list from the CPU instance**:
  `ctx->decoders = cpu->decoders` (`target/riscv/translate.c:1338`), and gates
  16-bit decoding on `has_ext(ctx, RVC) || ctx->cfg_ptr->ext_zca` (`:1269`).

**Consequence**: a scan needs a real `CPUState`. That is fine for a plugin and
for QMP — there is always a vCPU — but it kills any fantasy of extracting this
into an offline library. It also means the scan result is a property of *this
emulated CPU model*, which is arguably more correct than objdump's view but is
a different thing from "what the ISA allows".

**And one case is a genuine correctness hazard**: s390x's `extract_insn` writes
to `env` during decode (`target/s390x/tcg/translate.c:6126-6127`, clearing
`ex_value`). Scanning must not perturb guest state. Whether any *other* target
does this has not been checked — see §10.

### 6.2 decodetree names an instruction; it does not classify it

decodetree generates a dispatcher (`scripts/decodetree.py:1628-1642`) that
calls hand-written `trans_<NAME>` functions returning `bool`
(`:552-558`, call at `:595-596`). The `.decode` file carries **names and field
extraction, and nothing about control flow**.

MicroBlaze is the clean illustration. `target/microblaze/insns.decode:82` is
`beq` and `:89` is `beqd`; the delay-slot variant is a *separate pattern with a
separate name* and no marker of any kind. The delay-slot fact lives in C
constants passed to macros in `translate.c` — the `DELAY` argument of `DO_BR`
(`:1088-1099`) and the `delay` parameter of `do_bcc`/`DO_BCC`
(`:1101`, `:1137-1145`) — and is applied by `setup_dslot` (`:1051-1057`).

**Consequence**: you cannot mine `.decode` files for this. Classification must
be annotated in the `trans_*` bodies. An alternative worth naming — adding a
decodetree *attribute* syntax so a pattern could declare
`cf=cond_branch,delay` — is attractive on paper but is a change to a tool used
by eleven targets, and would need the attribute to be optional and ignored by
the existing consumers. Not proposed here, but a reviewer will suggest it.

Note also that eleven of nineteen targets have checked-in `.decode` files
(arm, avr, hppa, loongarch, microblaze, mips, openrisc, ppc, riscv, rx, sparc;
hexagon generates them at build time), and **seven are fully hand-written**
(alpha, i386, m68k, s390x, sh4, tricore, xtensa) — with arm, mips and ppc being
hybrids that retain large legacy decoders alongside decodetree. Any
decodetree-level solution reaches at most a bit over half the targets.

### 6.3 `is_jmp` does not distinguish conditional from unconditional

Covered in §5.6 with the RISC-V and MicroBlaze evidence. Restating the
consequence: **the classification cannot be derived generically from existing
`DisasContextBase` state.** It has to be added, per target, by hand. That is
the honest cost of this proposal and there is no way around it.

### 6.4 Code versus data

There is no general answer, and the front-ends actively make it harder by
converting "not an instruction" into "an instruction that faults":

* **MicroBlaze silently ignores it.** `trap_illegal`
  (`target/microblaze/translate.c:136-143`) emits a hardware exception **only
  if** `(dc->tb_flags & MSR_EE) && dc->cfg->illegal_opcode_exception`;
  otherwise the illegal instruction is a no-op and translation continues. A
  scan of a literal pool would produce a clean run of "instructions" with no
  complaint whatsoever.
* **i386 emits `#UD` and stops.** `gen_illegal_opcode`
  (`target/i386/tcg/translate.c:1564-1567`) → `gen_exception` (`:1554-1560`),
  which sets `DISAS_NORETURN` at `:1559`. Labels at
  `target/i386/tcg/decode-new.c.inc:2908-2916`. Good news for robustness — data
  in `.text` does **not** blow up the process — but the scan sees
  "instruction, undefined", not "not code".
* **RISC-V** likewise: `gen_exception_illegal`
  (`target/riscv/translate.c:264-273`) emits code and sets `DISAS_NORETURN`
  (`:261`).

**Design consequence**: `QEMU_PLUGIN_CF_F_UNDECODED` must be sourced from the
decoder's own `false` return (`scripts/decodetree.py:1641`), captured *before*
the front-end converts it into an emitted exception. For the seven
hand-written targets there is no single such return value and the flag would
have to be plumbed from each illegal-opcode path individually.

Even with that flag, a byte sequence that happens to be a valid encoding is
indistinguishable from code. Literal pools full of pointers decode beautifully.
**This problem is not solved by moving to QEMU's decoders**; it is only made
*detectable* in the cases where the decoder genuinely rejects the bytes.

### 6.5 Statefulness: the same bytes decode differently depending on history

MicroBlaze has two instances, both verified, both nasty:

* **The `imm` prefix.** `trans_imm` (`target/microblaze/translate.c:459-468`)
  sets `dc->ext_imm` and `IMM_FLAG`; the decodetree field function `typeb_imm`
  (`:79-85`, referenced as `!function=typeb_imm` by `%extimm` at
  `target/microblaze/insns.decode:30`) then splices the saved upper 16 bits into
  the *next* instruction's immediate. **The same 32-bit type-B word yields a
  different immediate — and therefore a different branch target — depending on
  whether the preceding instruction was `imm`.**
* **The delay-slot flag.** `D_FLAG` in `tb->flags` says a TB *begins* inside a
  delay slot (`target/microblaze/cpu.c:98-107` propagates
  `env->iflags & IFLAGS_TB_MASK` and `env->imm` into `flags`/`cs_base`; read
  back at `target/microblaze/translate.c:1615-1619`).

QEMU itself treats both as part of the decode *context*, not the byte stream —
which is the clearest possible confirmation that a stateless scan is unsound.

tcgcov already knows this on the objdump side and handles it the only honest
way: *"A branch whose immediate is preceded by an `imm` prefix is **refused
outright** rather than resolved from the printed low half"*
(`docs/ARCHITECTURES.md` §3). A scan API inherits the same problem and should
inherit the same answer — the mode token (§5.5) can carry `IMM_FLAG`/`ext_imm`,
but a scan that *starts* at an arbitrary address cannot know them, and must say
so rather than guess.

### 6.6 Thumb/ARM interworking and mapping symbols

The mode problem in its worst form.

`thumb_insn_is_16bit` (`target/arm/tcg/translate.c:6121-6158`) makes
instruction *length* depend on CPU features (`:6137`) and on position within the
page (`:6145`). Above that, ARM/Thumb state is per-*function*, switched by
`BX`/`BLX` and encoded in bit 0 of the target address — so a single `.text`
section contains interleaved regions in two different instruction sets, plus
literal pools in neither.

The ELF answer is **mapping symbols** (`$a`, `$t`, `$d`), and objdump uses them.
**QEMU cannot**: there is no plugin-facing symbol table
(`plugins/api-system.c:21-43`, §2.4), and `qemu_plugin_insn_symbol` is a single
address lookup (`plugins/api.c:307-311`).

**Consequence**: on ARM the mode token must come either from observed execution
(§5.5) or from the host, which read the ELF. This is a place where the proposal
does **not** let tcgcov delete its ELF knowledge, only its mnemonic knowledge.

### 6.7 Self-modifying and dynamically generated code

A scan is a **snapshot**. Code written at *t₁* is invisible to a scan at *t₀*.
QEMU has thorough machinery for *invalidating* translations when code changes
(`accel/tcg/tb-maint.c`, and the precise-SMC max_insns forcing at
`accel/tcg/translate-all.c:609`) but no "code appeared" event a plugin could
subscribe to.

For firmware — tcgcov's stated primary target — this is mostly moot. For a JIT
guest it makes the whole denominator model questionable, and it is the same
underlying issue as the timeline ambiguity in `docs/DYNAMIC-OBJECTS.md` §1:
*addresses are only unique within a time window*.

### 6.8 ROM/flash aliasing, overlays, XIP

The same physical code frequently appears at several virtual addresses (boot
ROM aliased low and high, flash mirrored into a cached and an uncached window).
A scan of a virtual range will decode the same instructions twice and produce
two denominators for one piece of code. `qemu_plugin_translate_vaddr()`
(§2.2, `plugins/api.c:575-592`) can canonicalise to a physical address, which is
why `QEMU_PLUGIN_SCAN_PHYS` is in the sketch — but DWARF is keyed by *link-time
virtual* address, so canonicalising breaks symbolization. Banked overlays are
worse: the range holds different code at different times and a snapshot sees one
bank. **Unconsidered in this design.**

---

## 7. What tcgcov would gain, and what it would still need

### 7.1 What goes away

If a patched QEMU could produce `(vaddr, size, cf_kind, cf_flags, target)` per
instruction, then the following becomes dead code:

* **the nine registered `ArchProfile` objects** (`tcgcov/cfg.py`, roughly
  `:239-548`) and the `ArchProfile` class and classifier around them
  (`class ArchProfile`, `cfg.py:119`; `get_profile`, `:834`; `detect_arch`,
  `:822`);
* **the disassembly text parser** — `parse_objdump` (`cfg.py:1079`),
  `match_insn_line`, `_instruction_text`, the `INSN_RE` layout handling;
* **`_parse_target` and its four trust-ranked sources**, and with them the
  entire PC-relative-versus-absolute question;
* **the `--arch-profile` JSON schema** and its documentation
  (`docs/ARCHITECTURES.md` §7).

More importantly, it kills whole *classes* of bug, not individual bugs. Every
item in the porting checklist:

| `ARCHITECTURES.md` | The bug | Why it cannot recur |
|---|---|---|
| §4.1 | absolute vs PC-relative operands (`brai 256` resolved to `0x1100` instead of `0x100`; *"wrong for a year"*) | the front-end computes the target; there is no operand to interpret |
| §4.2 | delay-slot fall-through off by one instruction | `CF_F_DELAY_SLOT` comes from `setup_dslot`, which is the ground truth |
| §4.3 | conditional calls (`bl<cc>`) swallowed by the `call` pattern and deleted from the denominator | `cf_kind` is set by the handler, not inferred from spelling |
| §4.4 | indirect branches parsed as having a target (`jmp *0x10(%rax)` → `0x10`) | `CF_F_INDIRECT` comes from `jmp_dest == -1` and its equivalents |
| §4.5 | aliases and disassembler spellings (`beqz` vs `c.beqz`, `b` vs `ba`, `retq` vs `ret`) | there is no text |
| §4.6 | false positives (`bsrli` classified as a branch, corrupting the block map) | there is no regex |
| §5.1 | tab vs space after the address colon — branch coverage silently vanished | there is no text |
| §5.2-5.4 | `--no-show-raw-insn`, hex-spellable mnemonics (`be`, `ba`, `bc`), raw-byte continuation lines | there is no text |
| §5.5 | stripped binaries lose `<sym+0xoff>` and every direct branch became "indirect" | targets come from the decoder, not from symbols |

All of §5 disappears for one reason: **the interchange stops being English.**
That alone is a large share of the historical bug count.

### 7.2 What does not go away

Be precise about this; the proposal is worth less if oversold.

1. **DWARF, and therefore `addr2line`, stays.** QEMU has no line-table access —
   `qemu_plugin_insn_symbol` is a single-symbol lookup
   (`plugins/api.c:307-311`) and there is no debug-info API of any kind.
   tcgcov's entire identity is `(source path, line)` merging, which is the
   design decision the rest of the tool hangs off (README, *"Why merge by
   source + line, not by address"*). A scan gives better **addresses**; it
   gives nothing at all about **lines**.
2. **Indirect targets remain unknowable.** `CF_F_INDIRECT` is a better-sourced
   version of the same exclusion tcgcov already applies; it does not resolve a
   single jump table. Branch points with no statically knowable outcome pair
   stay excluded from branch coverage, and stay counted separately.
3. **The host still reads the ELF.** Something must decide *what range to
   scan*, and QEMU will not say (§2.4). Program headers, section boundaries and
   — on ARM — mapping symbols stay on the host side.
4. **objdump stays as a fallback, for a long time.** A patched QEMU is not a
   thing users have. Until and unless this lands upstream and propagates into
   distributions, the profiles cannot actually be *deleted*; they become the
   fallback path. §8 stages around this, and §10 lists it as the main risk to
   the whole premise.
5. **Code-versus-data is improved, not solved** (§6.4).
6. **`CF_UNKNOWN` targets get line coverage only.** Seven targets are fully
   hand-written and may never adopt CF annotation. For those, the profile
   deletion is partial indefinitely.

### 7.3 A fair summary

> The proposal replaces *"parse the output of a second, independent
> disassembler with per-ISA regexes"* with *"ask the emulator's own decoder"*.
> It does not replace *"read the ELF"* or *"read the DWARF"*, and it does not
> make indirect control flow statically knowable. The win is concentrated
> entirely in the layer that has produced the most bugs.

---

## 8. A staged plan

### Stage 0 — what stock QEMU already allows, today, with no patch

**For the denominator: nothing.** §1 and §2 are conclusive.

**For the numerator: one clear improvement that has not been taken.**

`qemu_plugin_insn_size()` exists (`include/qemu/qemu-plugin.h:585-586`,
`plugins/api.c:263-266`) and is QEMU's authoritative instruction length. tcgcov
**never calls it** — verified by grep over `plugin/tcgcov.c`, whose only
per-instruction API uses are `qemu_plugin_insn_vaddr` at `:705`, `:718`, `:738`.
Nor does it call `qemu_plugin_insn_disas`.

Today the host re-derives instruction sizes from objdump address deltas and
re-derives which instruction ends a block from mnemonic regexes — **for code
that QEMU already decoded and already knows the answers about**. Concretely,
recording `(vaddr, size)` per executed instruction would give:

* a **self-describing numerator**: the artifact would carry instruction extents
  without any host-side ISA knowledge;
* the fall-through address of every executed block **for free**. tcgcov already
  records `last_insn_vaddr` (`plugin/tcgcov.c:705`) because the edge source is
  published from the last instruction of the block; with its size, the host
  knows the next address without knowing the ISA;
* **a cross-check against the objdump parse.** Comparing QEMU's executed-address
  set against the objdump-derived instruction addresses would have made the
  §5.1 tab-versus-space failure *loud* instead of silent — the case where the
  parser found zero instructions and everything downstream reported success.

That last point is the real argument. It does not fix the denominator, but it
converts the most dangerous failure mode from silent to detected, using an API
that already exists. **This is worth doing regardless of whether anything else
in this document ever happens.**

A note on `qemu_plugin_insn_disas()`: it is tempting as an objdump replacement,
but it routes through `plugin_disas` (`disas/disas-target.c:73-98`) — the
**second** decoder (§3.6), the same libopcodes family objdump uses. It would
give text for executed code only, from the same source of truth, with a
different column layout to parse. That is not obviously an improvement and is
not recommended.

### Stage 1 — out-of-tree QEMU patch, MicroBlaze only

Implement `translator_scan()` (§5.2) and `qemu_plugin_scan_range()` (§5.3),
with `DisasControlFlow` filled in by MicroBlaze alone.

**MicroBlaze is the right first target for three independent reasons**, and it
is worth stating them because the choice is not arbitrary:

1. **Fixed-width, no length problem at all** — `pc_next += 4`
   (`target/microblaze/translate.c:1662`), so linear sweep is exactly correct
   and §4's circularity largely evaporates for the first cut.
2. **The classification data already exists** (§5.6) — `jmp_cond`, `jmp_dest`,
   `D_FLAG` — so the target patch is minimal.
3. **It is the only arch with a validated oracle.** Per
   `docs/ARCHITECTURES.md` §2, MicroBlaze is *"the only profile that has been
   shown to produce a correct branch report on a real program"*: it has an
   exhaustively cited profile, a genuine GNU objdump golden fixture
   (`tests/data/gnu-microblaze.txt`, 111 instructions, 4 conditional branches
   with verified targets and fall-throughs, `tests/test_golden_disasm.py`), and
   an end-to-end QEMU run (`examples/branch-coverage/`) whose outcomes are known
   by construction.

So the scan output can be diffed against a known-good answer on day one. Every
other arch would be validating one unvalidated thing against another.

### Stage 2 — a second backend in `cfg.py`, cross-checked

Add a scan-artifact backend beside the objdump backend, producing the same
`Insn` / `Block` / `BranchPoint` structures. Then assert, on MicroBlaze, that
the two backends produce the **identical instruction address set and the
identical `(addr, mnemonic-kind, taken, fallthrough)` tuples** — mirroring the
existing assertion that objdump and the branch inventory see the same addresses
(`tests/test_golden_disasm.py`).

Disagreements are interesting in both directions and neither side is
automatically right. This is the stage that would surface the real error rate of
the current profiles.

### Stage 3 — upstream RFC

Mechanism first, surface second (§5.1). Suggested series shape:

| Patch | Content |
|---|---|
| 1 | `DisasControlFlow` in `DisasContextBase`, zero-initialised, unused |
| 2 | `translator_scan()` in `accel/tcg/translator.c` with non-faulting fetch |
| 3 | MicroBlaze fills in `cf` |
| 4 | `query-code-inventory` QMP command + a qtest |
| 5 | `qemu_plugin_scan_range()` plugin API + a `tests/tcg/plugins/` consumer |

Patches 1-4 are defensible without the plugin ABI commitment, which matters
(§9.3).

### Stage 4 — per-target CF annotation

One patch per target, each independently useful, each degrading to
`CF_UNKNOWN` if not merged. Order by ease: decodetree targets with a clean
branch handler set (riscv, openrisc, loongarch, sparc, hppa) before the
hybrids (arm, mips, ppc) before the hand-written ones (i386, s390x, m68k).

### Stage 5 — tcgcov demotes the profiles

Only after a patched QEMU is realistically available. The profiles become the
fallback path selected when the scan API is absent, and `ARCHITECTURES.md`
becomes a document about the fallback rather than about the primary mechanism.
**This is years away and may never arrive** — see §10.

---

## 9. Upstreaming considerations

### 9.1 Would the maintainers want it?

**Arguments in favour:**

* It is not a new decoder. It is a **second consumer of an existing one**, and
  QEMU already has three targets doing exactly that with decodetree
  (`target/loongarch/disas.c`, `target/openrisc/disas.c`, `target/rx/disas.c`;
  §3.7). The proposal generalises an established in-tree pattern.
* It reduces, rather than increases, QEMU's decoder duplication problem. QEMU
  ships **two** decoders per target (§3.6) and prints a *"Disassembler disagrees
  with translator over instruction decoding / Please report this to
  qemu-devel"* warning when they diverge (`disas/disas-target.c:52-58`). A scan
  API makes that comparison a sweep instead of an accident.
* The `CF_UNKNOWN` default means no target is *obliged* to do anything.

**Objections to expect:**

* *"The front-ends are the most fragile per-target code in the tree; a second
  consumer means a second way to break them."* True. Mitigated by
  decode-and-discard (§5.2) reusing the identical code path rather than a
  parallel one.
* *"This adds a per-target obligation that will bit-rot."* Also true. A new
  branch instruction added without a `cf` annotation silently reports
  `CF_NONE`, which is worse than `CF_UNKNOWN`. **The API should default the
  classification pessimistically**: `CF_UNKNOWN` whenever the target ended the
  block (`is_jmp != DISAS_NEXT`) without setting `cf`. Cheap, and it converts
  bit-rot from wrong data into missing data.
* *"Just use Capstone."* The strongest objection and it needs a real answer.
  Capstone is already in-tree (`disas/capstone.c`) but QEMU uses it for only
  four targets — arm, i386, ppc, s390x — and carries eleven libopcodes-derived
  decoders under `disas/` plus four QEMU-native ones under `target/<t>/disas.c`
  for the rest. Using Capstone *is* the second-decoder disagreement problem
  QEMU already warns about. And it does not answer the mode-statefulness
  problems in §6.5 at all, because it has no `tb->flags`.

### 9.2 Who else benefits

| Consumer | Use |
|---|---|
| **Coverage-guided fuzzers** | AFL++'s QEMU mode carries its own out-of-tree QEMU patches precisely because the plugin API cannot express what it needs; a block inventory is directly useful for seed scheduling and for a static edge denominator (**unverified** — no current qemuafl source was examined) |
| **Rehosting / firmware analysis** | tools that need a block inventory for a binary with no source and no symbols, on ISAs Capstone does not cover |
| **Disassembler validation** | sweep the TCG front-end against Capstone/libopcodes over a whole image, instead of waiting for `disas-target.c:52-58` to fire |
| **QEMU's own test suite** | a decode sweep over `tests/tcg` binaries is a strong regression test for front-end changes |
| **tcgcov, and other coverage tools** | the case this document makes |

### 9.3 API stability and the versioning wrinkle

`QEMU_PLUGIN_VERSION` is **5** (`include/qemu/qemu-plugin.h:79`);
`QEMU_PLUGIN_MIN_VERSION` is **2** (`plugins/plugin.h:19`), enforced at load
(`plugins/loader.c:214`, `:219`) and reported to plugins at `:298`. The header's
own policy statement (`:45-49`) is that the *minimum* is incremented only *"if
an API needs to be deprecated"*.

So a pure addition would not bump anything — and that is precisely the problem.
The version-history block (`include/qemu/qemu-plugin.h:45-75`) documents what
each version added:

```
 * version 5:
 * - added qemu_plugin_write_memory_vaddr
 * - added qemu_plugin_read_memory_hwaddr
 * - added qemu_plugin_write_memory_hwaddr
 * - added qemu_plugin_write_register
 * - added qemu_plugin_translate_vaddr
```

**The discontinuity API is not in that list.** `qemu_plugin_register_vcpu_discon_cb`
(`:295-298`), `qemu_plugin_vcpu_discon_cb_t` (`:203-206`) and
`enum qemu_plugin_discon_type` (`:179-184`) are present and exported
(`build/plugins/qemu-plugin.symbols`), but appear nowhere in the version
history and did not bump `QEMU_PLUGIN_VERSION`. **Verified**: the only "discon"
occurrences in the header are in the declaration region, none in lines 45-75.

tcgcov had to work around exactly this. `plugin/Makefile`:

```make
# Feature probe: discontinuity callbacks were added part-way through plugin API
# version 5 with no version bump, so QEMU_PLUGIN_VERSION cannot distinguish a
# header that has them from one that does not. Look for the symbol itself.
PLUGIN_HEADER := $(firstword $(wildcard $(QEMU_PLUGIN_H) \
                                        $(QEMU_INCLUDE)/qemu/qemu-plugin.h \
                                        $(QEMU_INCLUDE)/qemu-plugin.h))
HAVE_DISCON := $(shell grep -qs qemu_plugin_register_vcpu_discon_cb \
                         "$(PLUGIN_HEADER)" && echo 1 || echo 0)
CFLAGS    += -DTCGCOV_HAVE_DISCON=$(HAVE_DISCON)
```

A build system that greps a header for a symbol name is a workaround for a
missing convention, and the tool records the outcome in its artifact metadata
(`discon_tracking`) because it cannot otherwise be inferred.

A scan API would land the same way and every consumer would need the same
`grep`. **The RFC should therefore also propose a documented feature-probe
convention** — a `#define QEMU_PLUGIN_HAS_SCAN 1` alongside the declaration, or
a general rule that every addition gets a `QEMU_PLUGIN_HAS_*` macro. It costs
one line per addition, it is backward-compatible by construction, and it fixes
a real ergonomic bug that has already bitten at least one out-of-tree plugin.
Bundling a small, obviously-good fix with a large proposal is also good RFC
strategy.

---

## 10. Open questions

These are genuinely unresolved. They are the reason this is a proposal and not
a patch.

1. **Should the scan suppress the translator's non-CFG block terminations, or
   inherit them?** §3.4 lists four terminations that are artifacts (op-buffer
   pressure, insn budget, MMIO, `translator_io_start`) and one that is
   half-and-half (page crossing). Suppressing them means the scan diverges from
   what the real translator does, which weakens the "authoritative, same code
   path" claim that is the whole argument for doing this in QEMU. Inheriting
   them means the consumer gets fragmented blocks and has to stitch — which is
   what tcgcov does today anyway (`docs/ARCHITECTURES.md` §8.1). **Unresolved,
   and it is the most consequential design question in this document.**

2. **Do any targets besides s390x mutate guest state during decode?** s390x's
   `extract_insn` writes `env->ex_value` (`target/s390x/tcg/translate.c:6126-6127`).
   A scan must not perturb the guest. There is currently **no rule** saying
   front-ends may not do this, and only five of nineteen targets were examined
   for this document. Establishing such a rule may itself be a prerequisite
   patch series.

3. **What does a decode-and-discard scan actually cost?** Completely
   unmeasured. A full `.text` sweep of a large image at roughly translation
   cost could be seconds or minutes. If it is minutes, the API is only usable
   at exit and only once, which changes how tcgcov would call it.

4. **Is the mode token sufficient for ARM?** ARM/Thumb state is per-function,
   and `qemu_plugin_insn_scan_mode()` (§5.5) only covers regions that
   *executed*. For a region that never ran — the entire point of a denominator
   — the mode is exactly what is unknown. Falling back to ELF mapping symbols
   means the host keeps ISA-specific knowledge on the one ISA where it is most
   painful. **No good answer identified.**

5. **Is a size-only scan worth the patch on its own?** For the seven
   hand-written targets, `CF_UNKNOWN` gives `(vaddr, size)` and nothing else —
   a correct line denominator, no branch coverage. That is arguably the more
   valuable half (§1.1) but it means "delete the arch profiles" is partial for
   a very long time, and possibly permanently.

6. **Who supplies the range?** QEMU cannot say where `.text` is
   (`plugins/api-system.c:21-43`). If the host supplies it, tcgcov keeps an ELF
   reader forever. If QEMU grows a section/module API, that is a separate and
   considerably more contentious patch — and it overlaps with the module-map
   question in `docs/DYNAMIC-OBJECTS.md` §7, which wants the same information
   for a different reason. **These two proposals should probably be reconciled
   before either is posted.**

7. **Is a one-shot denominator the right model at all?** §6.7 and
   `docs/DYNAMIC-OBJECTS.md` §1 arrive at the same place from different
   directions: addresses are only meaningful within a time window. If the scan
   must be re-runnable and the artifact must carry generations, that is a
   `.cov` format change, and it is the same format change
   `DYNAMIC-OBJECTS.md` §8 question 2 is undecided about. Deciding these
   independently would be a mistake.

8. **Plugin API, QMP, or both — and in which order?** A QMP-only first cut
   commits nothing about the plugin ABI, is testable in `tests/qtest`, and is
   much easier to land. But it cannot be seeded from a plugin's observed decode
   modes (§5.5) or from executed addresses (§4.4), so tcgcov would gain little
   from it directly. Landing QMP first to establish the mechanism, then adding
   the plugin surface, is probably right — but it means tcgcov gets nothing
   from stage 3 and must wait for stage 5.

9. **Has something like this been proposed upstream before?** No mailing-list
   archive was consulted. If a similar API has been rejected, the reasons are
   the single most valuable missing input to this document.

---

## 11. What could not be verified

Stated plainly, since §1 argues the whole point of this exercise is not
reporting success you have not earned.

| Claim | Status |
|---|---|
| QEMU version / provenance | `/Users/sprice5/src/qemu-upstream` has **no `.git`**. `VERSION` reads `10.2.4` and `build/config-host.h:494` agrees, but there is no commit hash, no tag, and no way to confirm the tree matches a released 10.2.4 |
| Which QEMU release added the discontinuity API | **Not established.** `git log -S` was impossible (no `.git`). What is verified: it is present and exported in this tree, absent from the version-history block (`qemu-plugin.h:45-75`), and `QEMU_PLUGIN_VERSION` is still 5. The release number is unknown |
| Decode-time side effects across all targets | Only microblaze, riscv, i386, s390x and (partially) arm were examined. **14 targets unchecked** (§10 q2) |
| Cost of decode-and-discard | Unmeasured (§10 q3) |
| Whether `translator_scan()` can actually reuse `TranslatorOps` unmodified | **Not prototyped.** §5.2 argues it can; nothing has been compiled |
| Fuzzer benefit (§9.2) | Reasoning only. No current qemuafl or AFL++ QEMU-mode source was examined |
| Upstream reception | No RFC posted, no maintainer asked, no archive searched |
| tcgcov line numbers | `tcgcov/cfg.py` is under concurrent edit. Symbol names in this document are authoritative; the line numbers may drift. Line numbers quoted *from* `docs/ARCHITECTURES.md` carry that document's own drift caveat |
| The premise itself | The largest unverified assumption is that a patched QEMU could ever become common enough for tcgcov to rely on. If it cannot, the profiles never get deleted and this is a document about a permanent fallback (§7.2 item 4) |

---

## References

| | |
|---|---|
| QEMU plugin API | `include/qemu/qemu-plugin.h` (`QEMU_PLUGIN_VERSION 5` at `:79`, history `:45-75`); `plugins/api.c`, `plugins/api-system.c`, `plugins/core.c`, `plugins/loader.c`, `plugins/meson.build`; QEMU 10.2.4 |
| Generic translator | `accel/tcg/translator.c` (`translator_loop` `:122-246`), `include/exec/translator.h` (`DisasContextBase` `:67-91`, `DisasJumpType` `:33-49`, `TranslatorOps` `:117-124`) |
| Translation entry from execution | `accel/tcg/cpu-exec.c:577`, `:970`; `accel/tcg/translate-all.c:238-258`, `:261`; `include/accel/tcg/cpu-ops.h:51-63` |
| Plugin instrumentation hooks | `accel/tcg/plugin-gen.c` (`plugin_gen_tb_start` `:414-441`, `plugin_gen_tb_end` `:493-512`) |
| decodetree | `scripts/decodetree.py` (generated `decode()` `:1628-1642`, `trans_*` decl `:552-558`, variable width `:1145-1150`, `build_size_tree` `:1428-1477`); `docs/devel/decodetree.rst` |
| MicroBlaze front-end | `target/microblaze/translate.c` (`mb_tr_translate_insn` `:1636`, `do_branch` `:1059-1086`, `do_bcc` `:1101-1135`, `do_rts` `:1268-1284`, `setup_dslot` `:1051-1057`, `typeb_imm` `:79-85`, delay-slot state machine `:1660-1706`, `mb_tr_tb_stop` `:1709-1777`); `target/microblaze/insns.decode`; `target/microblaze/cpu.h:267-281`; `target/microblaze/cpu.c:98-107` |
| RISC-V front-end | `target/riscv/translate.c` (`decode_opc` `:1236-1291`, `riscv_tr_tb_stop` `:1404-1417`), `target/riscv/internals.h:231-234`, `target/riscv/insn_trans/trans_rvi.c.inc` |
| i386 front-end | `target/i386/tcg/translate.c` (`X86_MAX_INSN_LENGTH` `:1661`, `advance_pc` `:1663-1688`, `i386_tr_translate_insn` `:3820`), `target/i386/tcg/decode-new.c.inc` (`disas_insn` `:2536`) |
| ARM Thumb length rule | `target/arm/tcg/translate.c:6121-6158` |
| QEMU's second decoders | `disas/disas-target.c` (`target_disas` `:20-60`, disagreement warning `:52-58`, `plugin_disas` `:73-98`), `disas/meson.build:1-14`, `disas/capstone.c`; decodetree reuse at `target/loongarch/disas.c`, `target/openrisc/disas.c`, `target/rx/disas.c` |
| tcgcov static pipeline | [`../README.md`](../README.md), [`ARCHITECTURES.md`](ARCHITECTURES.md), [`FORMAT.md`](FORMAT.md); `tcgcov/cfg.py`, `tcgcov/coverable.py`, `tcgcov/branches.py` |
| tcgcov plugin | `plugin/tcgcov.c`, `plugin/Makefile` (the `HAVE_DISCON` header probe) |
| Related proposal | [`DYNAMIC-OBJECTS.md`](DYNAMIC-OBJECTS.md) — overlaps on the module-map and artifact-generation questions (§10 q6, q7) |
