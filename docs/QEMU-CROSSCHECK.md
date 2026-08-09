# Cross-checking the arch profiles against QEMU's translators

`tcgcov/cfg.py`'s eight arch profiles were originally derived from the binutils
opcode tables — the tables that decide what `objdump -d` *prints*. This document
re-derives the same question from a second, independent authority: **QEMU's
per-target TCG translators**, which must know exactly which instructions
redirect the PC because they have to emit `gen_goto_tb` / `tcg_gen_exit_tb` /
`lookup_and_goto_ptr` and end the translation block.

The two sources disagree in interesting places, and the disagreements are the
point.

Trees checked, and the versions the line numbers belong to:

| Tree | Version | Path |
|---|---|---|
| QEMU | 10.2.4 | `/Users/sprice5/src/qemu-upstream` |
| binutils-gdb | 2.46.50 | `/Users/sprice5/src/claude-mb/binutils-gdb` |
| tcgcov | `872d44e` | this repo |

---

## 1. Method

### What each source is authoritative for

**binutils is authoritative for TEXT.** `objdump -d` output is literally
generated from `opcodes/*-opc.c` / `*-dis.c`, so those tables settle every
question of the form "what string will tcgcov's regex actually see" — which
alias is printed, whether a condition suffix is glued or spaced, whether an
operand prints in decimal or hex, whether a row is `INSN_MACRO`/`F_ALIAS` and
therefore never disassembled at all.

**QEMU is authoritative for SEMANTICS.** A translator that failed to end a TB at
a control transfer would execute the wrong code, so the set of instructions with
`is_jmp != DISAS_NEXT` is a checked, executable specification of "this redirects
the PC". It also answers questions the opcode tables cannot: whether a branch is
really two-way, whether an operand is PC-relative or absolute, whether a delay
slot exists, and whether a mnemonic that *looks* like a branch actually
transfers (SPARC `bn`).

Neither source alone is sufficient. binutils will happily disassemble an
instruction QEMU cannot execute; QEMU will happily execute an encoding whose
printed spelling is nothing like the decodetree pattern name.

### The encoding-vs-text mapping problem

**QEMU decodes ENCODINGS. tcgcov matches DISASSEMBLY TEXT. There is no automatic
correspondence between the two.** QEMU's `a32.decode` names a pattern `BL`; the
same encoding prints as `bl`, `bleq`, `blne`, … depending on a field QEMU never
mentions in the pattern name. QEMU's `insn16.decode:205` names a pattern
`cm_jalt`; binutils prints *two* mnemonics (`cm.jt` and `cm.jalt`) for it,
selected by an operand value. QEMU's SPARC `trans_NCP` covers an entire opcode
space whose hardware mnemonics are `cb0`, `cb02`, `cb123`, …

Every row in the tables below therefore carries an explicit bridge. Bridges are
labelled:

* **VERIFIED (table)** — the mnemonic string was read out of the binutils opcode
  table, with a file:line.
* **VERIFIED (executed)** — the classification was obtained by importing
  `tcgcov.cfg` and calling `profile.classify()` / `.is_indirect()` /
  `.delays()` on the literal text, not by reading the regex.
* **INFERRED** — the mapping is an argument from the ISA manual or from
  structure, not a citation. Flagged inline.

Everything asserted about tcgcov's behaviour below was obtained by **executing**
the shipped profiles, because these regexes are subtle enough that reading them
produces wrong answers. Two of the findings reported by the QEMU-side survey of
this work were **refuted** that way (see §3.6) — reading a pattern and running it
are not the same activity.

### What was compared

For each of the eight profiled ISAs: every instruction in QEMU's translator that
sets `is_jmp` to something other than `DISAS_NEXT`, or calls `gen_goto_tb` /
`tcg_gen_exit_tb` / `tcg_gen_lookup_and_goto_ptr`, versus the
`OTHER`/`COND`/`UNCOND`/`CALL`/`RET` bucket the shipped profile puts the
corresponding printed mnemonic in — plus the orthogonal `indirect`, `absolute`
and `delay_slot` predicates.

---

## 2. Per-architecture comparison

Legend for the "tcgcov" column: the bucket from `ArchProfile.classify()`
(`cfg.py:161-167`), with `+ind` when `is_indirect()` is also true and `+delay`
when `delays()` is true. **OTHER means the instruction does not terminate a
basic block** (`cfg.py:1169`), which is the failure mode that silently merges
blocks.

### 2.1 MicroBlaze — agrees

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `bri` `brid` `brlid` | `do_branch` `translate.c:1059-1086`, `add_pc = dc->base.pc_next` (`:1076`) | UNCOND / UNCOND+delay / CALL+delay | agree |
| `brai` `braid` `bralid` | same, `add_pc = 0` (`:1076`, `abs=true` via `DO_BR` `:1094-1099`) | UNCOND+abs / UNCOND+abs+delay / CALL+abs+delay | agree |
| `br` `brd` `bra` `brad` `brld` `brald` | register target, `do_branch:1077-1082` | UNCOND/CALL **+ind** | agree |
| 24 × `beq/bne/blt/ble/bgt/bge{,d,i,id}` | `do_bcc` `translate.c:1101-1135`; PC-relative always (`:1119-1124`) — no absolute conditional form exists | COND, `d`/`id` forms +delay, register forms +ind | agree |
| `rtsd` `rtid` `rtbd` `rted` | `do_rts` `translate.c:1268-1284`, always `setup_dslot` (`:1278`), always `jmp_dest = -1` (`:1281`) | RET+delay | agree |
| `brk` / `brki` | `trans_brk` `translate.c:1154-1172` → `DISAS_EXIT`; `trans_brki` `:1174-1219` → `DISAS_EXIT` (`:1215`) or `DISAS_NORETURN` in user mode (`:1194-1197`). Neither calls `setup_dslot` | CALL (+ind for `brk`, +abs for `brki`), no delay | agree |
| `mbar` (incl. `sleep`/`hibernate`/`suspend` = `mbar 16`/`8`/`24`) | `trans_mbar` `translate.c:1221-1266`, **always** `DISAS_EXIT_NEXT` (`:1264`); comment at `:1225` calls it "a specialized branch instruction" | OTHER | agree — see §4.1 |
| `mts` | `trans_mts` `translate.c:1366-1423` → `DISAS_EXIT_NEXT` (`:1420`) | OTHER | agree — see §4.1 |
| `msrclr` / `msrset` | `do_msrclrset` `translate.c:1319-1354` → `DISAS_EXIT_NEXT` (`:1351`) only when `imm` touches bits outside `MSR_C\|MSR_CC\|MSR_PVR` (`:1345-1352`) | OTHER | agree — see §4.1 |
| `wdc` / `wic` | `trans_wdic` `translate.c:589-594` — no `is_jmp` write at all | OTHER | agree |
| `imm` | `trans_imm` `translate.c:459-468` — prefix only | OTHER | agree |

Bridges VERIFIED (table) against `opcodes/microblaze-opc.h:195-201` (register
forms), `:219-222` (rts family), `:223-229` (immediate forms), `:424-427`
(`mbar` + its three pseudo-forms).

**The `absolute` set is right, and a plausible-looking objection to it is
wrong.** QEMU marks *six* mnemonics absolute — `bra`, `brad`, `brald`, `brai`,
`braid`, `bralid` (`DO_BR` `translate.c:1094-1099` passing `abs=true`, consumed
at `do_branch:1076`) — while `cfg.py:258` lists only `bralid|braid|brai|brki`.
That is not a gap: `bra`/`brad`/`brald` are `INST_TYPE_R2`/`INST_TYPE_RD_R2`
(`microblaze-opc.h:198-200`), i.e. **register**-operand forms with no immediate
to be absolute *about*. They are covered by `indirect` (`cfg.py:254-255`), and
`_parse_target` short-circuits on `is_indirect` before `is_absolute` is ever
consulted (`cfg.py:923-924`). Adding them to `absolute` would be dead code.

`rtsd`/`rtid`/`rtbd`/`rted` are not in the `indirect` pattern even though their
target is always `R[ra] + imm` (`do_rts:1281-1282`). Also harmless: they classify
RET, and `_parse_target` is only called for COND/UNCOND/CALL (`cfg.py:1027`).

### 2.2 RISC-V — one real gap (Zc extensions)

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `jal` / `j` | `gen_jal` `translate.c:617-644` → `gen_goto_tb` (`:642`), `DISAS_NORETURN` (`:643`) | CALL / UNCOND | agree |
| `jalr` / `jr` / `ret` | `trans_jalr` `insn_trans/trans_rvi.c.inc:141-195` → `lookup_and_goto_ptr` (`:186`) | CALL+ind / UNCOND+ind / RET | agree |
| `beq…bgeu` + aliases | `gen_branch` `trans_rvi.c.inc:269-331`, two `gen_goto_tb` (`:300`, `:325`) | COND | agree |
| `c.j` `c.jal` `c.jr` `c.jalr` `c.beqz` `c.bnez` | pure decodetree aliases onto the above (`insn16.decode`, no `trans_rvc.c.inc` exists) | as above via the optional `(c\.)?` prefix | agree |
| **`cm.jt` / `cm.jalt`** | `trans_cm_jalt` `trans_rvzce.c.inc:302-340`: `tcg_gen_mov_tl(cpu_pc, addr)` (`:335`), `lookup_and_goto_ptr` (`:337`), `DISAS_NORETURN` (`:338`); links into `ra` iff `index >= 32` (`:316-320`). Decode `insn16.decode:205` | **OTHER** | **DIFFER — F3** |
| **`cm.popret` / `cm.popretz`** | `gen_pop` `trans_rvzce.c.inc:205-217`: `tcg_gen_mov_tl(cpu_pc, ret_addr)`, `lookup_and_goto_ptr`, `DISAS_NORETURN`. Decode `insn16.decode:200-201` | **OTHER** | **DIFFER — F3** |
| `cm.push` / `cm.pop` | `trans_cm_push` / `trans_cm_pop` — `ret=false`, `cpu_pc` untouched | OTHER | agree (must *not* be swept up by a `^cm\.` pattern) |
| `mret` `sret` `mnret` | `trans_privileged.c.inc:94-140` → helper + `exit_tb`, `DISAS_NORETURN` | OTHER | see §4.3 |
| `ecall` `ebreak` | `trans_privileged.c.inc:27-76` → `generate_exception` `translate.c:257-262`, `DISAS_NORETURN` | OTHER | see §4.3 |
| `wfi` | `trans_privileged.c.inc:142-152` — helper only, no `is_jmp`; TB exit is a runtime effect | OTHER | agree |
| `uret` | `trans_uret` returns `false` unconditionally — illegal instruction | OTHER | agree |
| `hret` | no decode entry anywhere in QEMU; exists at `riscv-opc.c:2368` | OTHER | agree |

Bridges VERIFIED (table): `riscv-opc.c:2337` `cm.popret`, `:2338` `cm.popretz`,
`:2343` `cm.jt`, `:2344` `cm.jalt` — **all four have a flags field of `0`**, i.e.
neither `INSN_MACRO` nor `INSN_ALIAS`, so GNU objdump really prints these
strings. Confirmed independently of the QEMU survey.

An independent sweep of every `riscv-opc.c` row carrying `INSN_BRANCH` or
`INSN_JSR` (excluding `INSN_MACRO`) found **0 of 27** classified OTHER — the
non-Zc core is complete.

### 2.3 ARM A32/T32 — two real gaps, both CFG-corrupting

The mechanism that matters: **A32/T32 conditionality is applied uniformly,
outside the instruction's own translator.** `disas_arm_insn`
(`target/arm/tcg/translate.c:6062-6106`) reads `cond = insn >> 28` and, for any
`cond` other than `0xe`/`0xf`, calls `arm_skip_unless(s, cond)`
(`translate.c:2247-2250`) *before* dispatching. Thumb does the same from the IT
state (`thumb_tr_translate_insn` `translate.c:6647-6663`). The condition-failed
path is then emitted once, at TB end, as a **second** `gen_goto_tb` into exit
slot 1 (`arm_tr_tb_stop` `translate.c:6821-6828`). So *any* A32 instruction with
a condition field — including `bx`, `tbb` and every ALU op — is a genuine
two-outcome branch in QEMU's IR, and no `trans_*` function contains condition
logic of its own.

binutils glues the suffix with no separator: `%c` expands to
`arm_conditional[cond]` (`arm-dis.c:8201-8204`, array at `:4917-4919`), and `AL`
is mapped to the empty string via `COND_UNCOND` (`arm-dis.c:7949-7951`).

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `b` / `b<cc>` | `trans_B` `translate.c:5327` → `gen_jmp` | UNCOND / COND | agree |
| `bl` / `bl<cc>` | `trans_BL` `translate.c:5349-5353`, no cond logic; cond from `:6104-6106` + `:6821` | CALL / **COND** | agree — the deliberate design at `cfg.py:315-326` is correct |
| `blx` imm/reg | `trans_BLX_i` `:5355`, `trans_BLX_r` `:3468-3479` → `gen_bx` | CALL (+ind for the register form) | agree |
| `bx r3` / `bxj r3` | `trans_BX` `:3441` → `gen_bx_excret`, `DISAS_JUMP`; `trans_BXJ` `:3450-3467` | UNCOND+ind | agree |
| **`bx<cc> r3` / `bxj<cc> r3`** | same trans function; conditionality from `:6104-6106`, second exit at `:6821` | **OTHER** (+ind) | **DIFFER — F1** |
| `tbb` / `tbh` | `op_tbranch` `translate.c:5708-5734` → `store_reg(s,15,…)`, `DISAS_JUMP` | UNCOND+ind | agree |
| **`tbb<cc>` / `tbh<cc>`** | same | **OTHER** (+ind) | **DIFFER — F1, worst case** |
| `bxns` / `blxns` | `trans_BXNS` `:3495-3502`, `trans_BLXNS` `:3503-3510` → `DISAS_EXIT` | UNCOND+ind / CALL | agree |
| `cbz` / `cbnz` | `trans_CBZ` `:5738-5745` | COND | agree |
| `mov pc,` / `ldr pc,` / `ldm…{pc}` / `pop {pc}` | `store_reg_from_load` `:878-884` → `gen_bx_excret`; `do_ldm` `:5161-5224` | UNCOND / RET | agree |
| **`mov<cc> pc,` / `ldr<cc> pc,` / `pop<cc> {pc}` / `bx<cc> lr`** | two-way (`:6821-6828`) | UNCOND / RET — **never COND** | **DIFFER — F4** |
| **`sub`/`subs`/`add`/`and`/`orr`/`bic`/`eor`/`rsb`/`rsc`/`adc`/`sbc`/`orn`/`mvn` writing `pc`** | `store_reg_kind` `translate.c:2422-2450` (per-opcode selection `:2604-2673`): `STREG_NORMAL` → `store_reg_bx`/`gen_bx` → `DISAS_JUMP`; `STREG_EXC_RET` → `gen_exception_return` `:1694` → `DISAS_EXIT` | **OTHER** | **DIFFER — F2** |
| `wls` / `wlstp` / `le` / `letp` | `trans_WLS` `:5466-5537`, `trans_LE` `:5538-5652` — both genuinely two-way | COND | agree |
| `dls` / `dlstp` / `lctp` | `trans_DLS` `:5428-5465` — not a branch | OTHER | agree, deliberately |
| `bf` / `bfx` / `bfl` / `bflx` / `bfcsel` | `trans_BF` `translate.c:5408-5426` — **implemented as a NOP**, "we take that IMPDEF option" | OTHER | agree; QEMU confirms the profile note |
| `svc` `hvc` `smc` `eret` `rfe*` `wfi` `wfe` | `DISAS_SWI`/`DISAS_HVC`/`DISAS_SMC`/`DISAS_EXIT`; `trans_ERET` `:3526-3543`, `trans_RFE` `:5789-5813` → `gen_rfe` `:1684-1693` | OTHER | see §4.3 |
| `cps` / `setend` / `srs` | `DISAS_EXIT` / `DISAS_UPDATE_EXIT`; PC not redirected | OTHER | agree |

### 2.4 AArch64 — agrees

There is no IT-block / condition-field mechanism on A64; every conditional form
open-codes its own two-`goto_tb` pair, which structurally rules out the F1 bug
class.

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `b` | `trans_B` `translate-a64.c:1693-1698` | UNCOND | agree |
| `b.<cc>` / `bc.<cc>` | `trans_B_cond` `:1752-1770`, two `gen_goto_tb` | COND | agree |
| `cbz`/`cbnz`, `tbz`/`tbnz` | `trans_CBZ` `:1716-1731`, `trans_TBZ` `:1733-1750` | COND | agree |
| `bl` | `trans_BL` `:1700-1714` | CALL | agree |
| `br` / `blr` / `ret` | `trans_BR` `:1796-1802`, `trans_BLR` `:1804-1818`, `trans_RET` `:1820-1831` → `gen_a64_set_pc` + `DISAS_JUMP` | UNCOND+ind / CALL+ind / RET | agree |
| `braa/brab/braaz/brabz`, `blraa/blrab/blraaz/blrabz`, `retaa/retab` | `trans_BRAZ`/`BRA` `:1855-1869`,`:1911-1924`; `trans_BLRAZ`/`BLRA` `:1870-1891`,`:1925-1946`; `trans_RETA` `:1892-1910` | UNCOND+ind / CALL+ind / RET | agree |
| `eret` / `eretaa` / `eretab` | `trans_ERET` `:1947-1972`, `trans_ERETA` `:1974-2010` → `DISAS_EXIT` | RET (via `eret\w*`) | agree |
| `svc` `hvc` `smc` `brk` `hlt` | `translate-a64.c:3151,3169,3189,3203,3209` → `DISAS_NORETURN` | OTHER | see §4.3 |
| `drps` | `a64.decode:230` is commented out — **QEMU does not decode it** (UNDEFs) | OTHER | agree under QEMU |
| CMPBR `cb<cc>`/`cbb<cc>`/`cbh<cc>` | **not implemented** — no pattern in `a64.decode`, no `trans_` in `translate-a64.c` | COND | tcgcov ahead of QEMU; see §3.5 |

An independent sweep of every branch-iclass row in `aarch64-tbl.h` found 17
classified OTHER; **16 of them are `F_ALIAS \| F_PSEUDO`** no-dot spellings
(`beq`, `bne`, `blt`, … at `aarch64-tbl.h:5251-5266`) that GNU objdump never
prints — the disassembled row is `"b.c"` with `F_COND` at `:4435`. The 17th is
`drps` (`:4418`). So the profile is complete against GNU objdump. See §5, A9 for
the caveat about other disassemblers.

All 30 CMPBR spellings in `aarch64-tbl.h` (`cbeq`…`cbhls`) are covered by
`cfg.py:401`'s `cb[bh]?(eq|ne|gt|ge|hi|hs|lt|le|lo|ls)` — verified by extracting
the mnemonics from the table and running them through `classify()`.

### 2.5 x86 / x86-64 — agrees on transfers; the TB-enders are correctly OTHER

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `j<cc>` | `gen_Jcc` `emit.c.inc:2295` → `gen_jcc` `translate.c:1246` + two `gen_jmp_rel` (`:1994`) | COND | agree |
| `loop`/`loope`/`loopne`/`jcxz`/`jecxz`/`jrcxz` | `emit.c.inc:2431,2441,2453,2304` — `tcg_gen_brcondi_tl` + two `gen_jmp_rel`, mechanically identical to Jcc | COND | agree |
| `jmp` rel / indirect / far | `gen_JMP` `emit.c.inc:2313`, `gen_JMP_m` `:2319`, `gen_JMPF{,_m}` `:2326,2331` | UNCOND (+ind on `*`) | agree |
| `call` rel / indirect / far | `gen_CALL` `emit.c.inc:1576`, `gen_CALL_m` `:1582`, `gen_CALLF{,_m}` `:1588,1593` | CALL (+ind) | agree |
| `ret` / `retf` / `iret` | `gen_RET` `emit.c.inc:3602`, `gen_RETF` `:3613`, `gen_IRET` `:2283` → `DISAS_EOB_ONLY` | RET | agree |
| `sysret` / `sysexit` | `emit.c.inc:4179`, `:4173` | RET | agree |
| `syscall` / `sysenter` | `emit.c.inc:4150`, `:4167` → `DISAS_EOB_RECHECK_TF` / `DISAS_EOB_ONLY` | OTHER | see §4.3 |
| `int n` / `int3` / `int1` | `gen_INT`/`gen_INT3` → `gen_interrupt` `translate.c:2262`; `gen_INT1` `emit.c.inc:2263-2269` → `DISAS_NORETURN` | OTHER | see §4.3 |
| `into` | `gen_INTO` `emit.c.inc:2275-2281` — **never sets `is_jmp`**; the OF test is entirely inside the helper | OTHER | agree — QEMU does not treat it as a transfer either |
| `hlt` | `gen_HLT` `emit.c.inc:2045-2052` → `DISAS_NORETURN` | OTHER | agree; resumption address is the textual fall-through |
| `ud2` / decode failure | `gen_illegal_opcode` `translate.c:1554-1564` → `DISAS_NORETURN` | OTHER | agree |
| `jmpabs` | **not implemented** — no APX/REX2 decode anywhere in `target/i386/`; `0xD5` is legacy `AAD` at `decode-new.c.inc:1706` | UNCOND | tcgcov ahead of QEMU; binutils prints it at `i386-dis.c:14640` |
| `sti`, `mov→cr/dr`, `wrmsr`, `xsetbv`, `lmsw`, `invlpg`, `clts`, `rsm`, `popf`, `xrstor`, `pop ss`/`mov ss`, `mwait`, `pause`, `rdpmc`, `stgi`, `vmrun` | all end the TB (`DISAS_EOB_NEXT` / `DISAS_EOB_INHIBIT_IRQ` / `DISAS_EOB_ONLY` / `DISAS_NORETURN`) for interrupt-shadow / TLB / CPU-state reasons; destination is **always** the next sequential instruction | OTHER | **agree, and this is the correct answer** — see §4.1 |
| `cli` | `gen_CLI` `emit.c.inc:1621` — does not even end the TB | OTHER | agree |

Regex-ordering audit for x86 came back clean when executed: `ret` does not
swallow `retq`/`retf`, `call` does not swallow `callq`, no `_X86_CC` alternative
equals `m`/`mp` so `jmp` can never be read as a Jcc, and `jmpabs` precedes `jmp`
in the alternation (`cfg.py:450`). The `\b` at the end of each alternation plus
Python's backtracking is what makes all of this safe.

### 2.6 MIPS — agrees, one ASE gap

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `b`/`bal`, `beq…bgez`, `*l` likely forms, `bltzal`/`bgezal(l)` | `gen_compute_branch` `translate.c:4379-4637` → `MIPS_HFLAG_{B,BL,BC}`, consumed by `gen_branch` `:10944-11000` (`DISAS_NORETURN` at `:10950`) | UNCOND/CALL/COND, all +delay | agree |
| `j`/`jal`/`jr`/`jalr`/`jr.hb`/`jalr.hb` | same, `MIPS_HFLAG_BR` → `lookup_and_goto_ptr` | UNCOND/CALL/RET, +ind, +delay | agree |
| r6 compact: `bc`, `balc`, `beqzc`…`bnvc`, `*alc` | `gen_compute_compact_branch` `translate.c:11003-11224` | UNCOND/CALL/COND, **no delay** | agree |
| `jic` / `jialc` | same function, `rs==0` path `:11057-11100`; `gen_branch(ctx,4)` called at `:11100` so **no delay-slot instruction is ever processed** | UNCOND+ind / CALL+ind, no delay | agree — independently confirmed by `NODS` at `mips-opc.c:3257,3261` |
| `jic $ra` | as above | RET (register-keyed) | agree |
| `bc1f`/`bc1t`/`bc1fl`/`bc1tl` | `gen_compute_branch1` `translate.c:8695-8794` | COND+delay | agree |
| `bc1eqz` / `bc1nez` | `gen_compute_branch1_r6` `translate.c:8797-8845`, always `MIPS_HFLAG_BC` (`:8813-8833`) | COND+delay | agree |
| `bposge32` / `bposge64` | `translate.c:4587-4594` — `tcg_gen_setcondi_tl(TCG_COND_GE, …)` → `MIPS_HFLAG_BC` | COND+delay | agree |
| `bbit0`/`bbit1`/`bbit032`/`bbit132` | `trans_BBIT` `octeon_translate.c:16-42` → `MIPS_HFLAG_BC` (`:38`) | COND+delay | agree |
| `bz.*` / `bnz.*` (MSA) | `msa_translate.c:219-282`, always `MIPS_HFLAG_BC` (`:238`,`:268`) | COND+delay | agree |
| **`bc1any2f/t`, `bc1any4f/t`** (MIPS-3D) | handled by `gen_compute_branch1` `translate.c:8695-8794` | **OTHER** | **DIFFER — F5** |
| `bc2t`/`bc2f`/`bc2eqz`/`bc2nez` | opcodes declared (`translate.c:966-968`) but **never dispatched** — `OPC_CP2` is repurposed for Loongson LMMI at `:14862-14866` | COND | tcgcov ahead of QEMU |
| `nal` | `bltzal $0, .+4` — links, never transfers | OTHER | agree (the MIPS analogue of SPARC `bn`) |
| `syscall` / `break` | `translate.c:13271-13275` → `DISAS_NORETURN` | OTHER | see §4.3 |
| `eret` / `eretnc` / `deret` | `translate.c:8635-8668` → `DISAS_EXIT` | OTHER | see §4.3 |
| `wait` | `translate.c:8670-8683` → unconditional `DISAS_NORETURN` | OTHER | agree |

An independent sweep of every `mips-opc.c` row flagged `UBD`/`CBD` (branch
delay) found **5 of 52** classified OTHER: the four `bc1any*` above, plus `nal`.

The delay-slot rule `^(?!\w+c\b)\w+` (`cfg.py:521`) was checked against QEMU's
actual split and is exactly right: every classic branch goes through
`gen_compute_branch`'s deferred path, every r6 compact branch calls `gen_branch`
immediately.

### 2.7 PowerPC — agrees on everything that is printed by default

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `b`/`ba`/`bl`/`bla` | `gen_b` `translate.c:3697-3717` → `gen_goto_tb` + `DISAS_NORETURN` (`:3716`) | UNCOND/CALL | agree |
| `bc`/`bca`/`bcl`/`bcla` and all extended forms (`blt`,`bne`,`bdnz`,`bt`,…) | `gen_bcond(BCOND_IM)` `translate.c:3724-3841`; CTR test `:3752-3801`, CR test `:3802-3816`; both arms end in a `goto_tb` (`:3820-3826`, `:3838`) | COND | agree |
| `blr` / `bctr` / `btar` (BO=20 always-taken aliases) | `gen_bcond` with `BO==20`: **neither** the CTR test at `:3752` **nor** the CR test at `:3802` fires — no conditional TCG at all | RET+ind / UNCOND+ind / UNCOND+ind | agree — **verified by execution**, see §3.6 |
| `bctrl` / `btarl` | as above with `gen_setlr` (`:3747-3750`) | CALL+ind | agree |
| conditional to LR/CTR/TAR (`beqlr`, `bltctr`, `bnetar`, `bdnzlr`, …) | `gen_bcond(BCOND_LR/CTR/TAR)`, real `brcondi` before the indirect jump (`:3752-3816`), target from `cpu_lr`/`cpu_ctr`/`SPR_TAR` (`:3731-3743`) | COND+ind → branch point with no static target, EXCLUDED | agree |
| **raw `bclr` / `bclrl`** | same, generic BO — genuinely conditional | **RET** (the `ret` pattern `^(blr\|bclr)l?[+-]?\b` wins first) | **DIFFER — F6, zero coverage impact** |
| **raw `bcctrl` / `bctarl`** | same | **CALL** | **DIFFER — F6, zero coverage impact** |
| `sc` / `scv` | `translate.c:4002`, `:4013-4015` → `DISAS_NORETURN` | OTHER | see §4.3 |
| `rfi` / `rfid` / `rfscv` / `hrfid` | `translate.c:3937,3952,3967,3981` → `DISAS_EXIT` | OTHER | see §4.3 |
| `rfebb` | `translate/branch-impl.c.inc:23` → `DISAS_CHAIN` | OTHER | see §4.3 |
| `tw`/`twi`/`td`/`tdi` | `check_unconditional_trap` `translate.c:4023-4035`: `TO==31` → `DISAS_NORETURN` (`:4031`); `TO==0` → no-op; **every other `TO` never touches `is_jmp`** — the trap is a runtime helper effect | OTHER | agree |
| `nap`/`doze`/`sleep`/`rvwinkle`/`stop` | `translate.c:3424-3502` → `DISAS_NORETURN` | OTHER | agree |
| POWER-only spellings | not decoded by QEMU at all | OTHER | see §3.5 |

The whole to-LR/CTR/TAR extended-mnemonic space was enumerated from `ppc-opc.c`
and run through `classify()`: all 14 condition spellings × {lr, ctr, tar} ×
{`l`,`a`,`+`,`-`} suffixes classify COND+ind correctly, including the POWER8
`*tar` family at `ppc-opc.c:7093-7210`.

### 2.8 SPARC — agrees, and the `bn` decision is now positively verified

| Instruction | QEMU treatment | tcgcov | Verdict |
|---|---|---|---|
| `Bicc`/`BPcc` (`be`,`bne`,`bg`,…) | `gen_compare` `translate.c:1113-1210` → `advance_jump_cond` `:2600-2678`, `dc->npc = JUMP_PC` (`:2663`) | COND+delay | agree |
| `FBfcc`/`FBPfcc` (`fbe`,`fbne`,…) | `gen_fcompare` `translate.c:1212-1270` | COND+delay | agree |
| `BPr` (`brz`,`brnz`,`brlez`,…) | `gen_compare_reg` `translate.c:1272-1295`; reserved `cond&3==0` → `return false` → illegal instruction (`:1282-1284`) | COND+delay | agree |
| `ba`/`fba` | `cond` 8 → `TCG_COND_ALWAYS` (`translate.c:1207-1209`) | UNCOND+delay | agree |
| **`bn` / `fbn` (branch never)** | `gen_compare:1122-1125` / `gen_fcompare:1227-1229` → `TCG_COND_NEVER`; `advance_jump_cond:2619-2632` emits **no** `gen_goto_tb`, **no** `exit_tb`, **no** `lookup_and_goto_ptr`, and does **not** set `is_jmp` — translation continues linearly in the same TB | **OTHER** | **agree — tcgcov is right, now verified not merely argued** |
| `bn,a` annul | `advance_jump_cond:2624` / `:2628` still advance past the delay slot | inexpressible (documented at `cfg.py:588-590`) | known limitation |
| `call` | `trans_CALL` `translate.c:2738-2746` — static target, links `%o7` | CALL+delay (+ind on `%`) | agree |
| `jmpl` | `do_jmpl` `translate.c:4292-4309` → `dc->npc = DYNAMIC_PC_LOOKUP` (`:4307`) | UNCOND+ind+delay | agree |
| `rett` / `return` | `do_rett` `:4313-4327` (`DYNAMIC_PC`), `do_return` `:4331-4342` (`DYNAMIC_PC_LOOKUP`) | RET (+delay for `rett`, none for `return`) | see §5, U1 |
| `Tcc` (`ta`,`tne`,`tge`,…) | `do_tcc` `translate.c:2775-2826`; `cond==0` (`tn`) → plain `advance_pc` (`:2784-2787`), otherwise a real conditional trap | OTHER | see §4.3 |
| `done` / `retry` | `do_done_retry` `translate.c:4364-4381` → `dc->npc = dc->pc = DYNAMIC_PC` (`:4369-4370`) | OTHER | see §4.3 |
| `cb`/`cba` (branch-always), `cb0`…`cb013` (14 conditional) | **QEMU does not decode CBccc at all**: `insns.decode:19` routes the whole `op2=7` space to `NCP`, and `trans_NCP` `translate.c:2748-2760` raises `TT_NCP_INSN` (32-bit) or returns `false` (64-bit) | UNCOND / COND | tcgcov ahead of QEMU; see §3.5 |
| `cwb*` / `cxb*` (M7 CBcond) | zero decode support — no `cbcond`/`cwb`/`cxb` anywhere in `target/sparc/` | COND, no delay | tcgcov ahead of QEMU |

An independent sweep of every `sparc-opc.c` row flagged `F_UNBR`/`F_CONDBR`/
`F_JSR` found **0** classified OTHER (`bn`/`fbn`/`cbn` excluded by design).

The 14 numeric `cb*` spellings (`sparc-opc.c:1690-1706`) and the 14 sparclet
letter spellings (`:1953-1967`) were each enumerated and run through
`classify()` — the profile's `_SPARC_CB` group (`cfg.py:604-605`) covers all 28
with no gaps and no shadowing, and correctly leaves bare `cb`/`cba` in
`unconditional` (`sparc-opc.c:1688-1689`, `F_UNBR`).

---

## 3. Findings that matter, ranked

### 3.1 F1 — ARM conditional `bx`/`bxj`/`tbb`/`tbh` are invisible (CFG-corrupting)

**`cfg.py:343`'s `unconditional` pattern has no condition-suffix group**, while
the sibling `ret` (`:349-353`) and `indirect` (`:357-359`) patterns both do. The
result, executed:

```
bx r3        -> uncond  (indirect)
bxeq r3      -> OTHER   (indirect)     <-- does not terminate a block
bxjne r3     -> OTHER   (indirect)
tbbeq [pc, r3]           -> OTHER  (indirect)
tbhne [pc, r3, lsl #1]   -> OTHER  (indirect)
```

The profile **contradicts itself**: `is_indirect("bxeq r3")` is `True` while
`classify("bxeq r3")` is `OTHER`. It knows the instruction is a register-target
transfer and still declines to call it one.

* QEMU: these are real two-way transfers — `trans_BX` (`translate.c:3441`),
  `trans_BXJ` (`:3450-3467`), `op_tbranch` (`:5708-5734`) all end the TB, and the
  condition adds a second exit at `:6821-6828`.
* Text bridge VERIFIED (table): `"bx%c\t%0-3r%T"` (`arm-dis.c:3398`),
  `"bxj%c\t%0-3R"` (`:3808`), `"tbb%c\t[…]"` (`:4563`), `"tbh%c\t[…]"` (`:4565`);
  `%c` glues `arm_conditional[cond]` on with no separator (`:8201-8204`).
* Impact: `OTHER ∉ TERMINATORS` (`cfg.py:116`), so `build_blocks` does not split
  there (`cfg.py:1169`). Blocks merge across the transfer. **For `tbb<cc>`/
  `tbh<cc>` it is worse than a merge** — the inline jump table sits in the bytes
  immediately after, objdump disassembles those bytes as instructions, and they
  get spliced into the surviving block. `cfg.py:338-342` documents exactly this
  hazard for the unconditional spelling and then leaves the conditional one open.

Conditional `bx`/`tbb` are not exotic: A32 `bxeq lr`-style tails are ordinary
compiler output, and any Thumb `bx`/`tbb` inside an IT block prints with a
suffix.

### 3.2 F2 — ARM ALU-writes-PC is entirely unmodelled (CFG-corrupting)

Only `mov`/`movs` and `ldr` are recognised as PC writers (`cfg.py:344`, `:353`,
`:359`). Executed:

```
sub  pc, lr, #4   -> OTHER     subs pc, lr, #8  -> OTHER
add  pc, pc, r3   -> OTHER     and  pc, r0, r1  -> OTHER
orr  pc, r0, r1   -> OTHER     eor  pc, r0, r1  -> OTHER
bic  pc, r0, r1   -> OTHER     rsb  pc, r0, r1  -> OTHER
mvn  pc, r0       -> OTHER     adds pc, lr, #4  -> OTHER
```

`subs pc, lr, #4` is the classic A32 IRQ return and `add pc, pc, rN` the classic
A32 jump-table dispatch; neither terminates a block today.

* QEMU handles all of these through one dispatcher: `store_reg_kind`
  (`translate.c:2422-2450`), selected per-opcode at `:2604-2673`. `STREG_NORMAL`
  → `store_reg_bx`/`gen_bx` → `DISAS_JUMP`; `STREG_EXC_RET` (the `SUBS/MOVS
  PC,LR` exception-return family) → `gen_exception_return` (`:1694`) →
  `DISAS_EXIT`.
* Text bridge VERIFIED (table): the A32 data-processing rows print
  `"<op>%20's%c\t%12-15r, %16-19r, %o"` (`arm-dis.c:3914`, `:3921`,
  `:3924-3928`), and register 15 prints as `pc`.

### 3.3 F3 — RISC-V Zcmt/Zcmp table jumps and returns classify OTHER (CFG-corrupting)

Four real transfers, all `DISAS_NORETURN`, all currently non-terminating:

| Mnemonic | binutils | QEMU | Should be |
|---|---|---|---|
| `cm.jt` | `riscv-opc.c:2343` (flags `0`) | `trans_cm_jalt` `trans_rvzce.c.inc:302-340`, `index < 32` | UNCOND + indirect |
| `cm.jalt` | `riscv-opc.c:2344` (flags `0`) | same, `index >= 32`, links `ra` (`:316-320`) | CALL + indirect |
| `cm.popret` | `riscv-opc.c:2337` | `gen_pop` `trans_rvzce.c.inc:205-217` | RET |
| `cm.popretz` | `riscv-opc.c:2338` | same, `ret_val=true` | RET |

All four resolve their target through `lookup_and_goto_ptr`, so none has a
static target — they must be `indirect` as well. `cm.push`/`cm.pop` are **not**
transfers (`trans_cm_push`/`trans_cm_pop`, `ret=false`) and must not be caught by
a lazy `^cm\.` pattern.

Impact scales with how much RV32 embedded code enables Zcmp/Zcmt — where it is
enabled, `cm.popret` replaces the epilogue of nearly every function, so nearly
every function-end block boundary disappears.

### 3.4 F4 — ARM conditional returns/jumps vanish from the branch denominator

Executed:

```
moveq pc, r3          -> uncond   (should be COND)
ldreq pc, [r3]        -> ret      (should be COND)
popeq {r4, pc}        -> ret      (should be COND)
ldmiaeq sp!, {r4,pc}  -> ret      (should be COND)
bxeq lr               -> ret      (should be COND)
```

These still terminate their block, so the block map is fine — but only `COND`
produces a `BranchPoint` (`cfg.py:1199-1212`), so QEMU's second exit
(`translate.c:6821-6828`) is never counted. `moveq pc, rN` is a real, common
if-converted branch that today reports as an always-taken jump.

This is the same problem the profile already solved for `bl<cc>`
(`cfg.py:315-326`, classified COND precisely so it is both a terminator and a
branch point). The fix is the same shape.

### 3.5 Instructions tcgcov treats as transfers that QEMU cannot execute

These are **not** false positives in the CFG sense — binutils is authoritative
for what a disassembler prints, and each is a real ISA branch — but under this
QEMU they can never produce an edge, so any branch point built on them will be
permanently unevaluated:

| Family | tcgcov | QEMU |
|---|---|---|
| SPARC `cb`/`cb0`…`cb013` + sparclet `cbe`…`cbnefr` | UNCOND / COND | `trans_NCP` `translate.c:2748-2760` — `TT_NCP_INSN` trap (32-bit) or illegal (64-bit); CBccc is never decoded as a branch |
| SPARC `cwb*` / `cxb*` (M7 CBcond) | COND | no decode pattern anywhere in `target/sparc/`; falls to `gen_exception(TT_ILL_INSN)` `translate.c:5750` |
| AArch64 CMPBR `cb<cc>`/`cbb<cc>`/`cbh<cc>` | COND | not in `a64.decode`, not in `translate-a64.c` |
| MIPS `bc2t`/`bc2f`/`bc2eqz`/`bc2nez` | COND | opcodes declared `translate.c:966-968`, never dispatched — `OPC_CP2` repurposed for Loongson LMMI `:14862-14866` |
| x86 `jmpabs` | UNCOND | no APX/REX2 decode in `target/i386/` at all |
| PowerPC POWER-only spellings | OTHER | never decoded |
| ARM `bxaut` (`arm-dis.c:4397`) | OTHER | not implemented in `target/arm/tcg/` |

The PowerPC row is worth a note: `cfg.py:568-571` says the unmodelled POWER
spellings are `br/brl/bcr/bcrl/bcc/bccl`. Sweeping every `b*` mnemonic in
`ppc-opc.c` through `classify()` puts the real count at **~30**, not 6 — the
`b<cc>r` family (`beqr`, `bltr`, `bnsr`, … `ppc-opc.c:6791`+), the `bbt`/`bbf`
branch-on-bit family (`:6620`), and the `bdn` family (`:6378`). All are
`PWRCOM`-gated, i.e. printed only under `-Mpwr`/`-Mcom`, so the practical impact
is nil — but the note undercounts.

### 3.6 Two claimed findings that are wrong, and why the method matters

The QEMU-side survey reported that PowerPC `bctr` and `btar` are misclassified
COND because the `cond` pattern's `bc` / `b[tf]` alternatives partially match
them. **Refuted by execution:**

```
cond regex: ^(b(dnz|dz)[tf]?|b(eq|ne|lt|gt|le|ge|so|ns|un|nu|nl|ng)|b[tf]|bc)(lr|ctr|tar)?l?a?[+-]?\b

bctr   -> cond_match=None  -> uncond   (indirect)
btar   -> cond_match=None  -> uncond   (indirect)
bctrl  -> cond_match=None  -> call     (indirect)
btarl  -> cond_match=None  -> call     (indirect)
```

The trailing `\b` is what kills the partial match: after consuming `bc`, the
position sits between `c` and `t`, both word characters, so there is no word
boundary and the whole alternative fails. Reading the regex without the `\b` in
mind produces a plausible, confident, wrong answer. Every claim in this document
about tcgcov's behaviour was therefore obtained by running the shipped profile,
not by reading it.

### 3.7 F5, F6 — low-impact real differences

**F5 (MIPS, low):** `bc1any2f`, `bc1any2t`, `bc1any4f`, `bc1any4t` (MIPS-3D ASE
conditional FP branches) classify OTHER. QEMU handles them in
`gen_compute_branch1` (`translate.c:8695-8794`); binutils flags them `CBD` at
`mips-opc.c:725-728`. MIPS-3D is rare enough that this is a completeness item,
not a correctness emergency — but they are block-merging when they do appear.

**F6 (PowerPC, cosmetic):** the raw generic forms are genuinely conditional in
QEMU (`gen_bcond` `translate.c:3752-3816`) but land in the wrong bucket:

```
bclr   -> ret     bclrl  -> ret      (ret pattern ^(blr|bclr)l?[+-]?\b wins first)
bcctrl -> call    bctarl -> call
bcctr  -> cond    bctar  -> cond     (correct)
```

**Coverage impact is exactly zero.** All four are `indirect`, so even a correct
COND classification would produce a `BranchPoint` with `taken is None`, which is
EXCLUDED from branch coverage (`cfg.py:1104-1111`). The only visible difference
is the "N indirect/unknown target -> EXCLUDED" count in the summary line
(`branches.py:262-266`). These raw spellings are also only printed when the
BO/BI pair matches no extended alias.

---

## 4. What QEMU knows that tcgcov cannot get from text at all

The plugin records `src = last instruction vaddr of the source TB`,
`dst = start vaddr of the destination TB` (`plugin/tcgcov.c:186-194`, `Edge` at
`:232-244`). That is TB-to-TB adjacency and nothing else.

### 4.1 Why a TB ended

`translator_loop` stops for two reasons (`accel/tcg/translator.c:191-201`):
the target set `is_jmp != DISAS_NEXT`, **or** the op buffer filled / the
instruction budget ran out (`DISAS_TOO_MANY`). The budget is
`cflags & CF_COUNT_MASK`, defaulting to `TCG_MAX_INSNS = 512`
(`include/tcg/tcg.h:131`, `accel/tcg/translate-all.c:281-285`), and is forced to
**1** by gdb single-step, `-accel tcg,one-insn-per-tb=on`
(`accel/tcg/cpu-exec-common.c:49-52`) and by any breakpoint on the current page
(`accel/tcg/cpu-exec.c:353-355`).

Several targets additionally clamp the budget so a TB can never cross a page:

```
target/microblaze/translate.c:1621-1622
target/sparc/translate.c:5711-5712
target/arm/tcg/translate.c:6381-6382
(also alpha, hppa, openrisc, sh4, loongarch)
```

x86, MIPS, PowerPC and RISC-V instead set `DISAS_TOO_MANY` on the page cross
inside `translate_insn`. Either way, a `DISAS_TOO_MANY` TB emits a direct link to
the **next sequential address** (x86: `gen_jmp_rel_csize(dc, 0, 0)` at
`translate.c:3899-3902`; MicroBlaze: `gen_goto_tb(dc, 0, dc->base.pc_next)` at
`translate.c:1721-1722`).

So the plugin will observe edges out of ordinary non-branch instructions, and
cannot tell them from anything else. **Add to that the side-effect TB-enders
which are extremely common on x86** — `sti`, `mov %rax,%cr3`, `wrmsr`, `popf`,
`mov`/`pop` to `%ss`, `xsetbv`, `invlpg`, `pause`, `mwait` — and MicroBlaze's
`mbar` (`translate.c:1264`), `mts` (`:1420`) and `msrset`/`msrclr` (`:1351`).
Every one of these ends a TB at a point that is **not** a basic-block boundary.

tcgcov handles this correctly by construction, and it is worth stating why so
nobody "fixes" it:

* `build_blocks` only splits at branch targets and after `TERMINATORS`
  (`cfg.py:1142-1185`), so it never learns these pseudo-boundaries exist;
* `branch_for_source` rejects an edge whose source lies **before** the block's
  conditional terminator, or whose block has no conditional terminator at all
  (`cfg.py:1228-1245`);
* `match_edges` buckets those as `ignored` rather than inventing an outcome
  (`cfg.py:1283-1312`).

`sti` and friends are therefore **correctly** OTHER, and turning them into
terminators to "match QEMU" would be an active regression.

### 4.2 Delay slots can be split across TBs

This is the non-obvious one. QEMU carries the pending-branch state in `tb_flags`,
so a TB can *begin* in a delay slot:

```c
/* target/microblaze/translate.c:1618 */
dc->jmp_cond = dc->tb_flags & D_FLAG ? TCG_COND_ALWAYS : TCG_COND_NEVER;
```

(`D_FLAG` is defined at `target/microblaze/cpu.h:267-281`; SPARC does the
equivalent with `npc == JUMP_PC`, `translate.c:169-171`, `:5724-5728`; MIPS with
`MIPS_HFLAG_BMASK`.) When the page clamp or the instruction budget lands between
a branch and its delay slot, the branch and the slot end up in **different TBs**.

Traced through tcgcov's matcher, the outcome is benign but visible:

1. Edge 1 is `src = the branch itself`, `dst = the delay-slot address`. The
   source is inside the branch's block and at-or-after `bp.addr`, so
   `branch_for_source` matches it — but the destination is neither `taken` nor
   `fallthrough` (it is `branch+4`, while the fall-through is `branch+8`). It is
   counted as **`unresolved`**.
2. Edge 2 is `src = the delay slot`, `dst = the real target`. The continuation TB
   emits **both** exits — `gen_goto_tb(dc, 1, dc->base.pc_next)` for the
   not-taken side (`translate.c:1754`) and `gen_goto_tb(dc, 0, dc->jmp_dest)` for
   the taken side (`:1757`) — so this edge resolves correctly.

**Net effect: the taken/not-taken counts stay correct; the `unresolved` figure in
the summary line (`branches.py:267-270`) is inflated.** A non-zero `unresolved`
count on MicroBlaze/SPARC/MIPS is therefore not automatically a bug — this is one
benign source of it.

### 4.3 The true target of a computed branch, and of a trap

QEMU resolves every indirect transfer at runtime through
`tcg_gen_lookup_and_goto_ptr`, so it knows the destination on every single
execution. tcgcov cannot recover it from text and correctly marks such branches
`indirect` → EXCLUDED (`cfg.py:1104-1111`). The affected population is
substantial: AArch64 `br`/`blr` jump tables, ARM `tbb`/`tbh`, SPARC `jmpl`,
PowerPC `bcctr`/`bclr` (including every conditional return `beqlr`), MIPS
`jr`/`jic`, RISC-V `jalr`.

**This is a recoverable limitation, not a fundamental one.** The observed edge's
`dst` *is* the real target. A future pass could learn indirect targets from the
edge data itself and report per-destination coverage, which is information the
static model can never have.

The same applies to the trap/exception family, which is OTHER on every arch:

| Arch | Instructions | QEMU |
|---|---|---|
| MicroBlaze | `brki` in user mode | `EXCP_SYSCALL`/`EXCP_DEBUG`, `translate.c:1194-1197` |
| RISC-V | `ecall` `ebreak` `mret` `sret` `mnret` | `trans_privileged.c.inc:27-140` |
| ARM | `svc` `hvc` `smc` `eret` `rfe*` `wfi` `wfe` | `translate.c:3526-3543`, `:5789-5813`, `DISAS_EXIT`/`DISAS_SWI`/… |
| AArch64 | `svc` `hvc` `smc` `brk` `hlt` | `translate-a64.c:3151-3209`, `DISAS_NORETURN` |
| MIPS | `syscall` `break` `eret` `eretnc` `deret` `wait` | `translate.c:8635-8683`, `:13271-13275` |
| PowerPC | `sc` `scv` `rfi` `rfid` `rfscv` `hrfid` `rfebb` `tw`/`td` (TO==31) | `translate.c:3937-4031`, `branch-impl.c.inc:23` |
| SPARC | `Tcc` (`ta`…`tvs`) `done` `retry` | `translate.c:2775-2826`, `:4364-4381` |
| x86 | `int` `int3` `int1` `syscall` `sysenter` `ud2` `hlt` | `emit.c.inc:2260-2281`, `:4150-4179`, `:2045` |

Leaving these OTHER is defensible and, for the overwhelmingly common case,
correct: the handler returns to the instruction *after* the trap, so the
"merged" block is exactly the right straight-line flow, the outgoing edge lands
outside the disassembled range, and the incoming edge is ignored because the
source block has no conditional terminator. The residual risk is confined to
traps that do not resume at the next instruction — and note the SPARC `Tcc`
family is *conditional* (`do_tcc:2814-2823`), so a conditional trap is a genuine
two-way branch that is entirely absent from the model. `sparc-opc.c:1353-1379`
generates the branch and the trap mnemonic from one `cond()` macro, so the trap
spellings are `ta`, `tn`, `te`, `tne`, `tg`, `tle`, `tge`, `tl`, `tgu`, `tleu`,
`tcc`, `tcs`, `tpos`, `tneg`, `tvc`, `tvs` (+ aliases).

### 4.4 Annulled and nullified delay slots

QEMU models the skip; tcgcov cannot express it.

* MIPS "likely" branches nullify the delay slot when not taken —
  `decode_opc` `translate.c:15018-15026` emits `tcg_gen_brcondi_tl` + a
  `gen_goto_tb` straight past the slot, at the *start* of decoding the slot.
* SPARC `,a` annuls — `advance_jump_cond:2624`, `:2628`. This applies even to
  `bn,a`, which never branches but still eats its delay slot.

Neither changes the fall-through **address**, so branch coverage is unaffected;
line coverage will report the delay-slot instruction as executed-with-the-block
when it was in fact skipped. `cfg.py:585-590` already documents the SPARC half.

---

## 5. Actionable list

Ordered by impact. **A QEMU-derived claim is not yet a regex** — QEMU proves
*that* the instruction transfers, binutils proves *what string* tcgcov will see.
Each item records whether the spelling was confirmed.

**A1 — ARM: give `unconditional` a condition-suffix group.** Highest impact:
`bx<cc>`/`bxj<cc>`/`tbb<cc>`/`tbh<cc>` currently do not terminate a block, and
`tbb<cc>` additionally splices jump-table bytes into the block map.
Justification: `target/arm/tcg/translate.c:3441`, `:3450-3467`, `:5708-5734`
(the transfers), `:6104-6106` + `:6821-6828` (the second exit).
Spelling **CONFIRMED**: `arm-dis.c:3398`, `:3808`, `:4563`, `:4565`, with `%c`
gluing at `:8201-8204` and `AL` suppressed at `:7949-7951`.
Prefer classifying the conditional spellings **COND** rather than UNCOND — that
gives both properties, exactly as `bl<cc>` already does (`cfg.py:315-326`).
Diagnostic to add to the test suite: `is_indirect(t)` must never be true while
`classify(t) == OTHER`.

**A2 — ARM: model ALU writes to PC.** Justification:
`target/arm/tcg/translate.c:2422-2450` (`store_reg_kind` dispatcher) with
per-opcode selection at `:2604-2673`; `STREG_EXC_RET` → `gen_exception_return`
`:1694`. Spelling **CONFIRMED** from the A32 data-processing rows
(`arm-dis.c:3914`, `:3921`, `:3924-3928`). Suggested shape:
`^(add|adc|and|bic|eor|mvn|orn|orr|rsb|rsc|sbc|sub)s?<CC>?(\.[nw])?\s+pc\s*,` —
route `subs pc, lr, #N` / `movs pc, lr` to RET (exception return) and the rest to
UNCOND + `indirect`. **Not confirmed:** the exact operand spacing in real output;
generate a sample disassembly before finalising the pattern.

**A3 — RISC-V: add the Zcmt/Zcmp transfers.** `cm.jt` → UNCOND + indirect,
`cm.jalt` → CALL + indirect, `cm.popret`/`cm.popretz` → RET. Justification:
`target/riscv/insn_trans/trans_rvzce.c.inc:302-340` and `:205-217`; decode at
`target/riscv/insn16.decode:200-201`, `:205`. Spelling **CONFIRMED**:
`riscv-opc.c:2337`, `:2338`, `:2343`, `:2344`, all with a flags field of `0`
(really disassembled, not macro or alias). Guard the pattern so `cm.push` and
`cm.pop` are excluded — they are not transfers.

**A4 — ARM: promote conditional return/jump idioms to COND.** `mov<cc> pc,`,
`ldr<cc> pc,`, `ldm<cc>`/`pop<cc> {…pc}`, `bx<cc> lr`. Justification:
`target/arm/tcg/translate.c:6821-6828`. Spelling **CONFIRMED** (same `%c`
mechanics as A1). Denominator-only fix; no CFG risk. Same precedent as
`bl<cc>`.

**A5 — MIPS: add `bc1any2f|bc1any2t|bc1any4f|bc1any4t` to `conditional`.**
Justification: `target/mips/tcg/translate.c:8695-8794`. Spelling **CONFIRMED**:
`mips-opc.c:725-728`, flagged `CBD` — so they have a delay slot, which the
existing `^(?!\w+c\b)\w+` rule already gets right for all four spellings.

**A6 — PowerPC: split raw `bclr`/`bclrl` out of the `ret` pattern.** They are
conditional (`target/ppc/translate.c:3752-3816`). Coverage impact is **zero**
(all indirect → excluded either way); do it only for report accuracy, and only
if the `ret` pattern can be narrowed without breaking `blr`/`blrl`.

**A7 — ARM: upgrade the `le <label>` note.** `docs/ARCHITECTURES.md` currently
calls the LR-less `le` spelling "an informed guess" with no opcode-table
citation. It has one: `arm-dis.c:4409-4410`, `{…, 0xf02fc001, 0xfffff001,
"le\t%P"}`. **CONFIRMED** — the note can be promoted to verified.

**A8 — ARM: two completeness items with no QEMU justification.** `bxaut`
(`arm-dis.c:4397`, an Armv8.1-M PACBTI register-indirect branch) classifies
OTHER, and the branch-future note omits `bflx` (`arm-dis.c:4431`). QEMU
implements **neither** — a grep of `target/arm/tcg/` for `bxaut` is empty and
`trans_BF` is a NOP (`translate.c:5408-5426`) — so these rest on binutils alone.
Lowest priority; listed so the gap is on the record.

**A9 — PowerPC: correct the POWER-spelling note.** `cfg.py:568-571` names 6
unmodelled POWER mnemonics; the sweep found ~30 (`b<cc>r`, `bbt`/`bbf`, `bdn`
families — `ppc-opc.c:6378`, `:6620`, `:6791`). All `PWRCOM`-gated, so no code
change is warranted; the note is what needs fixing.

### Could not determine

**U1 — whether SPARC v9 `return` really has no delay slot.** `cfg.py:654`
excludes it. binutils agrees by omission — `sparc-opc.c:866-871` carries no
`F_DELAYED`, while `rett` at `:811-817` does. **QEMU does not corroborate**:
`do_return` (`translate.c:4331-4342`) uses the same `DYNAMIC_PC_LOOKUP` mechanics
as `do_rett` (`:4313-4327`) and `do_jmpl` (`:4292-4309`), and nothing in
`target/sparc/` treats `RETURN`'s successor differently. The two authorities
differ in emphasis rather than contradicting; resolving it needs the SPARC v9
manual, which was not consulted.

**U2 — whether any disassembler in use prints AArch64's no-dot condition
aliases.** GNU objdump does not: the disassembled row is `"b.c"` (`F_COND`,
`aarch64-tbl.h:4435`) and `beq`/`bne`/… are `F_ALIAS | F_PSEUDO` at `:5251-5266`.
llvm-objdump was not checked. If one does print them, every AArch64 conditional
branch silently becomes OTHER — verified: `classify("beq 0x10") == "other"`.
Cheap insurance would be to accept both spellings.

**U3 — microMIPS / MIPS16e register jumps.** QEMU funnels them through
`gen_compute_branch` (`micromips_translate.c.inc:789`, `:796`, `:805`, `:840`,
`:891`, `:932`, `:1193`), so they are real transfers, but the printed spellings
were not checked against `micromips-opc.c`. `cfg.py:525-527` already declares
them unmodelled; that remains accurate and unquantified.

**U4 — exact ARM ALU-writes-PC operand text.** See A2. No sample disassembly was
generated, so the proposed regex is unvalidated against real output.
