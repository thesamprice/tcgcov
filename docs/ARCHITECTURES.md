# Bringing tcgcov up on a new architecture

This is a working reference for someone pointing tcgcov at a processor it has
not been used on. Every trap in the porting checklist (§4) and the toolchain
section (§5) is a bug that was found in this codebase and fixed — the commit
messages `63fbeaf` and `9fa44c1`, and the comment blocks they left behind in
`tcgcov/cfg.py`, are the primary sources. They are written here as "this bit
us, here is how to tell if it bites you".

Where the code does not answer a question, this document says so rather than
guessing. Claims are cited as `file:line` against the tree they were checked
in.

---

## 1. What is and is not architecture-dependent

**Line coverage is architecture-independent.** It needs two things from the
target toolchain and nothing else:

* `<prefix>objdump -d`, to enumerate every instruction address in the
  executable sections (`tcgcov/coverable.py:40-53`), parsed by the single
  shared line matcher `cfg.match_insn_line` (`tcgcov/cfg.py:694-710`);
* `<prefix>addr2line`, to map those addresses and the executed addresses onto
  `(file, line, function)`.

No mnemonic is ever interpreted. If binutils can disassemble your ELF and
QEMU can run it, line coverage works. The failure mode is loud, not silent:
if the disassembly parses to zero instruction addresses, `coverable` refuses to
write an inventory and exits non-zero (`tcgcov/coverable.py:85-100`), because
an empty denominator makes every downstream report read 100%.

**Branch coverage needs a per-ISA profile.** Deciding which mnemonic is a
conditional branch, which is a call or a return, where each branch's two
successors are, and whether a delay slot sits between the branch and its
fall-through, is ISA-specific. That knowledge lives in one `ArchProfile`
object per ISA (`tcgcov/cfg.py:119-187`), which is a set of `re.match`,
case-insensitive regexes applied to the normalized text
`"<mnemonic> <operands>"`.

**An architecture with no profile is refused, not guessed.** `get_profile()`
returns `UNSUPPORTED_PROFILE` (`tcgcov/cfg.py:210-213`), and
`tcgcov branches` exits **2** with (`tcgcov/branches.py:203-213`):

```
error: branch coverage unsupported for this arch (<arch or 'unknown'>): no branch
mnemonics are known for it, and guessing would produce wrong data.
       known arches: aarch64, arm, microblaze, micromips, mips, mips16, powerpc, riscv, sparc, thumb, x86, x86_64
       add your own with --arch-profile FILE (see tcgcov/cfg.py load_profile_file for the schema)
```

Exit 2 specifically means "no profile". The driver treats it as a benign,
expected gap and carries on with line coverage only, printing
`note: no branch profile for arch '<ARCH>'; line coverage only`
(`tcgcov-report.sh:172-181`); any *other* non-zero exit is a real failure and
aborts the run, because silently dropping branch data looks exactly like a
coverage regression.

---

## 2. Status of the eight shipped profiles

Confidence is **not** uniform. Three kinds of evidence exist in the tree, and
most profiles have only the first:

| Evidence | What it proves |
|---|---|
| classification table in `tests/test_arch_profiles.py` | the regexes classify the mnemonics *we listed*, taken from the binutils opcode tables |
| golden fixture in `tests/data/` | real disassembler output for that ISA parses to the expected instruction inventory |
| end-to-end run under QEMU | edges recorded by the plugin actually resolve against the reconstructed CFG, on a program whose outcomes are known |

| Profile | `cfg.py` lines | Table rows | Opcode-table citations | Real tool output | Ran under QEMU |
|---|---|---|---|---|---|
| **microblaze** | 239-266 | 50 (24 cond, 8 non-branch guards) | **exhaustive** — `microblaze-opc.h:195-241`, every immediate form's `INST_PC_OFFSET`/`INST_NO_OFFSET` flag and every `DELAY_SLOT` flag (`:223-241` cited inline) | `tests/data/gnu-microblaze.txt` — genuine GNU `objdump -d`, 111 insns, 4 conditional branches with **verified targets and fall-throughs** (`tests/test_golden_disasm.py:93-113`) | **yes** — `qemu-system-microblazeel`, `petalogix-s3adsp1800`, `examples/branch-coverage/README.md:5-6` |
| **arm** (A32/T32) | 335-366 | 46 | partial — `arm-dis.c:4410-4422` (low-overhead loops), `:4425-4433` (branch-future), `:4563-4565` (`tbb`/`tbh`), `:4919` (condition suffixes) | `tests/data/llvm-armv7.txt` — 5 insns, **0 conditional branches**; proves layout parsing only | no |
| **aarch64** | 371-404 | 32 | the register-indirect family only — `aarch64-tbl.h:4413-4430`, `aarch64-opc.c:4096-4099`, `:5201-5211`; the conditional-branch rows in the test table carry none | `tests/data/llvm-aarch64.txt` — 4 insns, **0 conditional branches** | no |
| **x86 / x86_64** | 406-432 | 37 | one — `i386-dis.c:14640` (APX `jmpabs`); the 16 Jcc spellings are asserted but not line-cited | `tests/data/llvm-x86_64.txt` — 5 insns, **0 conditional branches**; does prove variable-length sizing from address deltas (`test_golden_disasm.py:115-120`) | no |
| **mips** (+ microMIPS) | 533-693 | 89 (12 non-branch guards) | good — `mips-opc.c:223-228` (CBD/UBD/CBL/NODS), plus `:718-723`, `:729`, `:734`, `:2146-2148`, `:3366`, `:3371`; microMIPS per-row from `micromips-opc.c:322-453`, `:732-780`, with the `16`-suffixed spellings cited to LLVM's `MicroMipsInstrInfo.td` / `MicroMips32r6InstrInfo.td` | **none** | no |
| **micromips** | 694-734 | shares the `mips` table | same as `mips` — identical pattern set, `insn_size=2` | **none** | no |
| **mips16** | 735-783 | 32 (11 non-branch guards) | **good** — per-row across `mips16-opc.c:237-263` (branches, no delay), `:325-341` (jumps and compact jumps), `:69` (`R` = `$31`), `:447-449` (non-transfers) | **none** | no |
| **sparc** | 524-544 | 54 | **good** — per-row citations across `sparc-opc.c:1361-1706` and `:1953-1967` | **none** | no |
| **powerpc** | 480-490 | 29 | **none inline**; `ppc-opc.c` named only in the test-file header | **none** | no |
| **riscv** | 273-372 | 46 (6 non-branch guards) | the indirect/alias analysis and the Zc extensions — `riscv-opc.c:484-507`, `:2309-2344` (Zcb/Zcmop/Zcmp/Zcmt, incl. `:404-419` match functions), `riscv-dis.c:85`, `:96-97`, `:565-566`, `:746-750`, `:1074-1095`, `:1111-1127`; the conditional-branch rows carry none | `tests/data/llvm-riscv64.txt` — 3 insns, **0 conditional branches** | no |

Read that table as: **MicroBlaze is the only profile that has been shown to
produce a correct branch report on a real program.** Every other profile is a
regex set validated against a hand-written table of mnemonics, with — at best —
a four-instruction fixture proving the *parser* copes with that disassembler's
column layout. None of the non-MicroBlaze fixtures contains a single
conditional branch.

The citation and row-count columns are the least durable part of this table:
profiles are being back-filled with opcode-table references and extra table
rows as they are audited. `cfg.py` and `tests/test_arch_profiles.py` are
authoritative; if a profile there carries more citations or more rows than this
table credits it with, this table is out of date, not the code. What does not
change quickly is the last two columns.

Two more scope notes:

* Nine profile objects are registered but eight ISA families are tested: `x86`
  and `x86_64` are the same pattern set registered twice (`cfg.py:431-432`).
  Two more MIPS-family profiles have since been added — see below.
* The CI end-to-end job (`ci/integration.sh`) compiles real C and runs real
  `objdump`/`addr2line`, but it synthesizes the `.cov` artifact and asserts a
  **line** number only — it never calls `tcgcov branches` and never runs QEMU.
  Branch coverage has no end-to-end CI on any architecture.

### 2.1 The two compressed MIPS profiles

microMIPS and MIPS16 are separate instruction sets that share the MIPS name,
have 16-bit encodings, and have different delay-slot rules from MIPS32. They
are handled differently from each other, on evidence:

| ISA | Handling | Why |
|---|---|---|
| **microMIPS** | **folded into `mips`** (a `micromips` profile exists, sharing the same pattern set, and differs only in `insn_size=2`) | It spells every transfer it shares with MIPS32 identically *and* flags it identically: `b`/`beqz`/`bnez`/`jr`/`jalr`/`j`/`jal` are UBD or CBD (`micromips-opc.c:322,386,444,732,749,756,775`), the compact `bc`/`beqzc`/`bnezc`/`jrc` are NODS (`:327,395,453,752`). No statement in the `mips` profile is wrong for microMIPS. Decisive: objdump selects microMIPS **per symbol** from `st_other` (`is_compressed_mode_p`, `mips-dis.c:2655-2679`), so a single disassembly interleaves microMIPS and MIPS32 functions and **one** profile must classify both. |
| **MIPS16** | **its own `mips16` profile** | It *contradicts* MIPS32 on identical text. `b`/`beqz`/`bnez`/`bteqz`/`btnez` (`mips16-opc.c:237-263`) carry only `UBR`/`CBR` in `pinfo2` and **no** `INSN_COND_BRANCH_DELAY` — there is no `CBD` macro in that file at all. Under the `mips` profile `beqz a0, 400` delays, so `_fallthrough` skips one extra instruction and the not-taken edge can never match: a permanently half-covered branch, reported with exit 0. Same family, different semantics, same text — exactly the `thumb` argument. |

**Neither is reachable from `detect_arch`, and that is a binutils fact, not an
omission.** objdump's "file format" line is the BFD *target vector* name
(`binutils/objdump.c:5809-5811`), i.e. `elf32-tradlittlemips` for a microMIPS
binary and a MIPS32 one alike. The machs exist — `bfd_mach_mips16`
(`bfd/archures.c:174`, printable name `"mips:16"` at `bfd/cpu-mips.c:142`) and
`bfd_mach_mips_micromips` (`bfd/archures.c:199`, `"mips:micromips"` at
`bfd/cpu-mips.c:168`) — but `_bfd_elf_mips_mach` (`bfd/elfxx-mips.c:7044-7160`)
never returns either from an ELF's `e_flags`; only GDB ever sets them
(`gdb/mips-tdep.c:7027-7030`). So:

* a microMIPS/MIPS16 ELF detects as **`mips`**, which is the right default —
  the ELF may interleave compressed and MIPS32 functions, and `mips` classifies
  the transfers of all three;
* to get the 2-byte section-end size fallback, pass **`--arch micromips`** (or
  `mips:micromips`, `micromips32r2`, `umips`);
* for MIPS16 code, pass **`--arch mips16`** (or `mips:16`, `mips16e`,
  `mips16e2`) — this one changes classification, not just sizing, so it is the
  only way to get MIPS16 branch fall-throughs right.

`micromips`/`mips16` are listed **before** `mips` in `ARCH_ALIASES` because
those are ordered substring tests and every one of those names contains
`mips` — the same ordering trap `thumb` has against `arm`.

---

## 3. Known gaps and unmodellable constructs

Taken from the `notes=` fields and the comment blocks, per arch. Anything not
listed here is not a claim of completeness — it is the absence of a note.

### SPARC

* **`bn` / `fbn` / `cbn` (branch never) are classified `OTHER`**
  (`cfg.py:498-508`, `:542-544`). binutils files `bn` under `F_CONDBR` and
  `fbn`/`cbn` under `F_UNBR`, and *neither* is usable: calling them
  unconditional splits a block at a target that is never reached, calling them
  conditional creates a permanently half-covered branch point. They always fall
  through, so they are neither a terminator nor a branch point.
* **`bn,a` annuls its delay slot** — the following instruction is skipped. This
  is a control-flow effect the CFG has **no way to express**: the model will
  place that instruction in the block and treat it as executed-with-the-block.
  It affects which instruction executes, not the branch denominator
  (`cfg.py:505-508`).
* Bare `cb`/`cba` are branch-**ALWAYS** (`sparc-opc.c:1688-1689`), not
  conditional; the 14 real conditional coprocessor spellings are enumerated
  explicitly (`cfg.py:522-523`).
* `return` and the CBcond family (`cwb*`/`cxb*`) do **not** delay; everything
  else does (`cfg.py:540`).

### ARM

* **Branch-future (`bf` / `bfl` / `bfx` / `bfcsel`) is not modelled**
  (`arm-dis.c:4425-4433`, stated in the profile note at `cfg.py:365-366`). If
  your Armv8.1-M code uses it, those transfers are invisible to the block map.
* **`le <label>` — the LR-less form — is classified `COND`, but that specific
  spelling is not confirmed from an opcode table.** The profile cites
  `arm-dis.c:4410-4418` for the `le`/`letp`/`wls`/`wlstp` family as a whole
  (`cfg.py:328-333`); the LR-less row exists in the table
  (`tests/test_arch_profiles.py:146`) with no separate citation. Treat it as an
  informed guess.
* **`tbb`/`tbh` are followed by inline jump-table bytes that objdump
  disassembles as instructions.** They are therefore classified `UNCOND` — not
  because they are unconditional in any interesting sense, but because they
  MUST terminate their block; a `tbb` that does not end its block splices table
  data into the block map (`cfg.py:339-344`).
* **ARM has no return instruction.** The `ret` pattern is a set of idioms —
  `bx lr`, `pop {…, pc}`, `ldm …{…, pc}`, `mov pc, lr`, `ldr pc, …`
  (`cfg.py:349-354`). A missed idiom merges two blocks; function symbols are
  also block leaders (`cfg.py:1131-1142`), which limits the damage.
* `dls`/`dlstp` only initialize LR and are deliberately `OTHER`
  (`cfg.py:332-333`).

### PowerPC

* **Conditional returns (`beqlr`, `bdnzlr`, …) are branch points with an
  implicit LR target** — no static target exists, so they are excluded from
  branch coverage rather than reported as uncovered (`cfg.py:488-490`).
* `blr`/`bctr` take no operand; they are correctly reported as having no
  target.
* The CR field prints **first** (`ble- cr1,90 <apfour+0x14>`), which is why
  target parsing takes the **last** hex operand (`cfg.py:473-478`,
  `:786-788`).

### MicroBlaze

* `brk`/`brki` (break/trap) are grouped with calls: they transfer control and
  end a translation block, but never delay (`cfg.py:261-263`).
* The register-target forms (`br`, `brd`, `bra`, `brad`, `brld`, `brald`, and
  every register-operand conditional) are indirect and excluded.
* A branch whose immediate is preceded by an `imm` prefix (upper 16 bits
  supplied separately) is **refused outright** rather than resolved from the
  printed low half (`cfg.py:839-845`).

### MIPS (and microMIPS / MIPS16)

* The `likely` (`*l`) forms nullify the delay slot when not taken. That does
  not change the fall-through **address**, so the model is unaffected
  (`cfg.py:469-471`) — but it does mean the delay-slot instruction did not
  execute on that path while the block map says it belongs to the block.
* r6 compact branches (mnemonics ending in `c`) have no delay slot, encoded as
  a negative lookahead. The microMIPS compact forms whose `c` is followed by
  a `16` width suffix (`bc16`, `beqzc16`, `bnezc16`, `jrc16`) and the
  `jraddiusp`/`jrcaddiusp` pair are invisible to that lookahead and are named
  explicitly beside it.
* **The `s`-suffixed microMIPS forms still delay.** `jrs`, `jalrs`, `jals`,
  `bals`, `bgezals`, `bltzals` carry `BD16` (`micromips-opc.c:216`), which
  constrains the delay slot to a *2-byte* instruction; it does not remove it.
  The distinction costs nothing here because `_fallthrough` takes the address
  of the instruction after the slot **from the disassembly** rather than
  computing it from a size.
* **`b16` is unconditional**, despite sitting next to `beqz16`/`bnez16` and
  reading like one of them: `micromips-opc.c:322` is `UBD`, not `CBD`, and LLVM
  derives it from `UncondBranchMM16` (`MicroMipsInstrInfo.td:673`).
* **`jraddiusp`/`jrcaddiusp` are returns whose operand is a stack adjustment.**
  They jump to `$ra` *and* add the printed number to `$sp`
  (`micromips-opc.c:735`, `NODS|UBR` with `RD_31|WR_sp|RD_sp`;
  `MicroMips32r6InstrInfo.td:493-496`), so they are marked indirect — reading
  `jraddiusp 16` as a branch to `0x16` is the same failure as
  `jmpl %g1+0x10`.
* **Two spellings per 16-bit form, and only one comes from binutils.** There is
  no `"16"` string anywhere in `micromips-opc.c`: GNU objdump prints the 16-bit
  encodings under the plain names (`b`, `beqz`, `jr`, `jalrs`), distinguished
  only by mask width (`mips_opcode_32bit_p`, `include/opcode/mips.h:511-518`).
  The `b16`/`beqz16`/`bnez16`/`jr16`/`jrc16`/`jalrs16`/`bc16`/`beqzc16`/
  `bnezc16` spellings are **llvm-objdump's**, cited to LLVM's MicroMips `.td`
  files. Both are accepted, exactly as RISC-V accepts llvm's `jalr 0x10(a0)`
  alongside GNU's `jalr 16(a0)`.
* **`jalr16` could not be confirmed as a printed spelling.** LLVM's record is
  `JALR16_MM` but its asm string is plain `"jalr"`
  (`MicroMipsInstrInfo.td:659`), and binutils has no such name either. It is
  accepted anyway because every `jalr*` form is register-target, so the pattern
  cannot swallow a direct branch — but no disassembler is known to emit it.
* **`eret`/`eretnc`/`deret`/`iret` are not modelled as transfers on any MIPS
  profile.** They *are* control transfers but carry only `NODS`
  (`micromips-opc.c:601,718,719,731`) — none of the `UBD`/`CBD`/`UBR`/`CBR`
  bits — so they were left out rather than guessed at. A missed return merges
  two blocks; function symbols are also block leaders, which limits the damage.
* **`NODS` alone cannot identify a compact branch.** `NODS`, `TRAP` and
  `DSP_VOLA` are literally the same bit (`INSN_NO_DELAY_SLOT`,
  `micromips-opc.c:210-211,270`; `mips16-opc.c:189-190`), so `break`, `sdbbp`,
  `syscall`, `restore`, `save`, `lwm`, `swm`, `movep` and much of the DSP ASE
  all carry it. The classification here keys on mnemonics, not on that bit;
  the non-branches are pinned as `OTHER` in the test tables for exactly this
  reason.
* MIPS16 `restore`/`save` (`mips16-opc.c:447-448`) write and read `$31` and
  carry `NODS`, but only move the frame; `entry`/`exit`/`break`/`sdbbp`
  (`:316-321,:260,:449`) are `TRAP` rows; `extend` (`:478`) is the
  32-bit-immediate prefix, not an instruction. None are modelled as transfers.
* MIPS16's `jal`/`j` are ambiguous — `mips16-opc.c:327-328,333-334` give them
  register forms that alias `jalr`/`jr` — so `indirect` splits them on the
  first operand character, the way ARM splits `blx` and SPARC splits `call`.
  objdump in practice prints `jalr`/`jr` for those encodings (the aliases come
  later in the table), so the ambiguous spellings should not appear; they are
  handled anyway.

### RISC-V

* `call`/`tail`/`jump` are `INSN_MACRO` (`riscv-opc.c:503-507`) and are skipped
  outright by the disassembler (`riscv-dis.c:1076-1078`), so GNU objdump never
  prints them; they are recognized only because llvm-objdump and hand-written
  `.s` listings do (`cfg.py:303-308`).
* `jr`/`jalr` print in three shapes, and the offset form is **decimal** in GNU
  objdump (`%d`, `riscv-dis.c:565-566`) but `0x10` in llvm-objdump — the
  spelling that used to parse as a branch target (`cfg.py:281-301`). A textbook
  instance of §4.5: same instruction, two disassemblers, two shapes.
* Compressed forms print under the alias name (`c.jr` prints as `jr`, `c.jr ra`
  as `ret`, `riscv-opc.c:484`), so both spellings are accepted.
* **Zcmt `cm.jt`/`cm.jalt` are table jumps with no static target.** Their
  operand is an index into the jump-vector table based at the JVT CSR
  (`riscv-opc.c:2343-2344`; `match_cm_jt`/`match_cm_jalt` at `:404-419` split
  the shared encoding at index 32), printed as a bare unsigned decimal
  (`riscv-dis.c:746-750`, `"%" PRIu64`) with no `0x`, no `<sym>` and no
  resolved-target comment — the disassembler cannot read JVT. They terminate
  their block and are marked **indirect**, so the index can never be read as an
  address. They are therefore *excluded* from branch coverage rather than
  reported: a `cm.jt`-based switch contributes nothing to the denominator.
* **binutils does not flag the Zcmt/Zcmp transfers at all.** All eight `cm.*`
  rows (`riscv-opc.c:2335-2344`) carry `pinfo == 0` — not `INSN_BRANCH`, not
  `INSN_JSR` — so `riscv-dis.c:1111-1127` never sets `info->insn_type` or
  `info->target` for them. Nothing downstream of objdump identifies these as
  transfers; they are listed in the profile from ISA semantics, not from an
  opcode-table bit. The same is true of `cm.popret`/`cm.popretz`
  (`:2337-2338`), classified `RET` here.
* `cm.push`/`cm.pop` (`riscv-opc.c:2335-2336`) and `cm.mva01s`/`cm.mvsa01`
  (`:2339-2340`) do **not** transfer control and are deliberately `OTHER`;
  `cm.pop` sharing its whole prefix with `cm.popret` is pinned as a
  false-positive guard in the test table.
* No other Zc mnemonic transfers: the Zcmop rows `c.mop.1`…`c.mop.15`
  (`riscv-opc.c:2324-2332`) are hint no-ops, and every Zcb row (`:2309-2322`)
  is a load, store or ALU op — several of which print under non-`c.` aliases
  (`lbu`, `sb`, `not`, `mul`) because those alias rows precede them in the
  table.

### AArch64

* The register-indirect family is enumerated from the `branch_reg` iclass
  (`aarch64-tbl.h:4413-4430`); `ret`/`retaa`/`retab`/`eret*`/`drps` are
  deliberately left out of the `indirect` pattern because they classify RET and
  RET is never target-parsed (`cfg.py:376-399`).
* Per the profile note: the CMPBR (v9.6 `cb*`), compbranch (`cbz`/`cbnz`) and
  testbranch (`tbz`/`tbnz`) families are PC-relative, not register-indirect,
  and the GCS extension (`aarch64-tbl.h:5201-5211`) contains no branches
  (`cfg.py:401-404`).
* **The conditional-branch rows still have no opcode-table citations** — see
  §2. The absence of further notes here is not a statement of completeness.

### Indirect branches, on every arch

An indirect branch (register or memory target) is still classified and still
terminates its block, but `_parse_target` returns `None` for it
(`cfg.py:806-807`), which makes `BranchPoint.indirect` true
(`cfg.py:987-994`). Such branches are **excluded from branch coverage** —
reporting them uncovered would be a lie, since nothing can ever cover them —
and counted separately in the summary line (`branches.py:262-266`).

**Not every profile defines an `indirect` pattern.** The ones that do not rely
on their register operands not *looking* like addresses, which happens to hold
for the spellings in the test tables but is not enforced. The set is being
filled in profile by profile, so check rather than assume:

```sh
python3 -c 'from tcgcov import cfg; print(cfg.get_profile("sparc")._indirect)'
```

A `None` there means every operand of every transfer on that arch will be read
by `_parse_target` (§4.4).

---

## 4. The porting checklist

Work through this in order. Each item is a bug this project shipped.

### 4.1 Absolute vs PC-relative branch operands

**The bug.** The MicroBlaze profile marked the whole ISA `pcrel_operand=True`.
But `microblaze-opc.h` flags each immediate branch individually: `bri`/`brid`/
`brlid` are `INST_PC_OFFSET` (:223-225) while `brai`/`braid`/`bralid`/`brki`
are `INST_NO_OFFSET` (:226-229). So `brai 256` at pc `0x1000` resolved to
`0x1100` instead of `0x100`. A fabricated address that happens to land on a
real instruction becomes a **basic-block leader**, and `build_blocks` splits a
block there — a corrupt block map, reported with no error and exit status 0.
This was the project's primary target, and it was wrong for a year.

**The fix.** A per-mnemonic `absolute` regex naming the exceptions to the
arch-wide default (`cfg.py:151-155`, `:173-179`, `:258`). It is consulted only
for profiles with `pcrel_operand` set, and only on the decimal-operand path
(`cfg.py:840-848`).

**What to check.** For every immediate-operand transfer in your ISA, find out
from the opcode table whether the operand is a displacement or an address —
do not assume the ISA is uniform. Then verify:

```python
from tcgcov import cfg
p = cfg.get_profile("yourarch")
cfg._parse_target("brai 256", 0x1000, p)   # -> 256   (absolute)
cfg._parse_target("bri 256",  0x1000, p)   # -> 0x1100 (pc-relative)
```

Note this path is only reached when the disassembler printed **no** resolved
target — sources 1-3 in `_parse_target` (`<sym+off>`, an explicit `0x`
operand, a `// <hex>` comment) win first (`cfg.py:780-856`). If your objdump
always prints a resolved target, `pcrel_operand` never fires and this whole
class of bug is moot. Check which case you are in before writing the regex.

### 4.2 Delay slots

Only MicroBlaze, MIPS and SPARC have them among the shipped profiles, and a
test asserts exactly that (`tests/test_arch_profiles.py:474-482`). Two
consequences, both handled by the profile:

* **The fall-through address is the instruction AFTER the delay slot**, not
  after the branch (`cfg.py:1003-1022`). On a 4-byte machine that is `A+8`, not
  `A+4`. Getting this wrong means the "not taken" outcome is attributed to the
  delay-slot instruction, which executes on **both** paths — so the branch
  reads as fully covered no matter what the program did.
* **The delay-slot instruction belongs to the branch's block**, so the last
  instruction of a QEMU translation block — which is what the plugin records as
  an edge's source (`plugin/tcgcov.c:186-194`, `:614-623`) — is the delay slot,
  not the branch. Edge matching therefore accepts any source address at or
  after the branch inside its block (`cfg.py:1111-1128`), and a delay slot is
  never allowed to become a block leader (`cfg.py:1025-1068`, `:1059`).

If only *some* forms delay (MicroBlaze: only the `d`-suffixed spellings; MIPS:
everything except the r6 compact forms), set `has_delay_slot` **and** a
`delay_slot` regex selecting the delaying forms. With `has_delay_slot` set and
no `delay_slot` regex, every terminator delays (`cfg.py:181-187`).

### 4.3 Conditional calls

ARM `bl<cc>`, PowerPC `bltl`/`bnel`, MIPS `bltzal`/`bgezal` are **two-way
branch points that happen to link**. `classify()` tries `call` *before*
`conditional` (`cfg.py:161-167`), so a `call` pattern with an optional
condition suffix swallows them and deletes them from the branch inventory
entirely — every if-converted conditional call in A32 code was missing from
the denominator until `63fbeaf`.

Classify them **COND**. That buys both properties the instruction needs: COND
is in `TERMINATORS` so the block still ends there, and `CFG` builds a
`BranchPoint` only for COND (`cfg.py:1082-1095`). Write the `call` pattern to
match the unconditional forms alone — and mind the ambiguity that `\b` after a
bare mnemonic resolves: ARM `ble` is `b`+`le`, a plain conditional branch, not
`bl`+something (`tests/test_arch_profiles.py:507-513`).

### 4.4 Indirect branches

Without an `indirect` pattern, an indirect transfer's operands are read as a
target: x86 `jmp *0x10(%rax)` parses as `0x10`
(`tests/test_cfg.py:192-199`). AT&T marks every indirect transfer with a
leading `*`, which is the whole x86 rule (`cfg.py:426-429`). ARM had **no**
`indirect` pattern at all until `63fbeaf`; it now needs three alternatives,
including one that splits `blx` on the first operand character because objdump
prints a register for the indirect form and a digit for the direct one
(`cfg.py:356-360`). The same hazard exists wherever a register operand carries
a displacement — RISC-V `jalr 16(a0)`, SPARC `jmpl %g1+0x10, %o7`.

A bogus target is partly caught downstream — `CFG.__init__` nulls a COND target
that is not a real instruction address (`cfg.py:1089-1092`), and
`_parse_target` validates its lower-trust sources against the real instruction
addresses when it is given them (`cfg.py:780-856`). Neither is a substitute:
an `UNCOND`/`CALL` target that *does* coincide with a real address still
injects a false leader. Write the pattern.

### 4.5 Aliases and disassembler spellings

**objdump prints aliases by default.** Write the patterns against what the
disassembler *emits*, not what the assembler accepts:

* RISC-V: binutils prints `beqz`, `bnez`, `j`, `jr`, `ret` by default, and
  prints the compressed encodings under those same names; the `c.`-prefixed
  spellings appear only with `-M no-aliases`. Both are accepted
  (`cfg.py:268-280`). `ble`/`bgt`/`bleu`/`bgtu` are assembler-only and never
  disassembled.
* SPARC: the unconditional branch prints as `b`, never `ba`; conditions print
  as `be`/`bg`/`bl`, never `beq`/`bgt`/`blt`. GNU objdump **never** prints
  `,pt` — llvm-objdump does, so both are accepted (`cfg.py:492-496`).
* PowerPC: extended mnemonics with suffixes glued on — `l` (link), `a`
  (absolute), `lr`/`ctr`/`tar`, and `+`/`-` prediction hints
  (`cfg.py:473-478`).
* x86: prefixes print as separate leading words (`bnd`, `notrack`, `data16`,
  `rex.W`, `cs`/`ds` hints), and the `q` suffix (`retq`, `callq`, `jmpq`)
  appears only with `-M suffix` or from llvm-objdump (`cfg.py:406-412`).
* ARM: objdump maps the `al` condition to the empty string, so a bare `b` is
  unconditional; Thumb adds `.n`/`.w` width suffixes; objdump prints `cs`/`cc`,
  never `hs`/`lo` (`cfg.py:310-315`, `:334`).

**Do not work from the ISA manual alone.** Generate real disassembly of a real
binary for your target and read what actually comes out. The manual tells you
what instructions exist; only the disassembler tells you how they will be
spelled in the text your regex sees.

### 4.6 False positives are as bad as misses

A sloppy `^b` pattern classifies MicroBlaze `bsrli` (barrel shift right
logical immediate) as a branch, which ends a basic block in the middle of
straight-line code and corrupts the block map. The MicroBlaze table therefore
carries eight deliberate non-branch rows — `bsrli`, `bslli`, `bsrai`, `bsefi`,
`bsifi`, `imm`, `addik`, `mbar` (`tests/test_arch_profiles.py:96-104`) — and
every other table carries the same kind of guard (SPARC `bn`, ARM `dls`/`lctp`,
`tests/test_arch_profiles.py:24-27`).

A miss understates the denominator, which is at least visible as a low branch
count. A false positive silently changes the *shape* of the CFG, and nothing
downstream can detect it. Put the non-branches in your table first.

---

## 5. Toolchain output format

### 5.1 The separator after the address colon

**The bug that cost the most.** `cfg.py` required a **tab** after the address
colon. GNU objdump emits a tab; llvm-objdump emits a **space**:

```
GNU objdump : "90000000:\tb00097ff \timm\t-26625"
llvm-objdump: "       0: 52800028     \tmov\tw8, #0x1"
```

Against llvm-objdump input the branch inventory parsed **zero instructions**,
produced zero branches, wrote a 0-byte file and exited 0 — while line coverage,
which used a different and correct regex, kept working perfectly. Branch
coverage silently disappeared.

The fix is one shared definition used by both producers, `INSN_RE`
(`cfg.py:59-72`) via `match_insn_line` (`cfg.py:694-710`), plus a golden
fixture per layout (`tests/data/llvm-*.txt`) and a test asserting the two
denominators see the identical address set
(`tests/test_golden_disasm.py:78-91`).

**What to check:** run **both** GNU objdump and llvm-objdump on a real binary
for your target and confirm each parses to a non-zero, plausible instruction
count:

```sh
<prefix>objdump -d prog.elf > gnu.txt
llvm-objdump -d prog.elf     > llvm.txt
python3 -c '
import sys; from tcgcov import cfg, coverable
for f in sys.argv[1:]:
    t = open(f).read()
    arch = cfg.detect_arch(t)
    g = cfg.analyze(t, cfg.get_profile(arch or "yourarch"))
    print(f, arch, len(g.insns), "insns", len(g.branch_points), "branch points",
          len(g.indirect_branches), "indirect")
    assert coverable.parse_addresses(t) == sorted({i.addr for i in g.insns})
' gnu.txt llvm.txt
```

A count of 0 is a parse failure, and `parse_objdump` raises
`DisassemblyParseError` for it rather than returning an empty list
(`cfg.py:685-691`, `:891-896`) — a total parse failure must never look like
"this binary has no branches".

### 5.2 `--no-show-raw-insn`

GNU objdump drops the raw-bytes column entirely; llvm-objdump leaves it as
blank padding (`tests/test_golden_disasm.py:139-147`). Both are handled by
`_instruction_text` (`cfg.py:756-777`), which takes the raw column to be the
first tab-separated field when there is more than one.

### 5.3 Mnemonics spelled entirely in hex digits

`add`, `dec`, `bad`, `adc`, and — for branches — SPARC `be`, `ba`, `bcc` and
PowerPC `bc` are all spellable in hex. With `--no-show-raw-insn` a purely
textual "is this the raw-bytes column?" test eats the mnemonic and leaves the
operands behind as the instruction. Two structural facts settle it
(`cfg.py:733-753`):

* raw bytes are **whole bytes**, so every group has an even digit count (`add`
  and `dec` are three — but `be`, `ba` and `bc` are **two**, so this rule does
  not save them);
* every objdump **pads** the raw column, so the field always ends in
  whitespace, whereas a mnemonic is followed directly by the tab that separates
  it from its operands. This is the rule that saves `be`/`ba`/`bc`.

If your disassembler does *not* pad the raw column, or separates mnemonic from
operands with something other than a tab, check every hex-spellable mnemonic in
your ISA by hand.

### 5.4 Raw-byte continuation lines

GNU objdump wraps an over-long instruction's bytes onto extra
address-prefixed lines carrying no mnemonic. `_instruction_text` returns `""`
for such a line so it is skipped (`cfg.py:81-84`, `:767-769`). The rule as
implemented is: *the line has exactly one tab-field and that field is all hex
with an even total digit count*.

Two caveats. First, the per-target byte limit at which objdump wraps (7 bytes
for x86 in GNU objdump) is **binutils behaviour that this repo does not encode
or check** — only the shape of the continuation line is. Second, an
operand-less mnemonic spelled entirely in hex digits with an even character
count would be dropped as a continuation line. No shipped profile has one;
check yours.

### 5.5 Stripped binaries

GNU objdump appends `<sym+0xoff>` to a branch target only when a symbol covers
that address. On a **stripped** ELF the same instruction prints a bare hex
number:

```
b.lt 4008b0 <f+0x20>    symbols present
b.lt 4008b0             stripped -- same instruction, same target
```

Before `63fbeaf`, every direct branch in a stripped binary fell through to
"indirect" and was excluded — the denominator silently became zero. Bare hex is
now accepted as the **lowest-trust** source and validated against the set of
real instruction addresses before use (`cfg.py:96-112`, `:850-855`), because a
bare number is genuinely ambiguous: MicroBlaze's `bri 12` is a displacement and
ARM's `movw r0, 4660` an immediate.

If you can, test with symbols **and** stripped and confirm the branch counts
match (`tests/test_cfg.py:308-345`).

---

## 6. Host-side and QEMU-build properties (not guest ISA)

Everything in this section is a property of the **host** you run QEMU on and of
the QEMU build, not of the architecture being emulated. They are listed here
because they look like arch problems when they bite.

### 6.1 Endianness

`endian` in the artifact header describes the **file**, not the guest: a
big-endian guest observed on a little-endian host produces `endian = 1`
(`docs/FORMAT.md:347-348`). You do not need to do anything for a big-endian
target.

There is, however, **no exercised big-endian writer path**:

* the plugin hardcodes `h.endian = 1` (`plugin/tcgcov.c:1220`) and writes the
  header struct's bytes directly with no byte-swap (`plugin/tcgcov.c:1238`), so
  the value is a claim about the *host*, not a conversion;
* `docs/FORMAT.md:343-346` says the writer "always writes native little-endian
  and sets `endian = 1`", and that `endian = 2` exists "so that a big-endian
  host build could write native-order files" — no code emits it;
* the reader rejects `endian = 2` outright with an explicit message
  (`tcgcov/format.py:85-88`).

Inference, not a tested claim: building and running the plugin on a **big-endian
host** would produce big-endian bytes labelled `endian = 1`, which this reader
would misparse. If you are on a big-endian host, verify with `tcgcov dump`
before trusting anything.

### 6.2 32-bit hosts and `libatomic`

The execution counters are `uint64_t` incremented with `__atomic_fetch_add`
(`plugin/tcgcov.c:564`, `:598`). On a 32-bit host there is no native 64-bit
read-modify-write, so the compiler may emit a call to `__atomic_fetch_add_8` in
libatomic. `plugin/Makefile` does not link `-latomic`, so such a build fails to
link — or loads with an unresolved symbol. This is documented and deliberately
unfixed in the source, because the remedy is a link flag or a narrower counter
type, both of which belong to the build contract (`plugin/tcgcov.c:462-476`).

**Which option this affects: `counts=1` only.** The coverage flag itself is an
`unsigned int` (`mark_executed`, `plugin/tcgcov.c:486-491`), which is lock-free
everywhere. Edge counts are plain non-atomic increments in per-vCPU state
(`plugin/tcgcov.c:547`). So on a 32-bit host, drop `counts=` and line and
branch coverage are unaffected.

### 6.3 Per-vCPU edge slots

The per-vCPU edge table is allocated **once**, only when `edges=1`
(`plugin/tcgcov.c:1468-1470`), and never grown so that no reader can race a
realloc (`plugin/tcgcov.c:310-318`, `:1423-1439`):

* **system emulation:** `info->system.max_vcpus` slots;
* **user mode:** a fixed `TCGCOV_VCPU_FALLBACK` = **1024** slots, because each
  guest thread is a vCPU and there is no bound to query
  (`plugin/tcgcov.c:274-281`).

Past the cap, `vcpu_slot()` returns NULL and the plugin **drops that vCPU's
edges**, printing one warning and never scribbling out of bounds
(`plugin/tcgcov.c:427-444`):

```
tcgcov: cpu_index <N> is outside the <cap>-slot per-vCPU edge table; edges for this vCPU are dropped
```

A `vcpu_init` callback is registered so the warning appears when the guest
brings the vCPU online rather than silently at the first lost edge
(`plugin/tcgcov.c:656-665`). Dropped edges reduce branch coverage; they never
produce wrong outcomes.

### 6.4 The three `mode=` values

| `mode=` | Records | Fidelity guarantee (`plugin/tcgcov.c:11-24`, `:353-356`) |
|---|---|---|
| `tb` | one address per executed TB — its start | exact for what it claims: reaching the TB proves its first instruction was reached. Metadata `insn_fidelity: "exact"` |
| `tb-insn` *(default)* | every instruction that individually executed, via a per-instruction execution callback | **exact** — an instruction after an abort point (exception, interrupt, MMIO write that stops the machine) is never reported. Metadata `insn_fidelity: "exact"` |
| `tb-insn-fast` | every instruction the TB was *translated* with, gated on block entry | **over-reports**: a block that aborts part way through still reports all of its instructions. Metadata `insn_fidelity: "tb-approx"` |

Edges are recorded in every mode. The edge source is published from a callback
on the **last instruction** of the block, so it exists only if that block
really ran to its end, and it is consumed by the next block's entry callback —
which is what stops a handler entry from being attributed to a branch that was
never reached (`plugin/tcgcov.c:497-516`, `:602-623`). If the QEMU header
provides discontinuity callbacks, an interrupt or exception additionally
invalidates the pending source (`plugin/tcgcov.c:625-654`); the metadata key
`discon_tracking` records whether that was compiled in. It cannot be gated on
`QEMU_PLUGIN_VERSION` — the API was added part-way through version 5 without a
bump — so the Makefile probes the header (`plugin/tcgcov.c:52-69`).

---

## 7. Adding a profile without forking

`tcgcov branches --arch-profile FILE` registers JSON profiles before analysis
(`branches.py:152-173`). It is repeatable.

> **The driver does not forward it.** `--arch-profile` exists on
> `tcgcov branches` only; `tcgcov-report.sh` has no such flag. Until it does,
> run `tcgcov branches` yourself for a custom arch (see
> `examples/branch-coverage/README.md` for the four-command sequence).

### 7.1 Schema

Three accepted top-level shapes (`cfg.py:650-661`): one profile object (it must
contain `name` or `conditional`), a `{"profiles": [ … ]}` list, or a
`{"<name>": { … }}` mapping.

Every key is optional except `name`; an unknown key is a hard error
(`cfg.py:670-677`), so a typo cannot be silently ignored.

| Key | Type | Meaning |
|---|---|---|
| `name` | str | profile name, e.g. `"mycpu"`. **Required.** |
| `aliases` | [str] | extra names that select it |
| `conditional` | regex | conditional branches — the only kind that becomes a coverage point |
| `unconditional` | regex | unconditional transfers (terminate blocks) |
| `call` | regex | calls — **unconditional forms only**, see §4.3 |
| `return` (or `ret`) | regex | returns |
| `has_delay_slot` | bool | the arch has architectural delay slots |
| `delay_slot` | regex | which forms actually delay; omit when every terminator does |
| `insn_size` | int | default instruction size in bytes, used only as a fall-through hint when address deltas are unavailable |
| `pcrel_operand` | bool | a trailing **decimal** operand is a PC-relative displacement; consulted only when the disassembler printed no resolved target |
| `absolute` | regex | the mnemonics that are the EXCEPTION to `pcrel_operand` — their operand is already the target |
| `comment_target` | bool | the resolved target may appear in a trailing `// <hex>` comment (MicroBlaze does this) |
| `indirect` | regex | register/memory-target transfers, whose operands must never be read as a target |
| `notes` | str | free text; put your citations here |

`supported` is **not** an accepted key — a loaded profile is supported by
construction.

Every regex is matched with `re.match` (anchored at the start,
case-insensitive) against `"<mnemonic> <operands>"`, so a pattern can key off
operands where the mnemonic alone is ambiguous — MIPS `jr ra` is a return while
`jr v0` is an indirect jump (`cfg.py:119-126`, `:465`). Classification order is
**return, call, conditional, unconditional** (`cfg.py:161-167`): precise
patterns must be written so the earlier kinds do not swallow the later ones.

### 7.2 Selecting your profile

`tcgcov branches` picks the arch as `--arch` → the `.cov` metadata's
`target_name` → `detect_arch()` on the objdump banner
(`branches.py:201-202`).

`detect_arch` and the free-form alias list are **built-in substring tables**
(`cfg.py:550-586`) that a user profile does not extend. A user profile's own
`aliases` are matched by **exact, lowercased** name only
(`normalize_arch`, `cfg.py:589-599`). So for a custom ISA:

* **pass `--arch <name>` explicitly**, matching your profile's `name` or one of
  its `aliases` exactly;
* write aliases in lowercase, or they can never match.

### 7.3 A complete worked example

Hypothetical — the mnemonics below are illustrative, not a profile for any real
chip. Assume a 32-bit fixed-width RISC whose GNU objdump prints
`bt`/`bf`/`beq`/`bne`/`blt`/`bge` for conditional branches, `jmp` and `jmpr`
for direct and register jumps, `jsr`/`jsrr` for calls, `rts` for return, a
trailing `d` marking the delay-slot form of each, and one absolute jump `jmpa`.
(This profile has been loaded and its classifications checked — it does what
the comments below claim.)

```json
{
  "name": "exarch",
  "aliases": ["exarch32", "exarchel", "exarchbe"],

  "conditional":   "^(beqd?|bned?|bltd?|bged?|btd?|bfd?)\\b",
  "unconditional": "^(jmpad?|jmprd?|jmpd?)\\b",
  "call":          "^(jsrrd?|jsrd?)\\b",
  "return":        "^rtsd?\\b",

  "has_delay_slot": true,
  "delay_slot":     "^\\w+d\\b",

  "indirect":     "^(jmpr|jsrr)d?\\b",
  "pcrel_operand": true,
  "absolute":      "^jmpad?\\b",
  "comment_target": false,
  "insn_size": 4,

  "notes": "exarch-opc.c:120-186. Conditional forms are all PC-relative (:120-149); jmpa/jmpad take an absolute operand (:170-171). Register-target jmpr/jsrr are indirect and excluded. Every 'd'-suffixed form delays and no other does (DELAY_SLOT column, :120-186)."
}
```

Points worth copying rather than the mnemonics:

* the trailing `\b` is doing real work: it is what stops `jmp` from matching
  `jmpa` (verified — with the boundary present, alternation order does not
  change the result; without it, the short alternative wins). Listing the long
  spellings first is belt-and-braces. Where a pattern makes a *suffix group*
  optional instead, the failure is silent and two-directional: SPARC's optional
  `cb` suffix group classified the unconditional `cb`/`cba` as conditional
  while missing the real `cb02`/`cb013`/`cb12` spellings entirely
  (`cfg.py:510-520`).
* the conditional pattern is an explicit alternation, not `^b`, so `bset` or
  `bswap` cannot be mistaken for a branch (§4.6).
* `call` names only the unconditional forms; if this ISA had `jsr<cc>`, those
  spellings would go in `conditional` (§4.3).
* `notes` carries the opcode-table citations that justify each decision. That
  is the difference between a profile a reviewer can check and one they have to
  trust.

Run it:

```sh
tcgcov branches --elf prog.elf --cov run.cov \
  --arch-profile exarch.json --arch exarch \
  --toolchain-prefix exarch-elf- --all-paths --out br.jsonl
```

### 7.4 Validating it

Write a classification table exactly like `tests/test_arch_profiles.py`, and
**cite the opcode-table line for every row**. The table format is a list of
`(instruction text, expected kind, expected delay-slot flag)`:

```python
EXARCH = [
    ("beq r1, r2, 400 <x>",  COND,   False),   # exarch-opc.c:120
    ("beqd r1, r2, 400 <x>", COND,   True),    # exarch-opc.c:121, DELAY_SLOT
    ("jmpa 4000 <x>",        UNCOND, False),   # exarch-opc.c:170, absolute
    ("jmpr r5",              UNCOND, False),   # exarch-opc.c:160, indirect
    ("jsr 400 <x>",          CALL,   False),   # exarch-opc.c:150
    ("rtsd",                 RET,    True),    # exarch-opc.c:186
    ("bset r3, 4",           OTHER,  False),   # NOT a branch (false-positive guard)
    ("bswap r3, r4",         OTHER,  False),   # NOT a branch
]
```

The shipped tables run 28-54 rows each and a test refuses a table under 28 rows
so it cannot be gutted rather than fixed
(`tests/test_arch_profiles.py:468-472`). Include the non-branches — that is
what catches §4.6. If your arch has delay slots, add it to the `delaying` set
in `test_delay_slot_flag_matches_the_arch`
(`tests/test_arch_profiles.py:474-482`).

Then add a golden fixture: capture genuine `objdump -d` output for a small real
binary into `tests/data/`, and assert the instruction count, the
conditional-branch count, the first and last instruction text, and — the part
that actually exercises your profile — the `(addr, mnemonic, taken,
fallthrough)` tuple for every branch, as
`tests/test_golden_disasm.py:93-113` does for MicroBlaze. A fixture with zero
conditional branches proves only that the parser copes with your
disassembler's column layout; see §2.

---

## 8. "Did I get it right?"

### 8.1 Read the summary that `tcgcov branches` already prints

Three lines on stderr (`branches.py:262-272`) — numbers below are illustrative,
wrapped for width:

```
prog.elf [microblaze]: 42 conditional branches (3 indirect/unknown target -> EXCLUDED
  from branch coverage, 1 without source mapping), 38 reported / 76 outcomes
  edges: 517 observed, 498 matched, 19 ignored (source block does not end in a
  conditional branch), 0 unresolved
  31/38 branches evaluated, 49/76 outcomes taken (64.5%) -> br.jsonl
```

What each number should look like:

* **conditional branches** — compare against a rough count from the
  disassembly. Zero, or an order of magnitude low, means the `conditional`
  pattern is not matching what the disassembler prints (§4.5). Suspiciously
  *high* means a false positive (§4.6) — grep the disassembly for the mnemonics
  your pattern matches and look at what else it caught.
* **indirect/unknown target — EXCLUDED** — these are branch points with no
  statically knowable outcome pair (`cfg.py:987-994`). A handful is normal
  (jump tables, PowerPC conditional returns). A large fraction means either a
  missing `indirect` pattern (§4.4) or targets your `_parse_target` path cannot
  read (§4.1, §5.5).
* **without source mapping** — branches in code with no kept DWARF mapping; a
  path-normalization question, not an arch question.
* **edges: ignored** — the source block does not end in a conditional branch.
  Expected and benign: a QEMU translation block can be shorter than a basic
  block, and ordinary fall-throughs land here (`cfg.py:1111-1128`).
* **edges: unresolved** — the edge's destination matched **neither** outcome of
  the branch its source resolves to (`cfg.py:1187-1194`). **This is the number
  that tells you the CFG model disagrees with reality.** A high unresolved
  count means your taken/fall-through pair is wrong — delay slot mis-modelled
  (§4.2), absolute vs PC-relative mis-modelled (§4.1), or a block boundary in
  the wrong place. Do not ignore it; nothing else will fail.

### 8.2 Then run a program whose outcomes are known by construction

`examples/branch-coverage/` is exactly that: four conditionals whose outcomes
are determined by the source, with the expected result stated up front — 4 of 8
outcomes taken, 3 of 4 branches evaluated, and one branch that must report `-`
(never evaluated) rather than `0` (evaluated, that outcome never occurred).
Build it freestanding for your target at `-O0 -g`, run it under QEMU with
`edges=1`, and compare against
`examples/branch-coverage/README.md:9-17` and the LCOV block at `:46-65`.

Build it at `-O0`. At `-O1` and above these functions inline into `main` and
every condition constant-folds; in the MicroBlaze validation run, `-O1` left 27
executed instructions and 3 edges with **no conditionals surviving**, while
`-O0` left 76 instructions and 17 edges with all four branches intact
(`examples/branch-coverage/README.md:84-91`).

### 8.3 What "taken" means

Machine-level "taken" is the **compiler's** branch, not the source condition.
At `-O0` a compiler typically emits the *inverted* test — it branches *over*
the body when the source condition is false. So a function whose `if` was never
true still reports `taken=1`, because the machine branch that skips the body is
the one that fired.

**`BRDA` outcome 0 does not mean "the `if` was true."** This is normal for
machine-level branch coverage and is not something a profile can or should
correct (`examples/branch-coverage/README.md:77-82`).

---

## Sources

* `tcgcov/cfg.py` — profiles, disassembly parsing, CFG construction, edge
  matching. The module and per-profile docstrings are the authority. Its line
  references here were checked against the tree at the time of writing, and
  that file is under active audit; if a range looks off by a few dozen lines,
  search for the quoted symbol or comment heading instead.
* `tcgcov/branches.py` — the unsupported-arch contract and the summary numbers.
* `tests/test_arch_profiles.py` — per-ISA classification tables with binutils
  citations.
* `tests/test_golden_disasm.py`, `tests/data/` — genuine disassembler output.
* `plugin/tcgcov.c` — modes, edge recording, per-vCPU state, host-side caveats.
* `docs/FORMAT.md` — the artifact format, including the endianness rules.
* `examples/branch-coverage/` — the end-to-end validation program.
