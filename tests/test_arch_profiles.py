"""Per-architecture branch-classification tables.

This is the regression net for the branch DENOMINATOR. `cfg.py` decides, from
the mnemonic alone, whether an instruction is a conditional branch (and so a
coverage point with two outcomes), an unconditional transfer, a call, a return,
or none of those. Every one of those decisions is silent: misclassify a branch
and the reported branch percentage changes with no error, no warning and exit
status 0. A table test is the only thing that turns such a slip into a failure.

Each table below is a list of

    (instruction text, expected kind, expected delay-slot flag)

and each has a companion INDIRECT_<ARCH> list naming the rows whose transfer
target comes from a REGISTER. The two are cross-checked in both directions
(TestIndirectTransfers): every row not named must classify as NOT indirect, and
every name must appear in the ISA table so it is kind-pinned as well. That
second direction is the one that matters most -- `indirect` EXCLUDES an
instruction from branch coverage, so a pattern greedy enough to swallow the
direct branches deletes them from the denominator, which is a worse failure than
the missing patterns it was written to fix.

The mnemonics are taken from the binutils opcode tables -- the same tables
`objdump` itself dispatches on, so "what objdump prints" and "what we classify"
have a single shared source of truth:

    opcodes/microblaze-opc.h   INST_PC_OFFSET / INST_NO_OFFSET, DELAY_SLOT
    opcodes/mips-opc.c         CBD / UBD / CBL / NODS  (lines 223-228)
    opcodes/sparc-opc.c        F_CONDBR / F_UNBR / F_DELAYED / F_JSR
    opcodes/arm-dis.c          the disassembler's format-string table
    opcodes/i386-dis.c         Jcc / jmpabs
    opcodes/riscv-opc.c, aarch64-tbl.h, ppc-opc.c

The tables deliberately include NON-branches too (MicroBlaze `bsrli`, SPARC
`bn`, ARM `dls`): a false positive corrupts the block map, which is just as
damaging as a miss and much harder to notice.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import cfg  # noqa: E402

COND, UNCOND, CALL, RET, OTHER = (cfg.COND, cfg.UNCOND, cfg.CALL, cfg.RET,
                                  cfg.OTHER)


# --- MicroBlaze -------------------------------------------------------------
# microblaze-opc.h:195-241. The delay-slot column is the table's third field
# (DELAY_SLOT / NO_DELAY_SLOT) verbatim: every 'd'-suffixed form delays, no
# other form does, and the link forms exist ONLY in delayed spellings.
MICROBLAZE = [
    # unconditional, immediate operand -- PC-relative (INST_PC_OFFSET, :223-225)
    ("bri 8", UNCOND, False),
    ("brid 8", UNCOND, True),
    ("brlid r15, 8", CALL, True),
    # unconditional, immediate operand -- ABSOLUTE (INST_NO_OFFSET, :226-229)
    ("brai 8", UNCOND, False),
    ("braid 8", UNCOND, True),
    ("bralid r15, 8", CALL, True),
    ("brki r16, 8", CALL, False),
    # unconditional, register operand (:195-201)
    ("br r5", UNCOND, False),
    ("brd r5", UNCOND, True),
    ("brld r15, r5", CALL, True),
    ("bra r5", UNCOND, False),
    ("brad r5", UNCOND, True),
    ("brald r15, r5", CALL, True),
    ("brk r5, r6", CALL, False),
    # conditional, register operand (:202-213)
    ("beq r3, r4", COND, False),
    ("beqd r3, r4", COND, True),
    ("bne r3, r4", COND, False),
    ("bned r3, r4", COND, True),
    ("blt r3, r4", COND, False),
    ("bltd r3, r4", COND, True),
    ("ble r3, r4", COND, False),
    ("bled r3, r4", COND, True),
    ("bgt r3, r4", COND, False),
    ("bgtd r3, r4", COND, True),
    ("bge r3, r4", COND, False),
    ("bged r3, r4", COND, True),
    # conditional, immediate operand -- all 12 are INST_PC_OFFSET (:230-241)
    ("beqi r3, 8", COND, False),
    ("beqid r3, 8", COND, True),
    ("bnei r3, 8", COND, False),
    ("bneid r3, 8", COND, True),
    ("blti r3, 8", COND, False),
    ("bltid r3, 8", COND, True),
    ("blei r3, 8", COND, False),
    ("bleid r3, 8", COND, True),
    ("bgti r3, 8", COND, False),
    ("bgtid r3, 8", COND, True),
    ("bgei r3, 8", COND, False),
    ("bgeid r3, 8", COND, True),
    # returns (:219-222), all DELAY_SLOT
    ("rtsd r15, 8", RET, True),
    ("rtid r14, 8", RET, True),
    ("rtbd r16, 8", RET, True),
    ("rted r17, 8", RET, True),
    # NOT branches. The barrel-shift mnemonics all begin with 'bs' and the
    # immediate prefix with 'b'; a sloppy '^b' pattern would eat them and end a
    # block in the middle of straight-line code.
    ("bsrli r3, r3, 2", OTHER, False),
    ("bslli r3, r3, 2", OTHER, False),
    ("bsrai r3, r3, 2", OTHER, False),
    ("bsefi r3, r4, 5, 6", OTHER, False),
    ("bsifi r3, r4, 5, 6", OTHER, False),
    ("imm -256", OTHER, False),
    ("addik r1, r1, -32", OTHER, False),
    ("mbar 1", OTHER, False),
]

# Register-target forms: the operand is a register number, so "beq r3, r4"
# branches to whatever r4 holds and the trailing 4 is not a displacement.
# 'brk' belongs here too (microblaze-opc.h groups it with the register forms);
# its immediate twin 'brki' does not.
INDIRECT_MICROBLAZE = [
    "br r5", "brd r5", "brld r15, r5", "bra r5", "brad r5", "brald r15, r5",
    "brk r5, r6",
    "beq r3, r4", "beqd r3, r4", "bne r3, r4", "bned r3, r4",
    "blt r3, r4", "bltd r3, r4", "ble r3, r4", "bled r3, r4",
    "bgt r3, r4", "bgtd r3, r4", "bge r3, r4", "bged r3, r4",
]


# --- ARM A32/T32 ------------------------------------------------------------
# Condition suffixes from arm-dis.c:4919; the v8.1-M low-overhead-loop and
# Thumb table-branch entries are cited inline.
ARM = [
    ("b 8010 <x>", UNCOND, False),
    ("bal 8010 <x>", UNCOND, False),
    ("b.n 8010 <x>", UNCOND, False),
    ("b.w 8010 <x>", UNCOND, False),
    # plain conditional branches
    ("beq 8010 <x>", COND, False),
    ("bne 8010 <x>", COND, False),
    ("bcs 8010 <x>", COND, False),
    ("bcc 8010 <x>", COND, False),
    ("bmi 8010 <x>", COND, False),
    ("bpl 8010 <x>", COND, False),
    ("bvs 8010 <x>", COND, False),
    ("bvc 8010 <x>", COND, False),
    ("bhi 8010 <x>", COND, False),
    ("bls 8010 <x>", COND, False),
    ("bge 8010 <x>", COND, False),
    ("blt 8010 <x>", COND, False),
    ("bgt 8010 <x>", COND, False),
    ("ble 8010 <x>", COND, False),
    ("cbz r0, 8010 <x>", COND, False),
    ("cbnz r0, 8010 <x>", COND, False),
    # calls: only the UNCONDITIONAL forms
    ("bl 8010 <x>", CALL, False),
    ("blx 8010 <x>", CALL, False),
    ("blx r3", CALL, False),
    ("blxns r3", CALL, False),
    # conditional calls -- two-way branch points, NOT plain calls
    ("bleq 8010 <x>", COND, False),
    ("blne 8010 <x>", COND, False),
    ("bllt 8010 <x>", COND, False),
    ("blgt 8010 <x>", COND, False),
    ("blxeq r3", COND, False),
    # v8.1-M low-overhead loops (arm-dis.c:4410-4422)
    ("le lr, 8000 <l>", COND, False),
    ("le 8000 <l>", COND, False),
    ("letp lr, 8000 <l>", COND, False),
    ("wls lr, r0, 8020 <e>", COND, False),
    ("wlstp.u16 lr, r0, 8020 <e>", COND, False),
    ("dls lr, r0", OTHER, False),      # sets LR only: not a branch
    ("lctp", OTHER, False),
    # Thumb table branches (arm-dis.c:4563-4565): indirect, but they MUST end
    # the block -- the jump table bytes follow inline and objdump disassembles
    # them as if they were instructions.
    ("tbb [r0, r1]", UNCOND, False),
    ("tbh [r0, r1, lsl #1]", UNCOND, False),
    # returns / indirect transfers through pc
    ("bx lr", RET, False),
    ("bx r3", UNCOND, False),
    ("mov pc, lr", RET, False),
    ("mov pc, r3", UNCOND, False),
    ("pop {r4, pc}", RET, False),
    ("ldr pc, [sp], #4", RET, False),
    # not branches
    ("mov r1, #2", OTHER, False),
    ("ldr r0, [r1]", OTHER, False),
]

# 'blx' splits on the first operand character: objdump prints a register for the
# indirect form and a digit for the direct one, which is why "blx 8010 <x>" is
# absent here and "blx r3" is present.
INDIRECT_ARM = [
    "blx r3", "blxeq r3",
    "tbb [r0, r1]", "tbh [r0, r1, lsl #1]",
    "bx lr", "bx r3",
    "mov pc, lr", "mov pc, r3", "ldr pc, [sp], #4",
]


# --- AArch64 ----------------------------------------------------------------
AARCH64 = [
    ("b 4008b0 <x>", UNCOND, False),
    ("b.eq 4008b0 <x>", COND, False),
    ("b.ne 4008b0 <x>", COND, False),
    ("b.lt 4008b0 <x>", COND, False),
    ("b.ge 4008b0 <x>", COND, False),
    ("b.hi 4008b0 <x>", COND, False),
    ("b.ls 4008b0 <x>", COND, False),
    ("bc.eq 4008b0 <x>", COND, False),     # v8.8 BC.cond
    ("cbz x0, 4008b0 <x>", COND, False),
    ("cbnz w0, 4008b0 <x>", COND, False),
    ("tbz x0, #3, 4008b0 <x>", COND, False),
    ("tbnz x0, #3, 4008b0 <x>", COND, False),
    ("cbeq w0, w1, 4008b0 <x>", COND, False),   # v9.6 CMPBR
    ("cbne w0, w1, 4008b0 <x>", COND, False),
    ("cbhi w0, w1, 4008b0 <x>", COND, False),
    ("cbblt w0, w1, 4008b0 <x>", COND, False),
    ("cbhge w0, w1, 4008b0 <x>", COND, False),
    ("bl 4008b0 <x>", CALL, False),
    # The complete iclass branch_reg block, aarch64-tbl.h:4413-4430.
    ("blr x8", CALL, False),               # :4415, OP1 (Rn)
    ("blraa x8, x9", CALL, False),         # :4421, OP2 (Rn, Rd_SP)
    ("blrab x8, x9", CALL, False),         # :4422
    ("blraaz x8", CALL, False),            # :4425, OP1 (Rn)
    ("blrabz x8", CALL, False),            # :4426
    ("br x8", UNCOND, False),              # :4414
    ("braa x8, x9", UNCOND, False),        # :4419
    ("brab x8, sp", UNCOND, False),        # :4420, Rd_SP prints 'sp' for r31
    ("braaz x8", UNCOND, False),           # :4423
    ("brabz x8", UNCOND, False),           # :4424
    # ret's operand is optional and defaults to x30 (F_OPD0_OPT|F_DEFAULT(30),
    # suppressed at aarch64-opc.c:4096-4099), so both spellings occur; retaa
    # and retab take OP0 and never print one (aarch64-tbl.h:4427-4428).
    ("ret", RET, False),                   # :4416
    ("ret x8", RET, False),
    ("retaa", RET, False),
    ("retab", RET, False),
    ("eret", RET, False),                  # :4417
    ("eretaa", RET, False),                # :4429
    ("drps", OTHER, False),                # :4418, not modeled as a transfer
    ("mov w8, #0x1", OTHER, False),
    ("ldr x0, [x1]", OTHER, False),
]

# The ten branch_reg entries that print a register operand AND classify UNCOND
# or CALL -- i.e. the ones whose operands _parse_target would otherwise read.
# ret/retaa/retab/eret* stay out: they classify RET, which is never
# target-parsed, and the `ret` pattern is tried first so nothing is
# double-counted.
INDIRECT_AARCH64 = [
    "br x8", "braa x8, x9", "brab x8, sp", "braaz x8", "brabz x8",
    "blr x8", "blraa x8, x9", "blrab x8, x9", "blraaz x8", "blrabz x8",
]


# --- x86 / x86-64 -----------------------------------------------------------
# All 16 Jcc spellings binutils emits, plus the loop/jcxz group, the prefixed
# forms, and the APX jmpabs (i386-dis.c:14640).
X86 = [
    ("jo 401000 <x>", COND, False),
    ("jno 401000 <x>", COND, False),
    ("jb 401000 <x>", COND, False),
    ("jae 401000 <x>", COND, False),
    ("je 401000 <x>", COND, False),
    ("jne 401000 <x>", COND, False),
    ("jbe 401000 <x>", COND, False),
    ("ja 401000 <x>", COND, False),
    ("js 401000 <x>", COND, False),
    ("jns 401000 <x>", COND, False),
    ("jp 401000 <x>", COND, False),
    ("jnp 401000 <x>", COND, False),
    ("jl 401000 <x>", COND, False),
    ("jge 401000 <x>", COND, False),
    ("jle 401000 <x>", COND, False),
    ("jg 401000 <x>", COND, False),
    ("jrcxz 401000 <x>", COND, False),
    ("jecxz 401000 <x>", COND, False),
    ("loop 401000 <x>", COND, False),
    ("loope 401000 <x>", COND, False),
    ("loopne 401000 <x>", COND, False),
    ("jmp 401000 <x>", UNCOND, False),
    ("jmpq 401000 <x>", UNCOND, False),
    ("jmp *%rax", UNCOND, False),
    ("jmpabs $0x401000", UNCOND, False),   # APX absolute direct jump
    ("bnd jmp 401000 <x>", UNCOND, False),
    ("notrack jmp *%rax", UNCOND, False),
    ("call 401000 <x>", CALL, False),
    ("callq 401000 <x>", CALL, False),
    ("call *%rax", CALL, False),
    ("lcall *0x10(%rax)", CALL, False),
    ("ret", RET, False),
    ("retq", RET, False),
    ("iretq", RET, False),
    ("sysretq", RET, False),
    ("mov $0x1,%eax", OTHER, False),
    ("cmpl $0x0,-0x4(%rbp)", OTHER, False),
]

# AT&T marks every indirect transfer with a leading '*'; nothing else is needed.
# 'jmpabs $0x401000' (i386-dis.c:14640) deliberately has no '*': it is a DIRECT
# absolute jump, so it must not land here.
INDIRECT_X86 = [
    "jmp *%rax", "notrack jmp *%rax", "call *%rax", "lcall *0x10(%rax)",
]


# --- MIPS -------------------------------------------------------------------
# Delay-slot column is the opcode table's CBD/UBD/CBL flag (mips-opc.c:223-228):
# the classic branches delay, the MIPS32r6 "compact" forms carry NODS and are
# exactly the mnemonics ending in 'c'.
MIPS = [
    ("b 400 <x>", UNCOND, True),
    ("bc 400 <x>", UNCOND, False),         # r6 compact, NODS
    ("j 400 <x>", UNCOND, True),           # mips-opc.c:1230, "a"
    ("jal 400 <x>", CALL, True),           # mips-opc.c:1245, "a"
    ("jalx 400 <x>", CALL, True),          # mips-opc.c:1246, "+i"
    ("balc 400 <x>", CALL, False),
    # Register jumps. objdump indexes a NAME table (mips-dis.c:1211, tables at
    # mips-dis.c:61,69), so the default spelling has NO '$'; the '$' forms only
    # appear under -M gpr-names=numeric ("$8") but are accepted so llvm-objdump
    # and hand-written listings work too. Both spellings must agree.
    ("jr $t0", UNCOND, True),
    ("jr t0", UNCOND, True),               # mips-opc.c:1216, "s"
    ("jr $ra", RET, True),
    ("jr ra", RET, True),                  # the return idiom, not a jump
    ("jr.hb t0", UNCOND, True),            # mips-opc.c:1221
    ("jalr $t0", CALL, True),
    ("jalr v1", CALL, True),               # mips-opc.c:1231, "s"
    ("jalr a0,v1", CALL, True),            # mips-opc.c:1232, "d,s"
    ("jalr.hb a0,v1", CALL, True),         # mips-opc.c:1236
    # r6 compact jumps: NODS, so no delay slot. 'jic' is an unconditional
    # transfer and must end its block (mips-opc.c:3257).
    ("jrc at", UNCOND, False),             # mips-opc.c:3256, "t"
    ("jalrc t0", CALL, False),             # mips-opc.c:3260, "t"
    ("jic v1,-32768", UNCOND, False),      # mips-opc.c:3257, "t,j"
    ("jic ra,0", RET, False),              # ...through $ra it is a return
    ("jialc v1,32767", CALL, False),       # mips-opc.c:3261, "t,j"
    ("beq $a0, $a1, 400 <x>", COND, True),
    ("bne $a0, $a1, 400 <x>", COND, True),
    ("beqz $a0, 400 <x>", COND, True),
    ("bnez $a0, 400 <x>", COND, True),
    ("blez $a0, 400 <x>", COND, True),
    ("bgtz $a0, 400 <x>", COND, True),
    ("bltz $a0, 400 <x>", COND, True),
    ("bgez $a0, 400 <x>", COND, True),
    ("beql $a0, $a1, 400 <x>", COND, True),      # CBL, likely
    ("bnel $a0, $a1, 400 <x>", COND, True),
    ("bltzal $a0, 400 <x>", COND, True),         # branch AND link
    ("bgezal $a0, 400 <x>", COND, True),
    ("beqc $a0, $a1, 400 <x>", COND, False),     # r6 compact
    ("bnec $a0, $a1, 400 <x>", COND, False),
    ("bltc $a0, $a1, 400 <x>", COND, False),
    ("bgec $a0, $a1, 400 <x>", COND, False),
    ("bovc $a0, $a1, 400 <x>", COND, False),
    ("bnvc $a0, $a1, 400 <x>", COND, False),
    ("bc1t 400 <x>", COND, True),                # pre-r6 FP branch
    ("bc1f 400 <x>", COND, True),
    ("bc1tl 400 <x>", COND, True),
    # MIPS32r6 replaced bc1t/bc1f with bc1eqz/bc1nez, so these two are the ONLY
    # FP conditional branches in r6 code (mips-opc.c:729,734, CBD).
    ("bc1eqz $f0, 400 <x>", COND, True),
    ("bc1nez $f0, 400 <x>", COND, True),
    ("bc2eqz $0, 400 <x>", COND, True),          # mips-opc.c:3366
    ("bc2nez $0, 400 <x>", COND, True),          # mips-opc.c:3371
    ("bposge32 400 <x>", COND, True),            # DSP ASE, mips-opc.c:2146
    ("bposge64 400 <x>", COND, True),            # mips-opc.c:2148
    ("bposge32c 400 <x>", COND, False),          # NODS, mips-opc.c:2147
    ("bbit0 $a0, 3, 400 <x>", COND, True),       # Octeon, mips-opc.c:718-723
    ("bbit1 $a0, 3, 400 <x>", COND, True),
    ("bbit032 $a0, 3, 400 <x>", COND, True),
    ("bbit132 $a0, 3, 400 <x>", COND, True),
    ("addiu $sp, $sp, -32", OTHER, False),
    ("lw $a0, 0($sp)", OTHER, False),
]

# Every jr/jalr/jic/jialc form, in both register spellings. 'jr ra' and
# 'jic ra,0' are here even though they classify RET: the `ret` pattern is tried
# first so the RETURN classification still wins, but the target of a return
# through $ra is a register all the same. j/jal/jalx/bc/balc are PC-relative
# and must stay out -- swallowing them would delete every MIPS jump target.
INDIRECT_MIPS = [
    "jr $t0", "jr t0", "jr $ra", "jr ra", "jr.hb t0",
    "jalr $t0", "jalr v1", "jalr a0,v1", "jalr.hb a0,v1",
    "jrc at", "jalrc t0",
    "jic v1,-32768", "jic ra,0", "jialc v1,32767",
]


# --- SPARC ------------------------------------------------------------------
# F_CONDBR / F_UNBR / F_DELAYED from sparc-opc.c.
SPARC = [
    ("b 10024 <x>", UNCOND, True),               # sparc-opc.c:1361, F_UNBR
    ("ba,a 10024 <x>", UNCOND, True),
    ("be 10024 <x>", COND, True),                # :1367
    ("bne 10024 <x>", COND, True),               # :1380
    ("bg 10024 <x>", COND, True),                # :1369
    ("bge 10024 <x>", COND, True),               # :1371
    ("bgu 10024 <x>", COND, True),               # :1373
    ("bl 10024 <x>", COND, True),                # :1374
    ("ble 10024 <x>", COND, True),               # :1376
    ("bleu 10024 <x>", COND, True),              # :1377
    ("bcc 10024 <x>", COND, True),               # :1365
    ("bcs 10024 <x>", COND, True),               # :1366
    ("bneg 10024 <x>", COND, True),              # :1381
    ("bpos 10024 <x>", COND, True),              # :1383
    ("bvc 10024 <x>", COND, True),               # :1384
    ("bvs 10024 <x>", COND, True),               # :1385
    ("be,a 10024 <x>", COND, True),
    ("be,pn %icc, 10024 <x>", COND, True),
    # "branch never": it NEVER transfers, so it is neither a terminator nor a
    # branch point (sparc-opc.c:1379 bn, :1697 fbn/cbn).
    ("bn 10024 <x>", OTHER, False),
    ("bn,a 10024 <x>", OTHER, False),
    ("fbn 10024 <x>", OTHER, False),
    ("cbn 10024 <x>", OTHER, False),
    # FP branches (sparc-opc.c:1688-1706)
    ("fb 10024 <x>", UNCOND, True),              # :1688, F_UNBR
    ("fba 10024 <x>", UNCOND, True),             # :1689
    ("fbe 10024 <x>", COND, True),               # :1690
    ("fbne 10024 <x>", COND, True),              # :1698
    ("fbul 10024 <x>", COND, True),              # :1705
    ("fbule 10024 <x>", COND, True),             # :1706
    # coprocessor branches -- the 'cb' spellings of the same table
    ("cb 10024 <x>", UNCOND, True),              # :1688, branch ALWAYS
    ("cba 10024 <x>", UNCOND, True),             # :1689
    ("cb0 10024 <x>", COND, True),               # :1690
    ("cb1 10024 <x>", COND, True),               # :1694
    ("cb2 10024 <x>", COND, True),               # :1692
    ("cb3 10024 <x>", COND, True),               # :1701
    ("cb01 10024 <x>", COND, True),              # :1695
    ("cb02 10024 <x>", COND, True),              # :1693
    ("cb03 10024 <x>", COND, True),              # :1702
    ("cb12 10024 <x>", COND, True),              # :1696
    ("cb13 10024 <x>", COND, True),              # :1705
    ("cb23 10024 <x>", COND, True),              # :1703
    ("cb012 10024 <x>", COND, True),             # :1700
    ("cb013 10024 <x>", COND, True),             # :1706
    ("cb023 10024 <x>", COND, True),             # :1704
    ("cb123 10024 <x>", COND, True),             # :1698
    ("cbe 10024 <x>", COND, True),               # sparclet, :1953
    ("cbnefr 10024 <x>", COND, True),            # sparclet, :1967
    # v9 register branches and CBcond
    ("brz %g1, 10024 <x>", COND, True),
    ("brnz %g1, 10024 <x>", COND, True),
    ("cwbne %g1, %g2, 10024 <x>", COND, False),  # CBcond: no delay slot
    # jmpl and its two rename-by-destination spellings. The printer emits a
    # space before EVERY operand character on top of the one after the mnemonic
    # (sparc-dis.c:560-561,:591), so the real text has two spaces after the
    # mnemonic and spaces around the '+'; immediates print %#x above 9 and %d
    # below (sparc-dis.c:689-716). Both the real spacing and the compact
    # spelling other disassemblers use are pinned.
    ("jmpl  %g1 + 0x10, %o2", UNCOND, True),     # sparc-opc.c:831, "1+i,d"
    ("jmpl %g1+0x10, %o7", UNCOND, True),
    ("jmpl %o7+8, %g0", UNCOND, True),
    ("jmp  %g2", UNCOND, True),                  # sparc-opc.c:1716, "1"
    ("jmp  %g1 + 0x10", UNCOND, True),           # sparc-opc.c:1717, "1+i"
    # rd == %g0 AND rs1 == %g0: the printed number really is the target, so
    # this one must stay DIRECT (sparc-opc.c:1719, args "i").
    ("jmp  0x10", UNCOND, True),
    ("call 10024 <x>", CALL, True),              # sparc-opc.c:1290, "L"
    ("call  1000 <foo-0x8>", CALL, True),
    ("call  %o0", CALL, True),                   # sparc-opc.c:1295, "1"
    ("call  %g1 + %g2", CALL, True),             # sparc-opc.c:1293, "1+2"
    ("retl", RET, True),
    ("ret", RET, True),
    ("rett  %i7 + 8", RET, True),                # sparc-opc.c:811-817
    ("return %i7+8", RET, False),
    ("add %g1, %g2, %g3", OTHER, False),
]

# The register-target spellings only. The split is on the FIRST operand
# character, exactly as the ARM profile splits 'blx': '%' means the target came
# from a register, a digit means the operand IS the address. That is what keeps
# the PC-relative "call  1000 <foo-0x8>" and the %g0-relative "jmp  0x10" out,
# both of which have a real, printed target.
INDIRECT_SPARC = [
    "jmpl  %g1 + 0x10, %o2", "jmpl %g1+0x10, %o7", "jmpl %o7+8, %g0",
    "jmp  %g2", "jmp  %g1 + 0x10",
    "call  %o0", "call  %g1 + %g2",
]


# --- PowerPC ----------------------------------------------------------------
# Extended mnemonics as objdump prints them, including the '+'/'-' prediction
# hints and the 'l' (link) / 'a' (absolute) suffixes.
POWERPC = [
    ("b 90 <x>", UNCOND, False),
    ("ba 90 <x>", UNCOND, False),
    ("bl 90 <x>", CALL, False),
    ("bla 90 <x>", CALL, False),
    ("blt 90 <x>", COND, False),
    ("bgt 90 <x>", COND, False),
    ("beq 90 <x>", COND, False),
    ("bne 90 <x>", COND, False),
    ("bge 90 <x>", COND, False),
    ("ble 90 <x>", COND, False),
    ("bso 90 <x>", COND, False),
    ("bns 90 <x>", COND, False),
    ("ble- cr1, 90 <x>", COND, False),
    ("bgt+ cr7, 90 <x>", COND, False),
    ("bdnz 90 <x>", COND, False),
    ("bdz 90 <x>", COND, False),
    ("bdnzt 90 <x>", COND, False),
    ("bt 4, 90 <x>", COND, False),
    ("bf 4, 90 <x>", COND, False),
    ("bc 12, 0, 90 <x>", COND, False),
    # conditional-and-link: branch points that also link, same as ARM's 'bleq'
    ("bltl 90 <x>", COND, False),
    ("bnel 90 <x>", COND, False),
    # conditional returns: branch points with an implicit LR target
    ("blelr", COND, False),
    ("bdnzlr", COND, False),
    ("blr", RET, False),                   # ppc-opc.c:6677
    ("blrl", RET, False),                  # ppc-opc.c:6679
    ("bclr", RET, False),                  # ppc-opc.c:6884
    ("bctr", UNCOND, False),               # ppc-opc.c:6940
    ("bctrl", CALL, False),                # ppc-opc.c:6941
    ("btar", UNCOND, False),               # ppc-opc.c:7097, POWER8
    # to-CTR / to-TAR conditionals. The CR and BH operands are optional and
    # print only when non-default (ppc-dis.c:615-643), which is why the same
    # mnemonic appears bare, with 'cr2', and with 'cr1,1'.
    ("bltctr", COND, False),
    ("bdnzctr", COND, False),
    ("bnectr  cr2", COND, False),          # gas/testsuite/gas/ppc/476.d:44
    ("bnectr  cr1,1", COND, False),        # gas/testsuite/gas/ppc/a2.d:61
    ("blttar", COND, False),               # gas/testsuite/gas/ppc/bcat.d:58
    ("bdnztar", COND, False),
    ("bgetar-", COND, False),
    ("bgetar+", COND, False),
    ("bdnzftar lt", COND, False),          # raw-BI form, bcat.d:51
    ("bttar", COND, False),
    # -Mraw spellings: three operands, the last of which used to be read as a
    # branch target (gas/testsuite/gas/ppc/raw.d:30-32).
    ("bclr    20,lt,0", RET, False),
    ("bcctr   6,lt,0", COND, False),
    ("bctarl  4,so,0", CALL, False),
    ("addi 1, 1, -32", OTHER, False),
    ("stw 31, 28(1)", OTHER, False),
]

# Everything that branches to LR, CTR or TAR: the target is in a special
# register and never printed, but the optional CR/BH operands are, and their
# trailing small integers were being read as addresses. The direct branches --
# including 'bl', 'bla', 'bltl' and 'ble', whose spellings come closest -- must
# all stay out.
INDIRECT_POWERPC = [
    "blelr", "bdnzlr", "blr", "blrl", "bclr", "bctr", "bctrl", "btar",
    "bltctr", "bdnzctr", "bnectr  cr2", "bnectr  cr1,1",
    "blttar", "bdnztar", "bgetar-", "bgetar+", "bdnzftar lt", "bttar",
    "bclr    20,lt,0", "bcctr   6,lt,0", "bctarl  4,so,0",
]


# --- RISC-V -----------------------------------------------------------------
RISCV = [
    ("beq a0, a1, 100b0 <x>", COND, False),
    ("bne a0, a1, 100b0 <x>", COND, False),
    ("blt a0, a1, 100b0 <x>", COND, False),
    ("bge a0, a1, 100b0 <x>", COND, False),
    ("bltu a0, a1, 100b0 <x>", COND, False),
    ("bgeu a0, a1, 100b0 <x>", COND, False),
    ("beqz a0, 100b0 <x>", COND, False),
    ("bnez a0, 100b0 <x>", COND, False),
    ("blez a0, 100b0 <x>", COND, False),
    ("bgez a0, 100b0 <x>", COND, False),
    ("bltz a0, 100b0 <x>", COND, False),
    ("bgtz a0, 100b0 <x>", COND, False),
    ("c.beqz a0, 100b0 <x>", COND, False),
    ("c.bnez a0, 100b0 <x>", COND, False),
    ("j 100b0 <x>", UNCOND, False),
    ("c.j 100b0 <x>", UNCOND, False),
    ("jal 100b0 <x>", CALL, False),
    ("call 100b0 <x>", CALL, False),
    ("tail 100b0 <x>", CALL, False),
    # jr/jalr, in every shape riscv-opc.c gives them. The offset prints as a
    # signed DECIMAL (riscv-dis.c:565-566), so the "16(a0)" spellings are what
    # GNU objdump emits; llvm-objdump writes the same operand as 0x10.
    ("jr a0", UNCOND, False),              # riscv-opc.c:487, "s"
    ("jr 16(a0)", UNCOND, False),          # riscv-opc.c:488, "o(s)"
    ("c.jr a0", UNCOND, False),            # riscv-opc.c:1193, -M no-aliases
    ("jalr a0", CALL, False),              # riscv-opc.c:491, "s"
    ("jalr 16(a0)", CALL, False),          # riscv-opc.c:492, "o(s)"
    ("jalr 0x10(a0)", CALL, False),        # llvm-objdump spelling of the same
    ("jalr a1,16(a0)", CALL, False),       # riscv-opc.c:495, "d,o(s)"
    ("jalr a1,a0", CALL, False),           # riscv-opc.c:494, "d,s"
    ("c.jalr a0", CALL, False),            # riscv-opc.c:1194, -M no-aliases
    ("ret", RET, False),
    ("c.ret", RET, False),
    ("addi sp, sp, -32", OTHER, False),
    ("sd ra, 24(sp)", OTHER, False),
    ("li a0, 0", OTHER, False),
]

# jr/jalr are the only register-indirect transfers in riscv_opcodes[]; j/jal
# (and the call/tail macros) are PC-relative and must stay out.
INDIRECT_RISCV = [
    "jr a0", "jr 16(a0)", "c.jr a0",
    "jalr a0", "jalr 16(a0)", "jalr 0x10(a0)", "jalr a1,16(a0)", "jalr a1,a0",
    "c.jalr a0",
]


TABLES = (
    ("microblaze", MICROBLAZE, INDIRECT_MICROBLAZE),
    ("arm", ARM, INDIRECT_ARM),
    ("aarch64", AARCH64, INDIRECT_AARCH64),
    ("x86_64", X86, INDIRECT_X86),
    ("mips", MIPS, INDIRECT_MIPS),
    ("sparc", SPARC, INDIRECT_SPARC),
    ("powerpc", POWERPC, INDIRECT_POWERPC),
    ("riscv", RISCV, INDIRECT_RISCV),
)


class TestClassificationTables(unittest.TestCase):
    """One assertion per mnemonic, per ISA.

    A subTest per row so a single misclassification reports the exact
    instruction rather than aborting the arch.
    """

    def test_kinds_and_delay_slots(self):
        for arch, table, _ in TABLES:
            profile = cfg.get_profile(arch)
            self.assertTrue(profile.supported, arch)
            for text, kind, delay in table:
                with self.subTest(arch=arch, insn=text):
                    got = profile.classify(text)
                    self.assertEqual(got, kind)
                    self.assertEqual(profile.delays(got, text), delay)

    def test_every_arch_table_is_substantial(self):
        """Guard against a table being gutted rather than fixed."""
        for arch, table, _ in TABLES:
            with self.subTest(arch=arch):
                self.assertGreaterEqual(len(table), 28)

    def test_delay_slot_flag_matches_the_arch(self):
        """Only MicroBlaze, MIPS and SPARC have architectural delay slots."""
        delaying = {"microblaze", "mips", "sparc"}
        for arch, table, _ in TABLES:
            profile = cfg.get_profile(arch)
            with self.subTest(arch=arch):
                self.assertEqual(profile.has_delay_slot, arch in delaying)
                if arch not in delaying:
                    self.assertFalse(any(d for _, _, d in table))


class TestIndirectTransfers(unittest.TestCase):
    """Which transfers take their target from a register, per ISA.

    `indirect` is the switch that EXCLUDES an instruction from branch coverage
    (and from target parsing). Both directions are failures that report a wrong
    number with exit status 0:

      * a MISSING pattern lets _parse_target read a register displacement as an
        address, and an unconditional branch with a bogus target injects a false
        basic-block leader -- the same corruption the MicroBlaze absolute-branch
        bug caused;
      * a TOO-GREEDY pattern swallows the direct branches and silently deletes
        them from the denominator, which is worse.

    So every row of every ISA table is pinned in one direction or the other.
    """

    def test_indirect_flag_for_every_row(self):
        for arch, table, indirect in TABLES:
            profile = cfg.get_profile(arch)
            expected = set(indirect)
            for text, _, _ in table:
                with self.subTest(arch=arch, insn=text):
                    self.assertEqual(profile.is_indirect(text),
                                     text in expected)

    def test_every_indirect_form_is_also_kind_pinned(self):
        """The companion list may only name rows the ISA table also carries."""
        for arch, table, indirect in TABLES:
            rows = {text for text, _, _ in table}
            with self.subTest(arch=arch):
                self.assertEqual(sorted(set(indirect) - rows), [])

    def test_every_arch_recognizes_indirect_transfers(self):
        """Every shipped ISA has register-indirect branches; none may lack them.

        aarch64, riscv, mips, sparc and powerpc all shipped with no `indirect`
        pattern at all, so `jmpl %g1+0x10, %o7` classified UNCOND with a
        "target" of 0x10.
        """
        for arch, _, indirect in TABLES:
            with self.subTest(arch=arch):
                self.assertTrue(cfg.get_profile(arch)._indirect is not None,
                                "%s has no indirect pattern" % arch)
                self.assertGreaterEqual(len(indirect), 4)


class TestConditionalCallsAreBranchPoints(unittest.TestCase):
    """A predicated call is a two-way branch, not a plain call.

    `classify` tries `call` before `cond`, so a `call` pattern with an optional
    condition suffix swallows every conditional call and deletes it from the
    branch inventory. Kept consistent across ARM, PowerPC and MIPS.
    """

    def test_arm_conditional_bl_is_a_branch_point(self):
        p = cfg.get_profile("arm")
        for text in ("bleq 8010 <x>", "blne 8010 <x>", "bllt 8010 <x>",
                     "blgt 8010 <x>", "blmi 8010 <x>", "blvs 8010 <x>"):
            with self.subTest(insn=text):
                self.assertEqual(p.classify(text), cfg.COND)

    def test_arm_unconditional_bl_is_still_a_call(self):
        p = cfg.get_profile("arm")
        for text in ("bl 8010 <x>", "bl.w 8010 <x>", "blx 8010 <x>",
                     "blx r3", "blxns r3"):
            with self.subTest(insn=text):
                self.assertEqual(p.classify(text), cfg.CALL)

    def test_arm_conditional_branches_are_not_calls(self):
        """'ble'/'blt'/'bls'/'blo' are b+cc, not bl+something."""
        p = cfg.get_profile("arm")
        for text in ("ble 8010 <x>", "blt 8010 <x>", "bls 8010 <x>",
                     "blo 8010 <x>"):
            with self.subTest(insn=text):
                self.assertEqual(p.classify(text), cfg.COND)

    def test_powerpc_conditional_link_matches_arm(self):
        p = cfg.get_profile("powerpc")
        for text in ("bltl 90 <x>", "bnel 90 <x>", "beql 90 <x>"):
            with self.subTest(insn=text):
                self.assertEqual(p.classify(text), cfg.COND)

    def test_a_conditional_call_still_terminates_its_block(self):
        """COND buys BOTH properties: branch point AND block terminator."""
        self.assertIn(cfg.COND, cfg.TERMINATORS)

    def test_conditional_call_produces_a_branch_point(self):
        text = "\n".join([
            "", "a.elf:     file format elf32-littlearm", "",
            "Disassembly of section .text:", "",
            "00008000 <main>:",
            "    8000:\te3a01002 \tmov\tr1, #2",
            "    8004:\t0b000002 \tbleq\t8014 <helper>",
            "    8008:\te3a01003 \tmov\tr1, #3",
            "    800c:\te12fff1e \tbx\tlr",
            "    8010:\te1a00000 \tnop",
            "",
            "00008014 <helper>:",
            "    8014:\te12fff1e \tbx\tlr",
        ]) + "\n"
        graph = cfg.analyze(text, cfg.get_profile("arm"))
        self.assertEqual([(bp.addr, bp.mnemonic, bp.taken, bp.fallthrough)
                          for bp in graph.branch_points],
                         [(0x8004, "bleq", 0x8014, 0x8008)])


class TestSparcBranchNever(unittest.TestCase):
    """'bn' must not terminate a block or invent a successor."""

    def test_branch_never_is_not_a_terminator(self):
        p = cfg.get_profile("sparc")
        for text in ("bn 10024 <x>", "bn,a 10024 <x>", "fbn 10024 <x>",
                     "cbn 10024 <x>"):
            with self.subTest(insn=text):
                self.assertEqual(p.classify(text), cfg.OTHER)
                self.assertNotIn(p.classify(text), cfg.TERMINATORS)

    def test_branch_never_does_not_split_a_block(self):
        text = "\n".join([
            "", "a.elf:     file format elf32-sparc", "",
            "Disassembly of section .text:", "",
            "00010000 <main>:",
            "   10000:\t80 00 00 00 \tadd  %g0, %g0, %g0",
            "   10004:\t00 80 00 04 \tbn  10014 <main+0x14>",
            "   10008:\t01 00 00 00 \tnop",
            "   1000c:\t80 00 00 00 \tadd  %g0, %g0, %g0",
            "   10010:\t81 c3 e0 08 \tretl",
            "   10014:\t01 00 00 00 \tnop",
        ]) + "\n"
        graph = cfg.analyze(text, cfg.get_profile("sparc"))
        # One straight-line run: 'bn' neither ends a block nor makes 0x10014 a
        # leader (nothing ever branches there).
        self.assertEqual([(b.start, b.end) for b in graph.blocks],
                         [(0x10000, 0x10014)])
        self.assertEqual(graph.branch_points, [])

    def test_bare_cb_is_unconditional_not_conditional(self):
        p = cfg.get_profile("sparc")
        self.assertEqual(p.classify("cb 10024 <x>"), cfg.UNCOND)
        self.assertEqual(p.classify("cba 10024 <x>"), cfg.UNCOND)


if __name__ == "__main__":
    unittest.main()
