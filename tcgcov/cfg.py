"""Static branch inventory: `objdump -d` text -> basic blocks + branch points.

This is the DENOMINATOR for branch coverage. Line coverage only needs the set of
instruction addresses (see coverable.py); branch coverage additionally needs to
know, for every conditional branch, its two possible successors -- so that a
branch whose "else" side never ran shows up as half-covered instead of being
invisible.

We reconstruct just enough control-flow graph from the disassembly to answer:

  * where do basic blocks start and end,
  * for a conditional branch at address A, what is the TAKEN target T and what
    is the FALL-THROUGH address F,
  * which instructions are unconditional branches / calls / returns (not branch
    coverage points themselves, but they terminate blocks, so getting them wrong
    corrupts the block map).

Delay slots
-----------
On MicroBlaze, MIPS and SPARC the instruction after a branch executes BEFORE the
transfer happens. Two consequences, both handled here via the arch profile:

  * the fall-through address F is the instruction after the DELAY SLOT (A+8 on a
    4-byte-insn machine), not A+4;
  * the delay-slot instruction belongs to the branch's basic block, so the last
    instruction of a QEMU translation block -- which is what the plugin records
    as an edge's source -- is the delay slot, not the branch. Matching therefore
    accepts any source address at-or-after the branch inside its block.

Arch profiles
-------------
Branch detection is per-ISA. ARCH_PROFILES maps an arch name to a set of regexes
matched (with re.match, case-insensitively) against the normalized instruction
text "<mnemonic> <operands>". Classification order is return, call, conditional,
unconditional, so precise patterns win over generic ones.

Conditional calls
-----------------
Several ISAs can predicate a call: ARM `bleq`, PowerPC `bltl`, MIPS `bltzal`.
Such an instruction is BOTH a two-way branch point and a block terminator, and
`call` is tried before `conditional`, so a `call` pattern that swallows them
deletes them from the branch inventory. Every profile therefore classifies them
COND, which supplies both properties: COND is in TERMINATORS, and CFG builds a
BranchPoint only for COND. The `call` patterns are written to match the
UNCONDITIONAL forms alone.

Users can add an arch without touching the package: write a JSON file and pass
`--arch-profile FILE` (see load_profile_file() for the schema). An arch with no
profile is NOT guessed at -- callers get UNSUPPORTED_PROFILE, whose contract is
to report "branch coverage unsupported for this arch" rather than emit numbers
that are silently wrong.
"""

import bisect
import json
import re
import subprocess

# --- objdump text shapes ----------------------------------------------------

# A disassembly line, in BOTH layouts the two objdumps emit. The separator
# after the colon differs and that difference is load-bearing:
#
#   GNU objdump : "90000000:\tb00097ff \timm\t-26625"      <- TAB
#   llvm-objdump: "       0: 52800028     \tmov\tw8, #0x1" <- SPACE
#
# Accepting only the tab silently drops every llvm-objdump instruction, which
# makes branch coverage vanish while line coverage still works. This regex is
# the single definition used by cfg.py AND coverable.py (via match_insn_line)
# so the two producers cannot disagree about what an instruction line is.
# "  4000d3:\t74 05                \tje     4000da <foo+0x1a>"
INSN_RE = re.compile(r"^[ ]*([0-9a-fA-F]+):[ \t](.*)$")
# "0000000000400470 <main>:"
SYMBOL_RE = re.compile(r"^([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
# "foo.elf:     file format elf32-microblazeel"
FILE_FORMAT_RE = re.compile(r"file format\s+(\S+)")
SECTION_RE = re.compile(r"^Disassembly of section (\S+):")
# Raw-bytes column: "74 05" / "b0000000" / "0000 1234".
RAW_BYTES_RE = re.compile(r"^(?:[0-9a-fA-F]{2,8} ?)+$")
# A raw-byte continuation line: GNU objdump wraps an over-long instruction's
# bytes onto extra address-prefixed lines that carry no mnemonic. Those bytes
# always print as 2-hex-digit groups, which is what tells them apart from a
# lone operand-less mnemonic.
RAW_CONT_RE = re.compile(r"^(?:[0-9a-fA-F]{2} ?)+$")
# A resolved branch target: hex address immediately followed by <sym+0xoff>.
SYMBOLIC_TARGET_RE = re.compile(r"(?:0x)?([0-9a-fA-F]+)\s*<[^>\n]*>")
# MicroBlaze prints the raw displacement as the operand and the resolved target
# as a trailing "// <hex>" comment (with "<sym+0xoff>" appended when a symbol
# sits exactly on it): "beqid r6, 16\t\t// 9000009c".
COMMENT_TARGET_RE = re.compile(r"//\s*(?:0x)?([0-9a-fA-F]+)\b")
# An explicit 0x address operand (used when the ELF has no symbols to print).
HEX_TARGET_RE = re.compile(r"0x([0-9a-fA-F]+)")
# Trailing signed decimal operand (MicroBlaze prints PC-relative displacements).
# The lookbehind rejects a register operand: in "beq r3, r4" the trailing token
# is the register r4, NOT a displacement of 4.
DECIMAL_TAIL_RE = re.compile(r"(?<![\w.$%])(-?\d+)\s*$")
# A BARE trailing hex operand, with no "0x" and no "<sym>" after it. This is how
# GNU objdump prints every direct branch in a STRIPPED binary -- the "<sym+off>"
# suffix is appended only when a symbol covers the target address:
#
#   b.lt 4008b0 <f+0x20>   symbols present
#   b.lt 4008b0            stripped -- same instruction, same target
#
# Without this the whole branch inventory of a stripped ELF parses as "indirect"
# and is excluded from coverage, i.e. the denominator silently becomes zero.
# It is the LOWEST-trust source precisely because a bare number is ambiguous
# (MicroBlaze's "bri 12" is a displacement, ARM's "movw r0, 4660" an immediate),
# so a value from here is accepted only after it is checked against the set of
# real instruction addresses -- see _parse_target's `valid_addrs`.
# The lookbehind rejects anything glued to a register/immediate/sign prefix
# ("r3", "$8", "#16", "-4"), which a target operand never has.
BARE_HEX_TARGET_RE = re.compile(r"(?<![\w.$%#+-])([0-9a-fA-F]+)\s*$")

# Instruction kinds.
OTHER, COND, UNCOND, CALL, RET = "other", "cond", "uncond", "call", "ret"
TERMINATORS = (COND, UNCOND, CALL, RET)


class ArchProfile(object):
    """Regex-driven branch classifier for one ISA.

    Every pattern is matched with re.match (anchored at the start,
    case-insensitive) against "<mnemonic> <operands>", so a pattern can key off
    operands where the mnemonic alone is ambiguous -- e.g. MIPS `jr ra` is a
    return while `jr v0` is an indirect jump.
    """

    def __init__(self, name, conditional="", unconditional="", call="",
                 ret="", has_delay_slot=False, delay_slot="", insn_size=4,
                 pcrel_operand=False, comment_target=False, indirect="",
                 absolute="", aliases=(), supported=True, notes=""):
        self.name = name
        self.has_delay_slot = bool(has_delay_slot)
        self.insn_size = int(insn_size)
        self.pcrel_operand = bool(pcrel_operand)
        self.comment_target = bool(comment_target)
        self.aliases = tuple(aliases)
        self.supported = bool(supported)
        self.notes = notes
        self._cond = self._compile(conditional)
        self._uncond = self._compile(unconditional)
        self._call = self._compile(call)
        self._ret = self._compile(ret)
        # When set, only instructions matching this have a delay slot (needed by
        # MicroBlaze, where only the 'd'-suffixed branch forms delay).
        self._delay = self._compile(delay_slot)
        # When set, a match means the transfer target is a register/memory
        # operand, so no static target exists no matter what the operands look
        # like (x86's 'jmp *0x10(%rax)' would otherwise "parse" as 0x10).
        self._indirect = self._compile(indirect)
        # pcrel_operand is an ARCHITECTURE-wide default, but on most ISAs that
        # have PC-relative branches at all, a handful of mnemonics take an
        # ABSOLUTE operand instead. This regex names those exceptions, so the
        # displacement is used as-is rather than added to the PC.
        self._absolute = self._compile(absolute)

    @staticmethod
    def _compile(pattern):
        return re.compile(pattern, re.IGNORECASE) if pattern else None

    def classify(self, text):
        """Return OTHER/COND/UNCOND/CALL/RET for one instruction's text."""
        for rx, kind in ((self._ret, RET), (self._call, CALL),
                         (self._cond, COND), (self._uncond, UNCOND)):
            if rx is not None and rx.match(text):
                return kind
        return OTHER

    def is_indirect(self, text):
        """True if the transfer target is a register/memory operand."""
        return self._indirect is not None and bool(self._indirect.match(text))

    def is_absolute(self, text):
        """True if this mnemonic's numeric operand is an ABSOLUTE address.

        Only consulted for profiles with pcrel_operand set; it names the
        per-mnemonic exceptions to that arch-wide default.
        """
        return self._absolute is not None and bool(self._absolute.match(text))

    def delays(self, kind, text):
        """True if this instruction is followed by an executed delay slot."""
        if not self.has_delay_slot or kind == OTHER:
            return False
        if self._delay is not None:
            return bool(self._delay.match(text))
        return True


# --- shipped arch profiles --------------------------------------------------
#
# Mnemonics below are the ones GNU objdump actually prints for each ISA (see the
# per-profile note for the source). Patterns are deliberately explicit rather
# than clever: a missed branch understates the denominator, and a mis-classified
# non-branch corrupts the block map.

ARCH_PROFILES = {}


def register_profile(profile):
    """Add/replace a profile and its aliases in the global table."""
    ARCH_PROFILES[profile.name] = profile
    for alias in profile.aliases:
        ARCH_PROFILES[alias] = profile
    return profile


# The generic fallback. It classifies nothing; branches.py checks .supported and
# refuses to emit branch data for it.
UNSUPPORTED_PROFILE = ArchProfile(
    "generic", supported=False,
    notes="no branch mnemonics known for this arch; pass --arch-profile FILE")
register_profile(UNSUPPORTED_PROFILE)


def _p(*a, **kw):
    return register_profile(ArchProfile(*a, **kw))


# MicroBlaze -- from the binutils opcode table (opcodes/microblaze-opc.h), which
# is what objdump actually prints, cross-checked against UG984 chapter 5 and the
# LLVM MicroBlazeInstrBranch*.td files. There are no absolute conditional-branch
# forms; the link (call) forms exist ONLY with a delay slot; every 'd'-suffixed
# form delays and no other form does. objdump prints the raw displacement as the
# operand and the resolved target only as a trailing "// <hex>" comment.
#
# ABSOLUTE vs PC-RELATIVE. Every immediate-operand branch carries an explicit
# flag in the opcode table, and the two groups are NOT interchangeable:
#
#   microblaze-opc.h:223-225  bri / brid / brlid        INST_PC_OFFSET
#   microblaze-opc.h:226-229  brai / braid / bralid /
#                             brki                      INST_NO_OFFSET
#   microblaze-opc.h:230-241  beqi..bgeid (all 12)      INST_PC_OFFSET
#
# So `brai 256` goes to 0x100, NOT to pc+256. Adding the PC to an absolute
# operand fabricates an address that can easily land on some unrelated real
# instruction, and build_blocks then splits a block there -- a corrupt block
# map, reported with no error. Hence the per-mnemonic `absolute` regex below.
_p("microblaze",
   aliases=("microblazeel", "microblazebe"),
   conditional=r"^(beqid|beqi|beqd|beq|bneid|bnei|bned|bne|bltid|blti|bltd|blt"
               r"|bleid|blei|bled|ble|bgtid|bgti|bgtd|bgt|bgeid|bgei|bged|bge)\b",
   unconditional=r"^(braid|brai|brad|brid|bra|brd|bri|br)\b",
   call=r"^(bralid|brald|brlid|brld|brki|brk)\b",
   ret=r"^(rtsd|rtid|rtbd|rted)\b",
   delay_slot=r"^(bralid|brald|brlid|brld|braid|brad|brid|brd"
              r"|beqid|beqd|bneid|bned|bltid|bltd|bleid|bled|bgtid|bgtd"
              r"|bgeid|bged|rtsd|rtid|rtbd|rted)\b",
   # The register-target forms (no trailing 'i' before the optional 'd') take
   # their destination from a register: "beq r3, r4" branches to r4, and the
   # trailing 4 is emphatically not a displacement.
   indirect=r"^(beqd?|bned?|bltd?|bled?|bgtd?|bged?|brd?|brad?|brld?|brald?)"
            r"(?=\s|$)",
   # INST_NO_OFFSET immediate forms (microblaze-opc.h:226-229): the operand IS
   # the target address. Everything else on this arch is INST_PC_OFFSET.
   absolute=r"^(bralid|braid|brai|brki)\b",
   has_delay_slot=True, insn_size=4,
   comment_target=True, pcrel_operand=True,
   notes="brk/brki (break/trap) are grouped with calls: they transfer control "
         "and end a translation block, but never delay. The register-target "
         "forms (br/brd/bra/brad/brld/brald) are indirect and excluded. "
         "brai/braid/bralid/brki take ABSOLUTE operands; every other "
         "immediate form (bri/brid/brlid and all 12 conditional forms) is "
         "PC-relative.")

# RISC-V rv32/rv64 -- binutils prints the standard aliases by default (beqz,
# bnez, blez, bgez, bltz, bgtz, j, jr, jal, jalr, ret) and the compressed
# encodings under those same names; 'c.'-prefixed spellings only appear with
# -M no-aliases, so both are accepted. ble/bgt/bleu/bgtu are assembler-only and
# never disassembled, but cost nothing to recognize. No delay slots.
_p("riscv",
   aliases=("riscv32", "riscv64", "rv32", "rv64", "riscv:rv32", "riscv:rv64",
            "littleriscv", "bigriscv"),
   conditional=r"^(c\.)?(beqz|bnez|blez|bgez|bltz|bgtz|beq|bne|bltu|bgeu|blt"
               r"|bge|bgtu|bleu|bgt|ble)\b",
   unconditional=r"^(c\.)?(jr|j)\b",
   call=r"^(c\.)?(jalr|jal|call|tail)\b",
   ret=r"^(c\.)?ret\b",
   insn_size=4,
   notes="compressed 2-byte forms are handled: instruction sizes come from "
         "address deltas, so a mixed RVC/RV32I stream is fine.")

# ARM A32/T32 -- objdump prints the condition suffix on the mnemonic (and maps
# 'al' to the empty string, so a bare 'b' is unconditional). Thumb adds the
# .n/.w width suffix and cbz/cbnz. objdump prints cs/cc, never hs/lo, but both
# are accepted.
#
# CONDITIONAL CALLS. 'bleq/blne/bllt/...' are BL under a condition: they are
# two-way branch points that happen to link. Classifying them as calls (which
# the exact-condition alternation used to do, because classify() tries `call`
# before `cond`) kept them out of the branch inventory entirely, so every
# if-converted call in A32 code was missing from the denominator. They are
# classified COND instead, which gives BOTH properties this instruction needs:
# COND is in TERMINATORS so the block still ends here, and CFG builds a
# BranchPoint for COND so both outcomes are counted. This is exactly how the
# PowerPC profile already treats its conditional-and-link forms (bltl, bnel),
# so the two arches now agree. Only the unconditional 'bl/blx/blxns' remain
# CALL; the \b after the bare mnemonic is what keeps 'ble' (b+le, a plain
# conditional branch) from matching 'bl'.
#
# Low-overhead loops (Armv8.1-M, arm-dis.c:4410-4418): 'le'/'letp' are the
# loop-END back-edge (decrement LR, branch if the loop is not finished) and
# 'wls'/'wlstp' the loop-START guard (branch past the loop when the count is
# zero). All four are genuine conditional branches with a printed target.
# 'dls'/'dlstp' (arm-dis.c:4420-4422) are NOT branches -- they only initialize
# LR -- and are deliberately left as OTHER.
_ARM_CC = r"(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)"
_p("arm",
   aliases=("armv7", "armel", "armhf", "thumb", "littlearm", "bigarm"),
   conditional=r"^(b" + _ARM_CC + r"|bl" + _ARM_CC + r"|blx" + _ARM_CC +
               r"|cbn?z|letp|le|wlstp|wls)(\.[nw])?\b",
   # tbb/tbh (arm-dis.c:4563-4565) are Thumb table branches: unconditional
   # register-indirect jumps. They MUST terminate the block -- the inline jump
   # table sits in the bytes right after them, and objdump happily disassembles
   # those bytes as instructions, so a tbb that does not end its block splices
   # table data into the block map.
   unconditional=r"^(bal|b|bx|bxj|bxns|tbb|tbh)(\.[nw])?\b"
                 r"|^movs?" + _ARM_CC + r"?(\.[nw])?\s+pc\s*,",
   call=r"^(bl|blx|blxns)(\.[nw])?\b",
   # ARM has no return instruction: returning is 'bx lr', a pop/ldm that writes
   # pc, or a move to pc. Missing one only merges two blocks, but function
   # symbols are block leaders as well, which limits the damage.
   ret=r"^(bx" + _ARM_CC + r"?(\.[nw])?\s+lr\b"
       r"|pop" + _ARM_CC + r"?(\.[nw])?\s*\{[^}]*\bpc\b"
       r"|ldm[\w.]*\s+\w+!?,\s*\{[^}]*\bpc\b"
       r"|movs?" + _ARM_CC + r"?(\.[nw])?\s+pc,\s*lr\b"
       r"|ldr" + _ARM_CC + r"?(\.[nw])?\s+pc,)",
   # Register-target transfers, whose operands are never an address. 'blx'
   # splits on the first operand character: objdump prints a register for the
   # indirect form ("blx r3") and a digit for the direct one ("blx 8010 <f>").
   indirect=r"^(bx|bxj|bxns|tbb|tbh)" + _ARM_CC + r"?(\.[nw])?\b"
            r"|^blx" + _ARM_CC + r"?(\.[nw])?\s+[a-z]"
            r"|^(movs?|ldr)[\w.]*\s+pc\s*,",
   insn_size=4,
   notes="'ble/blt/bls' are conditional branches; 'bleq/blne/...' are "
         "CONDITIONAL CALLS and are classified COND so they are branch points "
         "as well as block terminators (same as PowerPC 'bltl'). v8.1-M "
         "'le/letp/wls/wlstp' are conditional branches; 'bf/bfl/bfx/bfcsel' "
         "(arm-dis.c:4425-4433) are not modeled.")

# AArch64 -- b.<cond> (and the v8.8 bc.<cond>), cbz/cbnz, tbz/tbnz and the v9.6
# CMPBR family are the conditional branches; objdump appends a "// b.hs" alias
# comment to some of them, which is why comment_target is off here.
_p("aarch64",
   aliases=("arm64", "littleaarch64", "bigaarch64"),
   conditional=r"^(bc?\.\w+|cbn?z|tbn?z"
               r"|cb[bh]?(eq|ne|gt|ge|hi|hs|lt|le|lo|ls))\b",
   unconditional=r"^(b|br|braa|brab|braaz|brabz)\b",
   call=r"^(bl|blr|blraa|blrab|blraaz|blrabz)\b",
   ret=r"^(ret|retaa|retab|eret\w*)\b",
   insn_size=4)

# x86 / x86-64, AT&T syntax as objdump prints it. binutils emits exactly 16 Jcc
# spellings (jo jno jb jae je jne jbe ja js jns jp jnp jl jge jle jg) plus
# jcxz/jecxz/jrcxz and loop/loope/loopne; the assembler-only synonyms (jz, jnz,
# jc, ...) are accepted anyway so that llvm-objdump output also works. Prefixes
# print as separate leading words (bnd, notrack, data16, rex.W, repz, cs/ds
# branch hints), and the 'q' suffix (retq/callq/jmpq) appears only with
# -M suffix or from llvm-objdump -- both spellings are accepted.
_X86_PREFIX = (r"(?:(?:bnd|notrack|data16|addr32|lock|cs|ds|es|ss|xacquire"
               r"|xrelease|rep|repe|repz|repne|repnz|rex[\w.]*)\s+)*")
_X86_CC = (r"(o|no|b|ae|e|ne|be|a|s|ns|p|np|l|ge|le|g|z|nz|c|nc|na|nae|nb|nbe"
           r"|ng|nge|nl|nle|pe|po|cxz|ecxz|rcxz)")
_X86_KW = dict(
    conditional=_X86_PREFIX + r"(j" + _X86_CC + r"|loopn?[ez]?)\b",
    # jmpabs (i386-dis.c:14640) is the APX 64-bit absolute direct jump. It is
    # printed as "jmpabs $0x...", i.e. WITHOUT the '*' that marks every other
    # absolute-looking x86 transfer, so it is a direct unconditional branch --
    # and, being unconditional, it has to end its block.
    unconditional=_X86_PREFIX + r"(jmpabs|jmp|jmpq|jmpl|jmpw|ljmp\w*)\b",
    call=_X86_PREFIX + r"(call|callq|calll|callw|lcall\w*)\b",
    ret=_X86_PREFIX + r"(ret|retq|retl|retw|retf\w*|lret\w*|iret\w*"
                      r"|sysret\w*|sysexit)\b",
    # AT&T marks every indirect transfer with a leading '*'. Without this the
    # displacement in `jmp *0x10(%rax)` would parse as a target.
    indirect=_X86_PREFIX + r"\S+\s+\*",
    insn_size=1)
_p("x86_64", aliases=("x86-64", "amd64", "i386:x86-64"), **_X86_KW)
_p("x86", aliases=("i386", "i486", "i586", "i686"), **_X86_KW)

# MIPS -- all classic branches and jumps have a delay slot; the MIPS32r6
# "compact" forms have none and are exactly the mnemonics ending in 'c', which
# is what the delay_slot lookahead encodes. bltzal/bgezal(l) branch AND link;
# they are listed as conditional because they are genuine branch points (the
# link is a side effect), and classification checks calls before conditionals.
#
# Every mnemonic below carries CBD (INSN_COND_BRANCH_DELAY, mips-opc.c:224) or
# NODS (INSN_NO_DELAY_SLOT, mips-opc.c:228) in the opcode table. The additions:
#
#   mips-opc.c:729,734    bc1eqz / bc1nez     CBD -- the ONLY FP conditional
#                                             branches in MIPS32r6, which
#                                             replaced bc1t/bc1f wholesale, so
#                                             missing them loses every FP
#                                             branch in r6 code
#   mips-opc.c:3366,3371  bc2eqz / bc2nez     CBD -- coprocessor-2 equivalent
#   mips-opc.c:2146-2148  bposge32 / bposge64 CBD, bposge32c NODS -- DSP ASE
#   mips-opc.c:718-723    bbit0 / bbit1 /     CBD -- Octeon branch-on-bit
#                         bbit032 / bbit132
_p("mips",
   aliases=("mips64", "mipsel", "mipsisa32", "mipsisa64", "tradlittlemips",
            "tradbigmips"),
   conditional=r"^(beqzl|bnezl|beql|bnel|blezl|bgtzl|bltzl|bgezl"
               r"|bltzall|bgezall|bltzalc?|bgezalc?|blezalc|bgtzalc"
               r"|beqzalc|bnezalc"
               r"|beqzc?|bnezc?|beqc?|bnec?|blezc?|bgtzc?|bltzc?|bgezc?"
               r"|bltuc|bgeuc|bltc|bgec|bovc|bnvc"
               r"|bc[0-3][tf]l?|bc[12](eqz|nez)"
               r"|bposge(32c?|64)|bbit[01](32)?"
               r"|bn?z\.[bhwvd])\b",
   unconditional=r"^(bc|b|j|jr|jr\.hb|jrc)\b",
   call=r"^(jalx?|jalrc?|jalr\.hb|balc?|jialc)\b",
   ret=r"^(jr(\.hb)?\s+\$?(ra|31)\b|jrc\s+\$?ra\b|jic\s+\$?ra\b)",
   has_delay_slot=True,
   delay_slot=r"^(?!\w+c\b)\w+",
   insn_size=4,
   notes="delay_slot excludes the r6 compact branches (mnemonics ending in "
         "'c'). The 'likely' (*l) forms nullify the delay slot when not taken, "
         "which does not change the fall-through ADDRESS.")

# PowerPC -- objdump prints the extended mnemonics (blt bgt beq bso bge ble bne
# bns, bdnz/bdz, bt/bf, raw bc) with the suffixes glued on: 'l' (link), 'a'
# (absolute), 'lr'/'ctr'/'tar' (indirect target) and '+'/'-' prediction hints,
# e.g. "ble- cr1,90 <apfour+0x14>". The CR field prints FIRST, which is why
# target parsing takes the LAST hex operand. blr/bctr take no operand at all --
# their target is implicit, so they are correctly reported as having none.
_PPC_CC = r"(eq|ne|lt|gt|le|ge|so|ns|un|nu|nl|ng)"
_p("powerpc",
   aliases=("ppc", "ppc64", "powerpc64", "powerpcle", "ppc64le", "ppc64el"),
   conditional=r"^(b(dnz|dz)[tf]?|b" + _PPC_CC + r"|b[tf]|bc)"
               r"(lr|ctr|tar)?l?a?[+-]?\b",
   unconditional=r"^(b|ba|bctr|btar)[+-]?\b",
   call=r"^(bl|bla|bctrl|bclrl|bcctrl|btarl|bctarl)\b",
   ret=r"^(blr|bclr)l?[+-]?\b",
   insn_size=4,
   notes="conditional returns (beqlr, bdnzlr, ...) are conditional branches "
         "with an implicit LR target: branch points with no static target, so "
         "they are excluded from branch coverage rather than reported.")

# SPARC -- objdump prints the non-alias spellings only: the unconditional branch
# is 'b' (never 'ba'), and 'be/bg/bl/...' rather than 'beq/bgt/blt'. Suffixes
# are ',a' (annul) and ',pn'; GNU objdump never prints ',pt' (llvm-objdump
# does, so it is accepted). Operands are preceded by a space, giving the
# characteristic double space after the mnemonic.
#
# BRANCH NEVER. 'bn' (sparc-opc.c:1379, condition CONDN), 'fbn' and 'cbn'
# (sparc-opc.c:1697) encode the never-true condition: they NEVER transfer to
# the label they print. binutils files bn under F_CONDBR and fbn/cbn under
# F_UNBR, but neither classification is usable here -- calling them
# unconditional made build_blocks split a block at a target that is never
# reached, and calling them conditional would add a branch point whose taken
# side is unreachable by construction, i.e. a permanently half-covered branch.
# They fall through, always, so they are OTHER: not a terminator, not a branch
# point. (Caveat: 'bn,a' annuls its delay slot, so the following instruction is
# skipped. That is a control-flow effect this CFG has no way to express; it
# affects which instruction executes, not the branch denominator.)
#
# COPROCESSOR BRANCHES. The 'cb*' spellings are real -- they are the third
# expansion of the CONDFC macro (sparc-opc.c:1674-1706), paired one-for-one
# with the 'fb*' names. Bare 'cb' DOES exist (sparc-opc.c:1688, paired with
# 'fb') but it is F_UNBR, branch-ALWAYS, so making the suffix group optional in
# the conditional pattern was wrong in both directions: it classified the
# unconditional 'cb'/'cba' as conditional, while the real conditional spellings
# 'cb02', 'cb023', 'cb013' and 'cb12' were absent and fell through to OTHER.
# The 14 condition spellings below are enumerated from sparc-opc.c:1690-1706;
# the letter forms (cbe/cbf/cbr/... , sparc-opc.c:1953-1967) are the sparclet
# coprocessor branches, F_CONDBR, which share the same opcode space and are
# what objdump prints for a sparclet target.
_SPARC_SUFFIX = r"(,a)?(,pt|,pn)?"
_SPARC_CB = (r"cb(012|013|023|123|01|02|03|12|13|23|0|1|2|3"
             r"|n(efr|ef|er|fr|e|f|r)|efr|ef|er|fr|e|f|r)")
_p("sparc",
   aliases=("sparc64", "sparcv9", "sparclite", "sparc:v9"),
   conditional=r"^(bne|bneg|be|bg|bge|bgu|ble|bleu|bl|bcc|bcs|bpos|bvc|bvs"
               r"|bz|bnz|blu"
               r"|fb(ne|e|g|ge|lg|le|l|ue|ug|uge|ule|ul|u|o)"
               r"|" + _SPARC_CB +
               r"|br[zn]|brnz|brlez|brlz|brgz|brgez"
               r"|c[wx]b(ne|e|g|le|ge|l|gu|leu|cc|cs|neg|pos|vc|vs))"
               + _SPARC_SUFFIX + r"\b",
   # 'bn'/'fbn'/'cbn' are deliberately absent: see BRANCH NEVER above.
   unconditional=r"^(ba|b|fba|fb|cba|cb|jmpl|jmp)" + _SPARC_SUFFIX + r"\b",
   call=r"^call\b",
   ret=r"^(retl|return|rett|ret)\b",
   has_delay_slot=True,
   # Everything delays except v9 'return' and the CBcond compare-and-branch
   # family (cwb*/cxb*).
   delay_slot=r"^(?!return\b|c[wx]b)\w+",
   insn_size=4,
   notes="'bn'/'fbn'/'cbn' (branch never) are OTHER: they never transfer, so "
         "they neither end a block nor form a branch point. Bare 'cb'/'cba' "
         "are branch-ALWAYS (sparc-opc.c:1688-1689), not conditional.")


# --- lookup -----------------------------------------------------------------

# BFD target names as printed in objdump's "file format" line -> profile name.
BFD_TO_ARCH = (
    ("microblaze", "microblaze"),
    ("riscv", "riscv"),
    ("aarch64", "aarch64"),
    ("arm", "arm"),
    ("x86-64", "x86_64"),
    ("i386", "x86"),
    ("mips", "mips"),
    ("powerpc", "powerpc"),
    ("ppc", "powerpc"),
    ("sparc", "sparc"),
)

# Free-form arch names (QEMU target_name, --arch flags, `objdump -f`
# "architecture:" values) -> profile name.
ARCH_ALIASES = (
    ("microblaze", "microblaze"),
    ("riscv", "riscv"),
    ("rv32", "riscv"),
    ("rv64", "riscv"),
    ("aarch64", "aarch64"),
    ("arm64", "aarch64"),
    ("arm", "arm"),
    ("thumb", "arm"),
    ("x86_64", "x86_64"),
    ("x86-64", "x86_64"),
    ("amd64", "x86_64"),
    ("i386", "x86"),
    ("i486", "x86"),
    ("i586", "x86"),
    ("i686", "x86"),
    ("x86", "x86"),
    ("mips", "mips"),
    ("powerpc", "powerpc"),
    ("ppc", "powerpc"),
    ("sparc", "sparc"),
)


def normalize_arch(name):
    """Map a free-form arch/BFD name onto a profile name, or '' if unknown."""
    if not name:
        return ""
    low = name.lower()
    if low in ARCH_PROFILES:
        return ARCH_PROFILES[low].name
    for needle, arch in ARCH_ALIASES:
        if needle in low:
            return arch
    return ""


def detect_arch(objdump_text):
    """Infer the arch from objdump's 'file format elfNN-xxx' banner line."""
    m = FILE_FORMAT_RE.search(objdump_text)
    if not m:
        return ""
    fmt = m.group(1).lower()
    for needle, arch in BFD_TO_ARCH:
        if needle in fmt:
            return arch
    return ""


def get_profile(name):
    """Return the profile for an arch name, or UNSUPPORTED_PROFILE."""
    return ARCH_PROFILES.get(normalize_arch(name), UNSUPPORTED_PROFILE)


def load_profile_file(path):
    """Load user arch profiles from JSON and register them.

    Schema -- either one profile object, or a {"<name>": {...}} mapping, or
    {"profiles": [ ... ]}. Recognized keys (all optional but for `name`):

        name            profile name, e.g. "mycpu"
        aliases         [str] extra names/BFD substrings that select it
        conditional     regex for conditional branches
        unconditional   regex for unconditional branches
        call            regex for calls
        return          regex for returns
        delay_slot      regex selecting the forms that HAVE a delay slot
                        (omit when every branch delays)
        has_delay_slot  bool, arch has architectural delay slots
        insn_size       default instruction size in bytes (fall-through hint)
        pcrel_operand   bool, a trailing decimal operand is a PC-relative
                        displacement (used only when objdump printed no
                        resolved target)
        absolute        regex naming the mnemonics that are the EXCEPTION to
                        pcrel_operand -- their operand is already the target
                        address and the PC must not be added (MicroBlaze
                        brai/braid/bralid/brki)
        comment_target  bool, the resolved target may appear in a trailing
                        "// <hex>" comment (MicroBlaze does this)
        indirect        regex marking register/memory-target transfers, whose
                        operands must never be read as a target

    Every regex is matched with re.match against "<mnemonic> <operands>",
    case-insensitively. Returns the list of registered profile names.
    """
    with open(path) as f:
        data = json.load(f)
    if "conditional" in data or "name" in data:
        entries = [data]
    elif "profiles" in data:
        entries = list(data["profiles"])
    else:
        entries = []
        for name, body in data.items():
            body = dict(body)
            body.setdefault("name", name)
            entries.append(body)

    names = []
    for body in entries:
        body = dict(body)
        name = body.pop("name", None)
        if not name:
            raise ValueError(f"{path}: profile entry without a name")
        body["ret"] = body.pop("return", body.pop("ret", ""))
        allowed = ("conditional", "unconditional", "call", "ret",
                   "has_delay_slot", "delay_slot", "insn_size",
                   "pcrel_operand", "comment_target", "indirect", "absolute",
                   "aliases", "notes")
        unknown = [k for k in body if k not in allowed]
        if unknown:
            raise ValueError(f"{path}: unknown profile key(s): "
                             f"{', '.join(sorted(unknown))}")
        register_profile(ArchProfile(name, **body))
        names.append(name)
    return names


# --- disassembly parsing ----------------------------------------------------

class DisassemblyParseError(ValueError):
    """Disassembly text that yielded no instructions at all.

    A total parse failure must never look like "this binary has no branches":
    that reports a wrong number with exit status 0. It is a ValueError so the
    (OSError, ValueError) handlers callers already use catch it.
    """


def match_insn_line(line):
    """Return (address:int, rest:str) for one disassembly line, else None.

    THE shared definition of "this line is an instruction", used by both the
    branch inventory (cfg.parse_objdump) and the coverable-line inventory
    (coverable.disassemble_addresses). Keeping one implementation is the point:
    when these two disagreed, line coverage kept working while branch coverage
    silently produced an empty result.
    """
    # "beef.elf:\tfile format elf32-..." would otherwise parse as an
    # instruction at 0xbeef, because objdump prints the file name the same way.
    if FILE_FORMAT_RE.search(line):
        return None
    m = INSN_RE.match(line)
    if m is None:
        return None
    return int(m.group(1), 16), m.group(2)


class Insn(object):
    """One disassembled instruction."""

    __slots__ = ("addr", "text", "mnemonic", "kind", "target", "delay",
                 "section", "size")

    def __init__(self, addr, text, mnemonic, kind, section):
        self.addr = addr
        self.text = text
        self.mnemonic = mnemonic
        self.kind = kind
        self.section = section
        self.target = None      # resolved branch target, None if indirect
        self.delay = False      # followed by an executed delay slot
        self.size = 0

    def __repr__(self):
        return "<Insn 0x%x %s %s>" % (self.addr, self.kind, self.text)


def _is_raw_bytes_field(field):
    """True if `field` is objdump's raw-bytes column, not a mnemonic.

    Content alone is not enough: 'add', 'bad', 'dec' and PowerPC 'bc' are all
    spellable in hex, so with --no-show-raw-insn a purely textual test eats the
    mnemonic and leaves the operands behind as the "instruction". Two extra
    structural facts settle it:

      * raw bytes are WHOLE bytes, so every group has an even digit count
        ('add' and 'dec' are three);
      * every objdump pads the raw column -- binutils prints an explicit extra
        space after it, llvm-objdump pads to a fixed width -- so the field
        always ends in whitespace, whereas a mnemonic is followed directly by
        the tab that separates it from its operands.
    """
    stripped = field.strip()
    if not stripped or not RAW_BYTES_RE.match(stripped):
        return False
    if any(len(group) % 2 for group in stripped.split()):
        return False
    return field != field.rstrip()


def _instruction_text(rest):
    """Extract "<mnemonic> <operands>" from the part after 'addr:<sep>'.

    Both disassembly layouts are handled (see INSN_RE): GNU objdump puts the
    raw-bytes column between two tabs, llvm-objdump puts it after the space
    that follows the colon and before a tab, and --no-show-raw-insn omits it
    (GNU) or leaves it as blank padding (llvm-objdump). In every case the raw
    column, if present, is the FIRST tab-separated field.

    Returns "" for a raw-byte continuation line, which is not an instruction.
    """
    fields = rest.split("\t")
    if len(fields) == 1 and RAW_CONT_RE.match(fields[0].strip()):
        return ""  # continuation of the previous instruction's raw bytes
    for i, field in enumerate(fields):
        stripped = field.strip()
        if not stripped:
            continue
        if i == 0 and len(fields) > 1 and _is_raw_bytes_field(field):
            continue  # raw-bytes column
        return " ".join(f.strip() for f in fields[i:] if f.strip())
    return ""


def _parse_target(text, insn_addr, profile, prev=None, valid_addrs=None):
    """Return the resolved branch target address, or None if not statically known.

    Sources, in order of trust:

      1. "<hex> <sym+0xoff>" -- how most targets print a direct target. The LAST
         match wins because some ISAs put other operands first (PowerPC
         `beq cr7,<addr>`).
      2. An explicit 0x operand (llvm-objdump always prints one).
      3. A trailing "// <hex>" comment -- MicroBlaze prints the raw displacement
         as the operand and the resolved target only as a comment.
      4. Only for profiles that ask for it: a trailing decimal operand read as a
         displacement (MicroBlaze, where objdump omits the comment for some
         forms). PC-relative by default, but ABSOLUTE for the mnemonics the
         profile's `absolute` pattern names -- getting that split wrong
         manufactures an address out of thin air.
      5. A BARE trailing hex operand with no 0x and no <sym>, which is all a
         stripped binary gives you. Ambiguous by nature, so it is accepted only
         when it names a real instruction address -- pass `valid_addrs`.

    Anything else is a register/indirect target and returns None -- callers must
    EXCLUDE those from branch coverage rather than call them uncovered.
    """
    if profile.is_indirect(text):
        return None
    matches = SYMBOLIC_TARGET_RE.findall(text)
    if matches:
        return int(matches[-1], 16)
    hexes = HEX_TARGET_RE.findall(text)
    if hexes:
        return int(hexes[-1], 16)
    if profile.comment_target:
        comment = COMMENT_TARGET_RE.search(text)
        if comment:
            return int(comment.group(1), 16)
    if profile.pcrel_operand:
        # A preceding MicroBlaze `imm` supplies the immediate's upper 16 bits,
        # so the printed displacement alone is not the real target: refuse
        # rather than compute a wrong one. Refusing means refusing outright --
        # falling through to the bare-hex reading below would re-derive the very
        # number we just rejected, in a different base.
        if prev is not None and prev.mnemonic.lower() == "imm":
            return None
        m = DECIMAL_TAIL_RE.search(text)
        if m:
            disp = int(m.group(1))
            if profile.is_absolute(text):
                return disp & 0xFFFFFFFFFFFFFFFF
            return (insn_addr + disp) & 0xFFFFFFFFFFFFFFFF
        return None
    if valid_addrs:
        m = BARE_HEX_TARGET_RE.search(text)
        if m:
            addr = int(m.group(1), 16)
            if addr in valid_addrs:
                return addr
    return None


def parse_objdump(text, profile):
    """Parse `objdump -d` output into a list of Insn, sorted by address.

    Instruction sizes come from the address deltas of consecutive instructions
    in the same section (objdump prints them in address order); the last
    instruction of a section falls back to the profile's insn_size.

    Raises DisassemblyParseError when non-blank text produces no instructions
    at all: that is a parse failure (an unrecognized objdump layout, a
    non-disassembly file passed to --disasm), and returning an empty list makes
    it indistinguishable from "this binary genuinely has no code".
    """
    insns = []
    section = ""
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:
            section = m.group(1)
            continue
        matched = match_insn_line(line)
        if matched is None:
            continue
        addr, rest = matched
        itext = _instruction_text(rest)
        if not itext:
            continue  # continuation line of a long instruction's raw bytes
        mnemonic = itext.split(None, 1)[0]
        kind = profile.classify(itext)
        insn = Insn(addr, itext, mnemonic, kind, section)
        insn.delay = profile.delays(kind, itext)
        insns.append(insn)

    if not insns and text.strip():
        raise DisassemblyParseError(
            "no instructions found in %d lines of disassembly: the input is "
            "not `objdump -d` output, or its layout is unrecognized "
            "(expected lines like '  4000d3:\\t74 05\\tje  4000da')"
            % len(text.splitlines()))

    insns.sort(key=lambda i: i.addr)
    # The address set is what makes the bare-hex target reading (stripped
    # binaries) safe: a number that is not an instruction address is not a
    # target, whatever it looks like.
    valid_addrs = {insn.addr for insn in insns}
    for i, insn in enumerate(insns):
        nxt = insns[i + 1] if i + 1 < len(insns) else None
        if nxt is not None and nxt.section == insn.section \
                and 0 < nxt.addr - insn.addr <= 16:
            insn.size = nxt.addr - insn.addr
        else:
            insn.size = profile.insn_size
        if insn.kind in (COND, UNCOND, CALL):
            insn.target = _parse_target(insn.text, insn.addr, profile,
                                        insns[i - 1] if i else None,
                                        valid_addrs)
    return insns


def disassemble(objdump, elf):
    """Return the stdout of `objdump -d ELF` (raises on failure).

    Decoding is pinned to UTF-8 with surrogateescape rather than left to the
    locale: under LC_ALL=C (the default in most containers) Python would decode
    as ASCII and a single non-ASCII byte in a source path or symbol name would
    abort the whole run with UnicodeDecodeError.
    """
    proc = subprocess.run([objdump, "-d", elf], capture_output=True,
                          encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        raise RuntimeError(f"{objdump} failed: {proc.stderr.strip()}")
    return proc.stdout


def parse_symbols(text):
    """Return {address: symbol name} from objdump's '<addr> <name>:' headers."""
    syms = {}
    for line in text.splitlines():
        m = SYMBOL_RE.match(line)
        if m:
            syms[int(m.group(1), 16)] = m.group(2)
    return syms


# --- basic blocks and branch points -----------------------------------------

class Block(object):
    """A basic block: a straight-line run ending at a control transfer.

    On delay-slot machines the delay-slot instruction is part of the block that
    the branch terminates, because it executes before the transfer.
    """

    __slots__ = ("start", "end", "insns", "terminator")

    def __init__(self, insns):
        self.insns = insns
        self.start = insns[0].addr
        self.end = insns[-1].addr        # address of the LAST instruction
        # The terminator is the branch. On a delay-slot machine the block ends
        # with the delay slot, so the branch is the second-to-last instruction.
        self.terminator = None
        if len(insns) >= 2 and insns[-2].kind in TERMINATORS and insns[-2].delay:
            self.terminator = insns[-2]
        elif insns[-1].kind in TERMINATORS:
            self.terminator = insns[-1]

    def __repr__(self):
        return "<Block 0x%x-0x%x %s>" % (
            self.start, self.end,
            self.terminator.kind if self.terminator else "fallthrough")


class BranchPoint(object):
    """A conditional branch and its two outcomes."""

    __slots__ = ("addr", "mnemonic", "taken", "fallthrough", "block_start",
                 "block_end", "function")

    def __init__(self, addr, mnemonic, taken, fallthrough, block_start,
                 block_end):
        self.addr = addr
        self.mnemonic = mnemonic
        self.taken = taken              # None => indirect / unknown target
        self.fallthrough = fallthrough  # None => ran off the end of the dump
        self.block_start = block_start
        self.block_end = block_end
        self.function = ""

    @property
    def indirect(self):
        """True when a static target could not be determined.

        Such a branch IS a branch point but has no knowable outcomes, so it is
        excluded from branch coverage instead of being reported as uncovered.
        """
        return self.taken is None or self.fallthrough is None

    def __repr__(self):
        return "<BranchPoint 0x%x %s T=%s F=%s>" % (
            self.addr, self.mnemonic,
            "?" if self.taken is None else hex(self.taken),
            "?" if self.fallthrough is None else hex(self.fallthrough))


def _fallthrough(insns, index):
    """Address executed when the branch at `insns[index]` is NOT taken.

    With a delay slot that is the instruction after the delay slot, so it skips
    one extra instruction. Returns None if the dump ends first (a branch at the
    very end of a section has no observable fall-through).
    """
    branch = insns[index]
    skip = 2 if branch.delay else 1
    nxt = index + skip
    if nxt < len(insns) and insns[nxt].section == branch.section:
        return insns[nxt].addr
    # The dump (or the section) ends right after the branch: synthesize the
    # address from instruction sizes rather than dropping the branch.
    if not branch.delay:
        return branch.addr + branch.size
    if index + 1 < len(insns) and insns[index + 1].section == branch.section:
        slot = insns[index + 1]
        return slot.addr + slot.size
    return None  # delay slot itself is missing: the dump is truncated


def build_blocks(insns, extra_leaders=()):
    """Split an instruction list into basic blocks.

    Leaders are: the first instruction of each section, every branch target that
    lands on a known instruction, and the instruction following any control
    transfer (after its delay slot). A block also ends at a section change.

    A delay-slot instruction is never a leader even if something appears to
    branch to it: it is architecturally part of its branch's block, and splitting
    there would orphan the very instruction the plugin records as an edge source.
    """
    if not insns:
        return []
    addr_index = {insn.addr: i for i, insn in enumerate(insns)}
    delay_slots = set()
    for i, insn in enumerate(insns):
        if insn.delay and i + 1 < len(insns) \
                and insns[i + 1].section == insn.section:
            delay_slots.add(i + 1)

    leaders = {0}
    for addr in extra_leaders:            # e.g. function symbol addresses
        if addr in addr_index:
            leaders.add(addr_index[addr])
    for i, insn in enumerate(insns):
        if i and insn.section != insns[i - 1].section:
            leaders.add(i)
        if insn.kind not in TERMINATORS:
            continue
        if insn.target is not None and insn.target in addr_index:
            leaders.add(addr_index[insn.target])
        after = i + (2 if insn.delay else 1)
        if after < len(insns):
            leaders.add(after)
    leaders -= delay_slots

    blocks = []
    start = 0
    for i in range(len(insns)):
        end = i
        if i + 1 in leaders or i + 1 == len(insns):
            blocks.append(Block(insns[start:end + 1]))
            start = i + 1
    return blocks


class CFG(object):
    """Blocks + conditional-branch inventory for one ELF's disassembly."""

    def __init__(self, insns, blocks, arch, symbols=None):
        self.arch = arch
        self.insns = insns
        self.blocks = blocks
        self.symbols = symbols or {}
        self._starts = [b.start for b in blocks]
        self.branch_points = []
        addr_index = {insn.addr: i for i, insn in enumerate(insns)}
        for block in blocks:
            term = block.terminator
            if term is None or term.kind != COND:
                continue
            i = addr_index[term.addr]
            target = term.target
            # A "target" that is not a real instruction address is a parse
            # artifact (e.g. the 0x10 in x86's `jmp *0x10(%rax)`) -- treat it as
            # unknown so the branch is excluded, never mis-attributed.
            if target is not None and target not in addr_index:
                target = None
            self.branch_points.append(BranchPoint(
                term.addr, term.mnemonic, target, _fallthrough(insns, i),
                block.start, block.end))
        self._bp_by_block = {bp.block_start: bp for bp in self.branch_points}

    @property
    def indirect_branches(self):
        """Conditional branches with no statically knowable outcome pair."""
        return [bp for bp in self.branch_points if bp.indirect]

    def block_for(self, addr):
        """Return the block containing `addr`, or None."""
        i = bisect.bisect_right(self._starts, addr) - 1
        if i < 0:
            return None
        block = self.blocks[i]
        return block if block.start <= addr <= block.end else None

    def branch_for_source(self, addr):
        """Return the BranchPoint an edge source address resolves, or None.

        An edge source resolves a branch only when it lies inside that branch's
        block AT OR AFTER the branch -- which is what makes the delay-slot case
        work, since the recorded source is then the delay-slot instruction. A
        QEMU translation block can be SHORTER than a basic block (page/insn
        limits), in which case the source is before the branch (or in a block
        with no conditional terminator) and the edge is a plain fall-through
        that carries no branch information.
        """
        block = self.block_for(addr)
        if block is None:
            return None
        bp = self._bp_by_block.get(block.start)
        if bp is None or addr < bp.addr:
            return None
        return bp


def analyze(objdump_text, profile):
    """objdump -d text + arch profile -> CFG.

    Function symbol addresses are used as extra block leaders: it keeps the
    block map sane across a function whose last instruction we failed to
    recognize as a return (an ISA's return idiom can be an ordinary load, e.g.
    ARM's `pop {r4, pc}`).
    """
    insns = parse_objdump(objdump_text, profile)
    symbols = parse_symbols(objdump_text)
    blocks = build_blocks(insns, extra_leaders=symbols)
    return CFG(insns, blocks, profile.name, symbols)


# --- edge matching ----------------------------------------------------------

class BranchCounts(object):
    """Observed outcome counts for one branch point.

    `taken`/`nottaken` are None until the branch is seen to be EVALUATED; the
    distinction between "never evaluated" (LCOV '-') and "evaluated but this way
    never went" (LCOV '0') is the whole point of branch coverage.
    """

    __slots__ = ("taken", "nottaken")

    def __init__(self):
        self.taken = 0
        self.nottaken = 0

    @property
    def evaluated(self):
        return self.taken > 0 or self.nottaken > 0


def match_edges(cfg, edges):
    """Map observed edges onto branch outcomes.

    Returns (counts{branch_addr: BranchCounts}, stats{str: int}). Edges whose
    source block has no conditional terminator are ordinary fall-throughs and
    are ignored; edges landing on neither outcome (indirect branch, or a target
    outside the disassembly) are counted in stats but never invented as data.
    """
    counts = {}
    stats = {"edges": 0, "matched": 0, "ignored": 0, "unresolved": 0}
    for edge in edges:
        src, dst = edge[0], edge[1]
        count = edge[2] if len(edge) > 2 else 1
        stats["edges"] += 1
        bp = cfg.branch_for_source(src)
        if bp is None:
            stats["ignored"] += 1
            continue
        bc = counts.get(bp.addr)
        if bc is None:
            bc = counts[bp.addr] = BranchCounts()
        if bp.taken is not None and dst == bp.taken:
            bc.taken += count
            stats["matched"] += 1
        elif bp.fallthrough is not None and dst == bp.fallthrough:
            bc.nottaken += count
            stats["matched"] += 1
        else:
            stats["unresolved"] += 1
    return counts, stats
