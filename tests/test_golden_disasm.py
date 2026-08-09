"""Golden-fixture tests for disassembly parsing (tcgcov.cfg, tcgcov.coverable).

The fixtures in tests/data/ are GENUINE tool output, captured verbatim:

    gnu-microblaze.txt   GNU objdump -d   (the project's primary target)
    llvm-x86_64.txt      llvm-objdump -d
    llvm-aarch64.txt     llvm-objdump -d
    llvm-riscv64.txt     llvm-objdump -d
    llvm-armv7.txt       llvm-objdump -d

They exist because the two disassemblers do NOT agree on the separator after
the address, and the parser used to demand GNU's tab:

    GNU : "90000000:\\tb00097ff \\timm\\t-26625"
    LLVM: "       0: 52800028     \\tmov\\tw8, #0x1"

On llvm-objdump input that produced zero instructions, zero branches, a 0-byte
branch file and exit status 0 -- branch coverage silently disappeared while
line coverage (which used a different, correct regex) kept working. Every
llvm-* case below fails with an instruction count of 0 against that parser.
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from tcgcov import cfg, coverable  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# name -> (arch, instruction count, conditional-branch count, first insn text,
#          last insn text, kind of the last instruction)
GOLDEN = {
    "gnu-microblaze.txt": ("microblaze", 111, 4,
                           "imm -26625", "lwi r19, r1, -12", cfg.OTHER),
    "llvm-x86_64.txt": ("x86_64", 5, 0,
                        "xorl %eax, %eax", "retq", cfg.RET),
    "llvm-aarch64.txt": ("aarch64", 4, 0,
                         "mov w8, #0x1                // =1", "ret", cfg.RET),
    # The fixture above contains ZERO conditional branches -- the compiler
    # folded them into csel -- so it proves the parser handles llvm-objdump
    # layout but proves nothing about branch classification. This one is built
    # at -O0 specifically to emit real branches, and pins the spelling:
    # llvm-objdump prints the DOTTED form b.<cc>, never the no-dot assembler
    # alias. GNU objdump cannot print the no-dot form either -- beq/bne/blt/bgt
    # are F_ALIAS|F_PSEUDO in aarch64-tbl.h:5251-5265, and F_PSEUDO is defined
    # (include/opcode/aarch64.h:1470-1473) as assembly-only, "thus will not
    # show up in the disassembly". So matching only b.<cc> is correct.
    "llvm-aarch64-branches.txt": ("aarch64", 53, 5,
                                  "sub sp, sp, #0x10", "ret", cfg.RET),
    "llvm-riscv64.txt": ("riscv", 3, 0,
                         "slti a0, a0, 0x6", "ret", cfg.RET),
    "llvm-armv7.txt": ("arm", 5, 0,
                       "mov r1, #2", "bx lr", cfg.RET),
}


def read_golden(name):
    with open(os.path.join(DATA, name)) as f:
        return f.read()


class TestGoldenDisassembly(unittest.TestCase):
    """Every captured layout must parse to the same instruction inventory."""

    def test_all_golden_files_parse(self):
        for name, (arch, n_insns, n_cond, first, last, last_kind) in \
                sorted(GOLDEN.items()):
            with self.subTest(golden=name):
                text = read_golden(name)
                self.assertEqual(cfg.detect_arch(text), arch)
                graph = cfg.analyze(text, cfg.get_profile(arch))
                # The count, not merely "> 0": a partial parse (raw-bytes
                # column mistaken for a mnemonic, continuation lines counted as
                # instructions) also has to be caught.
                self.assertEqual(len(graph.insns), n_insns)
                self.assertEqual(len(graph.branch_points), n_cond)
                # The raw-bytes column must be stripped, not folded into the
                # instruction text, or every mnemonic would be a hex string.
                self.assertEqual(graph.insns[0].text, first)
                self.assertEqual(graph.insns[-1].text, last)
                self.assertEqual(graph.insns[-1].kind, last_kind)

    def test_coverable_and_cfg_see_the_same_instructions(self):
        """The two denominators are produced by ONE line matcher.

        When they diverged, line coverage worked and branch coverage silently
        emitted nothing -- so agreement here is the property that matters, not
        either count on its own.
        """
        for name in sorted(GOLDEN):
            with self.subTest(golden=name):
                text = read_golden(name)
                arch = GOLDEN[name][0]
                cfg_addrs = sorted({i.addr for i in
                                    cfg.analyze(text, cfg.get_profile(arch)).insns})
                self.assertEqual(coverable.parse_addresses(text), cfg_addrs)

    def test_microblaze_branch_outcomes(self):
        """Real branch targets and fall-throughs, from real GNU objdump text.

        MicroBlaze prints the displacement as the operand and the resolved
        target only in a trailing '// <hex>' comment, so these pairs also prove
        the comment-target path works on genuine output.
        """
        text = read_golden("gnu-microblaze.txt")
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        got = [(bp.addr, bp.mnemonic, bp.taken, bp.fallthrough)
               for bp in graph.branch_points]
        self.assertEqual(got, [
            (0x90000070, "bnei", 0x90000088, 0x90000074),
            (0x900000cc, "blti", 0x900000ec, 0x900000d0),
            (0x90000130, "blti", 0x90000150, 0x90000134),
            (0x90000180, "beqi", 0x900001a0, 0x90000184),
        ])
        self.assertEqual(graph.indirect_branches, [])
        self.assertEqual(sorted(graph.symbols.values()),
                         ["_start", "main", "never_called", "taken_both",
                          "taken_one"])

    def test_aarch64_conditional_branches_use_the_dotted_spelling(self):
        """Every AArch64 conditional branch prints as b.<cc>, never as the
        no-dot assembler alias.

        This is the whole reason the profile matches only the dotted form. If a
        disassembler ever emitted `beq` instead of `b.eq`, every AArch64
        conditional branch would classify OTHER and vanish from the branch
        denominator -- silently, with the report still exiting 0.
        """
        text = read_golden("llvm-aarch64-branches.txt")
        profile = cfg.get_profile("aarch64")
        conds = {i.text.split()[0]
                 for i in cfg.parse_objdump(text, profile) if i.kind == cfg.COND}
        self.assertTrue(conds, "fixture has no conditional branches to check")
        for mnemonic in conds:
            if mnemonic.startswith("b") and not mnemonic.startswith(("cb", "tb")):
                self.assertTrue(
                    mnemonic.startswith("b."),
                    f"{mnemonic!r} is a no-dot alias; if a real disassembler "
                    f"emits this, the aarch64 profile needs to accept it")

    def test_x86_sizes_come_from_address_deltas(self):
        """llvm-objdump x86 lines: variable-length insns at 0,2,5,8,a."""
        graph = cfg.analyze(read_golden("llvm-x86_64.txt"),
                            cfg.get_profile("x86_64"))
        self.assertEqual([i.addr for i in graph.insns], [0, 2, 5, 8, 0xa])
        self.assertEqual([i.size for i in graph.insns], [2, 3, 3, 2, 1])


class TestRawBytesColumn(unittest.TestCase):
    """_instruction_text must find the mnemonic in every column layout."""

    def test_gnu_layout(self):
        self.assertEqual(cfg._instruction_text("b00097ff \timm\t-26625"),
                         "imm -26625")

    def test_llvm_layout(self):
        self.assertEqual(cfg._instruction_text("52800028     \tmov\tw8, #0x1"),
                         "mov w8, #0x1")

    def test_llvm_layout_multibyte_column(self):
        self.assertEqual(
            cfg._instruction_text("31 c0                        \txorl\t%eax, %eax"),
            "xorl %eax, %eax")

    def test_no_show_raw_insn_gnu(self):
        # GNU --no-show-raw-insn drops the column entirely.
        self.assertEqual(cfg._instruction_text("addik\tr1, r1, -4"),
                         "addik r1, r1, -4")

    def test_no_show_raw_insn_llvm(self):
        # llvm-objdump --no-show-raw-insn leaves the column as blank padding.
        self.assertEqual(cfg._instruction_text("     \tmov\tw8, #0x1"),
                         "mov w8, #0x1")

    def test_hex_spellable_mnemonic_is_not_eaten(self):
        """'add', 'dec', 'bad' are hex strings; the mnemonic must survive.

        Content alone cannot tell them from a raw-bytes column, which is why
        the check also requires whole bytes and the trailing padding that every
        objdump prints after the real column.
        """
        for mnemonic in ("add", "dec", "bad", "adc"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(
                    cfg._instruction_text("%s\tr3, r6, r5" % mnemonic),
                    "%s r3, r6, r5" % mnemonic)

    def test_raw_byte_continuation_line_is_not_an_instruction(self):
        # GNU objdump wraps an over-long instruction's bytes onto extra
        # address-prefixed lines carrying no mnemonic.
        self.assertEqual(cfg._instruction_text("00 00 "), "")

    def test_file_format_banner_is_not_an_instruction(self):
        # "beef.elf:\tfile format ..." would otherwise parse as an instruction
        # at 0xbeef, because objdump prints the file name in the same shape.
        self.assertIsNone(
            cfg.match_insn_line("beef:\tfile format elf32-microblazeel"))


class TestZeroInstructionsIsAnError(unittest.TestCase):
    """A total parse failure must never be reported as success (BUG 2)."""

    def test_parse_objdump_raises_on_unparsable_text(self):
        profile = cfg.get_profile("microblaze")
        with self.assertRaises(cfg.DisassemblyParseError):
            cfg.parse_objdump("this is not objdump output\nnor is this\n",
                              profile)

    def test_error_is_a_valueerror_so_callers_catch_it(self):
        # Every caller handles (OSError, ValueError); a fresh exception type
        # outside that pair would escape as a traceback.
        self.assertTrue(issubclass(cfg.DisassemblyParseError, ValueError))

    def test_analyze_raises_too(self):
        with self.assertRaises(cfg.DisassemblyParseError):
            cfg.analyze("a.elf:     file format elf32-microblazeel\n"
                        "\nDisassembly of section .text:\n\n"
                        "90000000 <main>:\n"
                        "90000000 3021ffe0 addik r1, r1, -32\n",
                        cfg.get_profile("microblaze"))

    def test_empty_text_is_not_an_error(self):
        # Nothing to parse is not the same as failing to parse.
        self.assertEqual(cfg.parse_objdump("", cfg.get_profile("microblaze")),
                         [])
        self.assertEqual(cfg.parse_objdump("  \n\n",
                                           cfg.get_profile("microblaze")), [])

    def test_branches_command_exits_nonzero(self):
        from tcgcov import branches
        d = tempfile.mkdtemp()
        disasm = os.path.join(d, "a.dis")
        out = os.path.join(d, "br.jsonl")
        with open(disasm, "w") as f:
            f.write("a.elf:     file format elf32-microblazeel\n"
                    "\nDisassembly of section .text:\n\n"
                    "not a disassembly line at all\n")
        rc = branches.main(["--elf", os.path.join(d, "a.elf"),
                            "--disasm", disasm, "--all-paths", "--out", out])
        self.assertNotEqual(rc, 0)
        # No 0-byte output file left behind to be read as "no branches".
        self.assertFalse(os.path.exists(out))


FAKE_OBJDUMP = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "sys.stdout.write(%r)\n"
)


class TestCoverableRefusesEmptyInventory(unittest.TestCase):
    """An empty coverable inventory becomes 100% coverage downstream (BUG 3)."""

    def _objdump(self, output):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "fake-objdump")
        with open(path, "w") as f:
            f.write(FAKE_OBJDUMP % output)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return d, path

    def _run(self, output):
        d, objdump = self._objdump(output)
        out = os.path.join(d, "coverable.jsonl")
        # --denominator objdump is load-bearing here. Under the default `auto`
        # this would fall back to DWARF and then fail on the nonexistent fake
        # ELF instead -- still non-zero, but for the wrong reason, so the test
        # would pass while no longer testing that an unparsable disassembly is
        # refused. The `auto` fallback has its own tests in test_dwarfline.py.
        rc = coverable.main(["--elf", os.path.join(d, "a.elf"),
                             "--objdump", objdump, "--all-paths",
                             "--denominator", "objdump",
                             "--out", out])
        return rc, out

    def test_unparsable_output_exits_nonzero(self):
        rc, out = self._run("a.elf:     file format elf32-microblazeel\n"
                            "lots of output\nthat parses to nothing\n")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(out))

    def test_no_output_at_all_exits_nonzero(self):
        rc, out = self._run("")
        self.assertNotEqual(rc, 0)
        self.assertFalse(os.path.exists(out))


class TestSubprocessDecoding(unittest.TestCase):
    """Tool output is not always valid UTF-8, and the locale is not always
    UTF-8 either; neither may abort the run (BUG 5)."""

    def _objdump_emitting(self, raw_bytes):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "fake-objdump")
        with open(path, "w") as f:
            f.write("#!/usr/bin/env python3\n"
                    "import sys\n"
                    "sys.stdout.buffer.write(%r)\n" % raw_bytes)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return d, path

    def test_non_utf8_byte_in_disassembly_does_not_crash(self):
        # \xff is invalid UTF-8 and undecodable under LC_ALL=C's ASCII codec.
        d, objdump = self._objdump_emitting(
            b"a.elf:     file format elf32-microblazeel\n"
            b"\nDisassembly of section .text:\n\n"
            b"90000000 <f\xff\xfeoo>:\n"
            b"90000000:\t3021ffe0 \taddik\tr1, r1, -32\n"
            b"90000004:\tb60f0008 \trtsd\tr15, 8\n")
        text = cfg.disassemble(objdump, os.path.join(d, "a.elf"))
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        self.assertEqual(len(graph.insns), 2)

    def test_coverable_survives_non_utf8_too(self):
        d, objdump = self._objdump_emitting(
            b"a.elf:     file format elf32-microblazeel\n"
            b"90000000 <b\xffr>:\n"
            b"90000000:\t3021ffe0 \taddik\tr1, r1, -32\n")
        addrs, _text = coverable.disassemble_addresses(
            objdump, os.path.join(d, "a.elf"))
        self.assertEqual(addrs, [0x90000000])

    def test_addr2line_with_a_non_utf8_source_path(self):
        from tcgcov import symbolize
        d = tempfile.mkdtemp()
        a2l = os.path.join(d, "fake-addr2line")
        with open(a2l, "w") as f:
            f.write("#!/usr/bin/env python3\n"
                    "import sys\n"
                    "sys.stdin.read()\n"
                    "sys.stdout.buffer.write(b'0x1000\\nmain\\n"
                    "/src/caf\\xe9/main.c:12\\n')\n")
        os.chmod(a2l, os.stat(a2l).st_mode | stat.S_IEXEC)
        got = list(symbolize.run_addr2line(a2l, os.path.join(d, "a.elf"),
                                           [0x1000]))
        self.assertEqual(len(got), 1)
        addr, frames = got[0]
        self.assertEqual(addr, 0x1000)
        self.assertEqual(frames[0][0], "main")
        self.assertEqual(frames[0][2], "12")

    def test_tools_run_under_a_c_locale(self):
        """LC_ALL=C makes the locale codec ASCII; decoding must not depend
        on it."""
        d, objdump = self._objdump_emitting(
            b"a.elf:     file format elf32-microblazeel\n"
            b"90000000 <caf\xe9>:\n"
            b"90000000:\t3021ffe0 \taddik\tr1, r1, -32\n")
        env = dict(os.environ, LC_ALL="C", LANG="C",
                   PYTHONCOERCECLOCALE="0", PYTHONUTF8="0")
        script = ("import sys; sys.path.insert(0, %r);\n"
                  "from tcgcov import cfg;\n"
                  "print(len(cfg.disassemble(%r, 'a.elf').splitlines()))\n"
                  % (REPO_ROOT, objdump))
        proc = subprocess.run([sys.executable, "-c", script], env=env,
                              capture_output=True, encoding="utf-8",
                              errors="surrogateescape")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "3")


if __name__ == "__main__":
    unittest.main()
