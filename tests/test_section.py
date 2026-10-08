"""--section on a relocatable object: one section's code, not every section's.

In an ET_REL object (an RTEMS loadable `.o`, a Linux `.ko`) every section
starts at address 0, so the whole-file disassembly holds several instructions
at each offset. A slice's addresses are offsets into ONE section; the
coverable inventory and the branch analysis must look at that section alone,
and resolve through `addr2line -j SECTION`, or another section's lines and
branches get counted in its place (issue #12: pay_a.o reported a branch of
pay_entry() on spin()'s loop line, and pad_uncovered()'s lines were missing
from the denominator altogether).
"""

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import branches, cfg, coverable  # noqa: E402
from tests.test_branches import build_cov  # noqa: E402

SRC = "/work/proj/pay.c"

# Two code sections, both at offset 0, each with a conditional branch at the
# SAME offset (0x4) going to a different place.
TEXT = "\n".join([
    "pay.o:     file format elf32-microblazeel",
    "",
    "Disassembly of section .text.spin:",
    "",
    "00000000 <spin>:",
    "   0:\t3021ffe0 \taddik\tr1, r1, -32",
    "   4:\tbe06000c \tbeqid\tr6, 12\t\t// 10 <spin+0x10>",
    "   8:\t80000000 \tor\tr0, r0, r0",
    "   c:\t30a00001 \taddik\tr5, r0, 1",
    "  10:\tb60f0008 \trtsd\tr15, 8",
    "  14:\t80000000 \tor\tr0, r0, r0",
    "",
    "Disassembly of section .text.entry:",
    "",
    "00000000 <entry>:",
    "   0:\t3021ffe0 \taddik\tr1, r1, -32",
    "   4:\tbe260008 \tbneid\tr6, 8\t\t// c <entry+0xc>",
    "   8:\t80000000 \tor\tr0, r0, r0",
    "   c:\tb60f0008 \trtsd\tr15, 8",
    "  10:\t80000000 \tor\tr0, r0, r0",
    "",
])

# (section, offset) -> (function, line): what addr2line -j SECTION answers.
TABLE = {
    (".text.spin", 0x0): ("spin", 20), (".text.spin", 0x4): ("spin", 22),
    (".text.spin", 0x8): ("spin", 22), (".text.spin", 0xc): ("spin", 23),
    (".text.spin", 0x10): ("spin", 25), (".text.spin", 0x14): ("spin", 25),
    (".text.entry", 0x0): ("entry", 40), (".text.entry", 0x4): ("entry", 41),
    (".text.entry", 0x8): ("entry", 41), (".text.entry", 0xc): ("entry", 44),
    (".text.entry", 0x10): ("entry", 44),
}

# Answers per -j section, like the real tool; without -j it answers with
# .text.spin for every offset, which is what made the old code wrong.
FAKE_ADDR2LINE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "TABLE = " + repr({"%s@%x" % k: v for k, v in TABLE.items()}) + "\n"
    "sec = sys.argv[sys.argv.index('-j') + 1] if '-j' in sys.argv "
    "else '.text.spin'\n"
    "for raw in sys.stdin:\n"
    "    raw = raw.strip()\n"
    "    if not raw:\n"
    "        continue\n"
    "    print(raw)\n"
    "    func, line = TABLE.get('%s@%x' % (sec, int(raw, 16)), ('??', 0))\n"
    "    print(func)\n"
    "    print('" + SRC + ":%d' % line if line else '??:?')\n"
)


class SectionTextTest(unittest.TestCase):
    def test_keeps_one_section_and_the_preamble(self):
        text = cfg.section_text(TEXT, ".text.entry")
        self.assertIn("file format elf32-microblazeel", text)
        self.assertIn("<entry>", text)
        self.assertNotIn("<spin>", text)

    def test_unknown_section_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "no disassembly for section"):
            cfg.section_text(TEXT, ".text.nope")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.disasm = os.path.join(self.d, "pay.dis")
        with open(self.disasm, "w") as f:
            f.write(TEXT)
        self.a2l = os.path.join(self.d, "fake-addr2line")
        with open(self.a2l, "w") as f:
            f.write(FAKE_ADDR2LINE)
        os.chmod(self.a2l, os.stat(self.a2l).st_mode | stat.S_IEXEC)
        self.elf = os.path.join(self.d, "pay.o")
        with open(self.elf, "wb") as f:             # ET_REL header only
            f.write(b"\x7fELF\x01\x01\x01" + b"\0" * 9 + b"\x01\x00")
        self.out = os.path.join(self.d, "out.jsonl")

    def records(self):
        with open(self.out) as f:
            return [json.loads(line) for line in f]


class CoverableSectionTest(Fixture):
    def run_coverable(self, section, *extra):
        return coverable.main(["--elf", self.elf, "--disasm", self.disasm,
                               "--addr2line", self.a2l, "--all-paths",
                               "--denominator", "objdump", "--section",
                               section, "--out", self.out] + list(extra))

    def test_only_that_sections_lines(self):
        self.assertEqual(self.run_coverable(".text.entry"), 0)
        recs = self.records()
        self.assertEqual({r["function"] for r in recs}, {"entry"})
        self.assertEqual(sorted(r["line"] for r in recs), [40, 41, 44])

    def test_the_other_section_gets_its_own(self):
        self.assertEqual(self.run_coverable(".text.spin"), 0)
        self.assertEqual(sorted(r["line"] for r in self.records()),
                         [20, 22, 23, 25])

    def test_dwarf_denominator_fails_loudly_on_an_unreadable_object(self):
        # (The DWARF path reads real .o files since #18; see
        # test_dwarf_reloc. This one is a bare header with no sections.)
        rc = coverable.main(["--elf", self.elf, "--all-paths",
                             "--denominator", "dwarf", "--section",
                             ".text.entry", "--out", self.out])
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(self.out))


class BranchesSectionTest(Fixture):
    def test_edges_match_that_sections_branch(self):
        # Offset 0x4 is a branch in BOTH sections; the edge belongs to entry.
        cov = os.path.join(self.d, "entry.cov")
        with open(cov, "wb") as f:
            f.write(build_cov({"target_name": "microblazeel"},
                              [(0x8, 0xc, 3)]))       # entry's taken edge
        rc = branches.main(["--elf", self.elf, "--disasm", self.disasm,
                            "--addr2line", self.a2l, "--all-paths",
                            "--section", ".text.entry", "--cov", cov,
                            "--out", self.out])
        self.assertEqual(rc, 0)
        recs = self.records()
        self.assertEqual(len(recs), 1)               # spin's branch excluded
        self.assertEqual((recs[0]["function"], recs[0]["line"]),
                         ("entry", 41))
        self.assertEqual(recs[0]["taken"], 3)


if __name__ == "__main__":
    unittest.main()
