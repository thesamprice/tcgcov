"""DWARF line tables of relocatable objects (issue #18).

A `.o`'s debug sections are only correct after relocation: set_address
operands and string offsets are zero in place, and on RISC-V every address
advance inside a sequence is an R_RISCV_ADD16/SUB16 pair (linker
relaxation). The fixtures in tests/data/rtl-reloc are examples/rtems-dl's
pay_a.c built for riscv32 (-O0 and -O2) and MicroBlaze (-O0), with
-fdebug-prefix-map so they carry no local paths. expected.json was produced
by binutils, independently of this code:

  readelf_rows   (line@address -> count) from `readelf --debug-dump=decodedline`,
                 which applies the relocations itself;
  objdump_lines  per code section, the objdump + `addr2line -j` denominator.

No toolchain is needed to run these.
"""

import collections
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import coverable, dwarfline  # noqa: E402

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data",
                    "rtl-reloc")
with open(os.path.join(DATA, "expected.json")) as _f:
    EXPECTED = json.load(_f)
FIXTURES = sorted(f for f in EXPECTED if f.endswith(".o"))


def rows_of(path):
    elf = dwarfline.read_elf(path)
    return elf, [r for r in dwarfline.parse_line_section(
        elf.sections[".debug_line"], elf.little, elf.sections,
        dwarfline._unit_metadata(elf), elf.line_sections)
        if not r.end_sequence]


class RelocatedLineTableTest(unittest.TestCase):
    def test_rows_match_binutils(self):
        for f in FIXTURES:
            with self.subTest(f):
                _elf, rows = rows_of(os.path.join(DATA, f))
                got = collections.Counter("%d@%d" % (r.line, r.address)
                                          for r in rows)
                self.assertEqual(dict(got), EXPECTED[f]["readelf_rows"])

    def test_riscv_address_advances_need_the_add_sub_pairs(self):
        # Without relocation every RISC-V row would sit at address 0.
        _elf, rows = rows_of(os.path.join(DATA, "pay_a-riscv32-O0.o"))
        self.assertGreater(len({r.address for r in rows}), 10)

    def test_every_row_knows_its_section(self):
        for f in FIXTURES:
            with self.subTest(f):
                elf, rows = rows_of(os.path.join(DATA, f))
                self.assertTrue(elf.relocatable)
                self.assertTrue(all(r.section is not None for r in rows))
                names = {elf.section_names[r.section] for r in rows}
                self.assertEqual(names,
                                 set(EXPECTED[f]["objdump_lines"]))

    def test_file_names_come_from_the_relocated_string_table(self):
        for f in FIXTURES:
            with self.subTest(f):
                _elf, rows = rows_of(os.path.join(DATA, f))
                self.assertIn("/src/pay_a.c", {r.file for r in rows})

    def test_unknown_relocation_is_an_error_not_a_guess(self):
        # The RISC-V object relabelled as x86-64: its ADD16 relocations (34)
        # mean nothing there.
        data = bytearray(open(os.path.join(DATA, "pay_a-riscv32-O0.o"),
                              "rb").read())
        data[18:20] = (62).to_bytes(2, "little")
        with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as t:
            t.write(data)
        self.addCleanup(os.unlink, t.name)
        with self.assertRaisesRegex(dwarfline.DwarfError,
                                    "relocation type 34 for ELF machine 62"):
            dwarfline.read_elf(t.name)


class DwarfDenominatorTest(unittest.TestCase):
    """coverable --denominator dwarf --section on a .o, no toolchain."""

    def inventory(self, f, section):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as t:
            out = t.name
        self.addCleanup(os.unlink, out)
        rc = coverable.main(["--elf", os.path.join(DATA, f), "--section",
                             section, "--denominator", "dwarf", "--all-paths",
                             "--no-cross-check", "--out", out])
        self.assertEqual(rc, 0)
        with open(out) as fh:
            return {(r["file"], r["line"], r["function"])
                    for r in map(json.loads, fh)}

    def test_matches_objdump_at_O0(self):
        for f in ("pay_a-riscv32-O0.o", "pay_a-microblaze-O0.o"):
            for sec, lines in EXPECTED[f]["objdump_lines"].items():
                with self.subTest(f=f, section=sec):
                    self.assertEqual(self.inventory(f, sec),
                                     {tuple(x) for x in lines})

    def test_matches_objdump_at_O2_with_inlining(self):
        # Issue #23: per address only the last line-table row counts (what
        # addr2line reports), plus the call site of every inlined range --
        # pad_called/spin are inlined into pay_entry at -O2. Function names
        # differ on inlined lines (addr2line names the inlined function,
        # .symtab the one it was inlined into), so compare (file, line).
        lines = EXPECTED["pay_a-riscv32-O2.o"]["objdump_lines"][".text.pay_entry"]
        want = {(fl, ln) for fl, ln, _fn in lines}
        for f, sec in (("pay_a-riscv32-O2.o", ".text.pay_entry"),
                       ("pay_a-riscv32-O2-linked.elf", ".text")):
            with self.subTest(f):
                got = {(fl, ln) for fl, ln, _fn in self.inventory(f, sec)}
                self.assertEqual(got, want)

    def test_debug_info_of_discarded_code_is_not_coverable(self):
        # gc.c's dropped() is removed by --gc-sections; its line rows stay,
        # relocated near 0 (0x10, 0x28, 0x2c on MicroBlaze, whose address
        # advances are constants). Only code inside an executable section
        # counts, so its lines are not in the denominator -- as with objdump.
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as t:
            out = t.name
        self.addCleanup(os.unlink, out)
        rc = coverable.main(["--elf", os.path.join(DATA, "gc-microblaze.elf"),
                             "--denominator", "dwarf", "--all-paths",
                             "--no-cross-check", "--out", out])
        self.assertEqual(rc, 0)
        with open(out) as fh:
            got = {(r["file"], r["line"]) for r in map(json.loads, fh)}
        want = {(fl, ln) for fl, ln, _fn in
                EXPECTED["gc-microblaze.elf"]["objdump_lines"][""]}
        self.assertEqual(got, want)
        self.assertNotIn(("/src/gc.c", 5), got)

    def test_linked_image_section_offsets_keep_their_function_names(self):
        # Review of PR #24: in a linked image, --section rows are offsets
        # into the section but symbols are absolute; the lookup must add
        # the section's address back. pay_a-riscv32-O0-linked.elf is the
        # -O0 object linked with .text at 0x80000000.
        got = self.inventory("pay_a-riscv32-O0-linked.elf", ".text")
        want = {tuple(x) for lines in EXPECTED["pay_a-riscv32-O0.o"]
                ["objdump_lines"].values() for x in lines}
        self.assertEqual(got, want)

    def test_function_names_are_per_section(self):
        got = self.inventory("pay_a-riscv32-O0.o", ".text.pad_uncovered")
        self.assertEqual({fn for _f, _l, fn in got}, {"pad_uncovered"})


if __name__ == "__main__":
    unittest.main()
