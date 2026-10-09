"""TB table (FORMAT.md section 12, issue #25): block extents and early exits.

A mode=tb artifact records one address per executed translation block, its
start. With the TB table the reader expands each block into its
instructions, every one counted as often as the block was entered less the
early exits at or before it -- exactly what mode=tb-insn records, at block
cost. The live equivalence (13,399 instructions identical to a tb-insn run of
the riscv reuse fixture) is in examples/rtems-dl/README.md.
"""

import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import format as fmt  # noqa: E402
from tcgcov.format import (read_all, read_full, read_metadata,  # noqa: E402
                           write_cov, effective_record_type)

# A 12-byte block at 0x100: instructions at 0x100 (2), 0x102 (4), 0x106 (2),
# 0x108 (4). Entered 10 times; 3 times it was left before 0x106 ran.
SIZES = bytes([2, 4, 2, 4])


class Fixture(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "t.cov")

    def write(self, records, table, exits=(), meta=None, ctx=False, **kw):
        write_cov(self.path, dict(meta or {"mode": "tb"}), records,
                  record_type=1, ctx=ctx, tb_table=table, tb_exits=exits, **kw)
        return self.path


class ExpansionTest(Fixture):
    def test_block_expands_with_early_exits(self):
        self.write([(0x100, 10)], [(0x100, 10, 1, SIZES)],
                   [(0x100, 12, 0x106, 3)])
        _m, addrs, counts, _e = read_all(self.path)
        self.assertEqual(counts, {0x100: 10, 0x102: 10, 0x106: 7, 0x108: 7})

    def test_an_exit_at_the_block_end_removes_nothing(self):
        # An exception raised by the LAST instruction: the first instruction
        # that did not run is past the block.
        self.write([(0x100, 4)], [(0x100, 4, 1, SIZES)],
                   [(0x100, 12, 0x10C, 2)])
        self.assertEqual(read_all(self.path)[2][0x108], 4)

    def test_overlapping_blocks_add_up(self):
        # Entered at 0x100 (10x, 3 left before 0x106) and at 0x106 (5x):
        # 0x106 and 0x108 ran 7 + 5 times.
        self.write([(0x100, 10), (0x106, 5)],
                   [(0x100, 10, 1, SIZES), (0x106, 5, 2, bytes([2, 4]))],
                   [(0x100, 12, 0x106, 3)])
        counts = read_all(self.path)[2]
        self.assertEqual(counts[0x106], 12)
        self.assertEqual(counts[0x108], 12)

    def test_raw_read_keeps_the_block_starts(self):
        self.write([(0x100, 10)], [(0x100, 10, 3, SIZES)])
        _m, hdr, recs, _e = read_full(self.path, expand=False)
        self.assertEqual(recs, [(None, 0x100, 10)])
        self.assertEqual(hdr["record_type"], 1)
        self.assertEqual((hdr["tb_count"], hdr["exit_count"]), (1, 0))
        entries, _x = fmt.unpack_tb_table(open(self.path, "rb").read(), hdr)
        self.assertEqual(entries[0][5], 3)          # translations

    def test_expanded_read_is_instruction_granular(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)])
        _m, hdr, _r, _e = read_full(self.path)
        self.assertEqual(hdr["record_type"], 2)
        self.assertTrue(hdr["tb_expanded"])
        self.assertEqual(effective_record_type(
            fmt.parse_header(open(self.path, "rb").read())), 2)

    def test_filters_hide_out_of_range_instructions(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)],
                   meta={"mode": "tb", "filters": [
                       {"start": "0x100", "end": "0x106"}]})
        self.assertEqual(sorted(read_all(self.path)[1]), [0x100, 0x102])

    def test_contexts_stay_apart(self):
        self.write([(1, 0x100, 4), (2, 0x100, 6)],
                   [(1, 0x100, 4, 1, SIZES), (2, 0x100, 6, 1, SIZES)],
                   [(2, 0x100, 12, 0x102, 6)], ctx=True)
        self.assertEqual(read_all(self.path, ctx=1)[2][0x108], 4)
        self.assertNotIn(0x102, read_all(self.path, ctx=2)[2])
        self.assertEqual(read_all(self.path, ctx=2)[2][0x100], 6)

    def test_two_codes_with_one_start_and_length_stay_apart(self):
        # Review of PR #27: a reused address (or two processes) can hold
        # different code of the same length. Each keeps its own instruction
        # sizes, and an exit names its entry by index, not by (start, size).
        a_sizes, b_sizes = bytes([2, 2, 4]), bytes([4, 4])
        self.write([(0x100, 8)],
                   [(0x100, 3, 1, a_sizes), (0x100, 5, 1, b_sizes)],
                   [(0x100, 8, 0x104, 2, 1)])     # B left before 0x104, 2x
        _m, hdr, _r, _e = read_full(self.path, expand=False)
        entries, exits = fmt.unpack_tb_table(open(self.path, "rb").read(),
                                             hdr)
        self.assertEqual([e[6] for e in entries], [a_sizes, b_sizes])
        self.assertEqual(exits, [(1, 0x104, 2)])
        # A: 0x100, 0x102, 0x104 three times; B: 0x100 five, 0x104 three.
        self.assertEqual(read_all(self.path)[2],
                         {0x100: 8, 0x102: 3, 0x104: 6})

    def test_a_start_the_table_does_not_cover_is_kept(self):
        self.write([(0x100, 2), (0x200, 9)], [(0x100, 2, 1, SIZES)])
        self.assertEqual(read_all(self.path)[2][0x200], 9)

    def test_metadata_reads_through_the_extended_header(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)],
                   meta={"mode": "tb", "tb_table": True})
        self.assertTrue(read_metadata(self.path)["tb_table"])


class ValidationTest(Fixture):
    def patch(self, off, fmt_, value):
        with open(self.path, "r+b") as f:
            f.seek(off)
            f.write(struct.pack(fmt_, value))

    def test_flag_without_the_extended_header_is_refused(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)])
        self.patch(12, "<I", 88)                    # header_size
        with self.assertRaisesRegex(ValueError, "extended form"):
            read_full(self.path)

    def test_sizes_that_do_not_add_up_are_refused(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)])
        hdr = fmt.parse_header(open(self.path, "rb").read())
        self.patch(hdr["tb_offset"] + 16, "<I", 13)  # entry size 12 -> 13
        with self.assertRaisesRegex(ValueError, "add up"):
            read_full(self.path)

    def test_an_exit_naming_the_wrong_entry_is_refused(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)],
                   [(0x100, 12, 0x106, 1)])
        hdr = fmt.parse_header(open(self.path, "rb").read())
        self.patch(hdr["exit_offset"] + 28, "<I", 5)  # tb_index
        with self.assertRaisesRegex(ValueError, "names entry 5"):
            read_full(self.path)

    def test_exit_section_size_is_checked(self):
        self.write([(0x100, 1)], [(0x100, 1, 1, SIZES)],
                   [(0x100, 12, 0x106, 1)])
        self.patch(128, "<Q", 31)                   # exit_size
        with self.assertRaisesRegex(ValueError, "exit_size"):
            read_full(self.path)


class WritersLabelExpandedRecordsTest(Fixture):
    def test_scrubbed_copy_keeps_the_table(self):
        from tcgcov.dump import write_scrubbed
        self.write([(0x100, 10)], [(0x100, 10, 1, SIZES)],
                   [(0x100, 12, 0x106, 3)],
                   meta={"mode": "tb", "elf": "/secret/path/x.elf"})
        out = os.path.join(self.d, "scrubbed.cov")
        write_scrubbed(self.path, out)
        self.assertEqual(read_all(out)[2], read_all(self.path)[2])
        self.assertNotIn("secret", json.dumps(read_metadata(out)))

    def test_modmap_writes_instruction_records(self):
        from tcgcov.modmap import slice_cov
        self.write([(0x100, 10)], [(0x100, 10, 1, SIZES)])
        out, _m, _u = slice_cov(
            self.path, [{"object": "o", "section": ".text", "file": None,
                         "start": 0x100, "end": 0x10C}],
            os.path.join(self.d, "out"))
        hdr = fmt.parse_header(open(out[0]["out"], "rb").read())
        self.assertEqual(hdr["record_type"], 2)
        self.assertEqual(len(read_all(out[0]["out"])[1]), 4)


if __name__ == "__main__":
    unittest.main()
