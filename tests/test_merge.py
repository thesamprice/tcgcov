"""Tests for aggregate merge-by-source (tcgcov.merge)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.merge import main as merge_main  # noqa: E402

INFO_A = """\
TN:a
SF:cpukit/x.c
FN:10,foo
FNDA:3,foo
BRDA:10,0,0,3
BRDA:10,0,1,0
BRDA:11,0,0,-
BRDA:11,0,1,-
BRF:4
BRH:1
DA:10,3
DA:11,0
end_of_record
"""

INFO_B = """\
TN:b
SF:cpukit/x.c
FN:10,foo
FNDA:2,foo
BRDA:10,0,0,0
BRDA:10,0,1,2
BRDA:11,0,0,-
BRDA:11,0,1,-
BRDA:12,0,0,1
BRDA:12,0,1,0
BRF:6
BRH:2
DA:10,2
DA:11,5
DA:12,0
end_of_record
"""


class TestMerge(unittest.TestCase):
    def _merge(self):
        d = tempfile.mkdtemp()
        a = os.path.join(d, "a.info")
        b = os.path.join(d, "b.info")
        out = os.path.join(d, "agg.info")
        with open(a, "w") as f:
            f.write(INFO_A)
        with open(b, "w") as f:
            f.write(INFO_B)
        self.assertEqual(merge_main([a, b, "--out", out, "--name", "agg"]), 0)
        return out

    def test_sum_and_union(self):
        out = self._merge()

        da = {}
        with open(out) as f:
            for line in f:
                if line.startswith("DA:"):
                    ln, _, hits = line[3:].strip().partition(",")
                    da[int(ln)] = int(hits)
                elif line.startswith("FNDA:"):
                    hits, _, name = line[5:].strip().partition(",")
                    self.assertEqual((name, int(hits)), ("foo", 5))  # 3 + 2

        # coverable union = {10,11,12}; counts summed; line 12 coverable-not-hit.
        self.assertEqual(da, {10: 5, 11: 5, 12: 0})

    def test_branches_merge_by_source_line_block_branch(self):
        out = self._merge()
        brda = {}
        totals = {}
        with open(out) as f:
            for line in f:
                line = line.strip()
                if line.startswith("BRDA:"):
                    ln, blk, br, taken = line[5:].split(",")
                    brda[(int(ln), int(blk), int(br))] = taken
                elif line.startswith(("BRF:", "BRH:")):
                    k, _, v = line.partition(":")
                    totals[k] = int(v)

        # Line 10 block 0: A took branch 0 three times and never branch 1;
        # B is the mirror image. The aggregate knows BOTH outcomes happen.
        self.assertEqual(brda[(10, 0, 0)], "3")
        self.assertEqual(brda[(10, 0, 1)], "2")
        # Line 11 was never evaluated in EITHER input -> stays '-', not 0.
        self.assertEqual(brda[(11, 0, 0)], "-")
        self.assertEqual(brda[(11, 0, 1)], "-")
        # Line 12 exists only in B: union, and its untaken outcome is '0'
        # (evaluated) rather than '-'.
        self.assertEqual(brda[(12, 0, 0)], "1")
        self.assertEqual(brda[(12, 0, 1)], "0")
        self.assertEqual(totals, {"BRF": 6, "BRH": 3})

    def test_dash_loses_to_a_real_count(self):
        # A '-' from one test must not mask another test's observed count.
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a.info"), os.path.join(d, "b.info")
        out = os.path.join(d, "agg.info")
        with open(a, "w") as f:
            f.write("SF:x.c\nBRDA:5,0,0,-\nBRDA:5,0,1,-\nDA:5,0\n"
                    "end_of_record\n")
        with open(b, "w") as f:
            f.write("SF:x.c\nBRDA:5,0,0,7\nBRDA:5,0,1,0\nDA:5,7\n"
                    "end_of_record\n")
        self.assertEqual(merge_main([a, b, "--out", out]), 0)
        got = [l.strip() for l in open(out) if l.startswith("BRDA:")]
        self.assertEqual(got, ["BRDA:5,0,0,7", "BRDA:5,0,1,0"])


if __name__ == "__main__":
    unittest.main()
