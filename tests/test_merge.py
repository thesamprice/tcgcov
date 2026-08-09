"""Tests for aggregate merge-by-source (tcgcov.merge)."""

import contextlib
import io
import itertools
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import branches, cfg  # noqa: E402
from tcgcov.lcov import main as lcov_main  # noqa: E402
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


# A third input, overlapping A and B on cpukit/x.c and adding a second file, so
# ordering has something to disturb: file order, line order and branch order.
INFO_C = """\
TN:c
SF:bsps/y.c
FN:1,bar
FNDA:9,bar
BRDA:1,0,0,4
BRDA:1,0,1,-
DA:1,9
DA:2,0
end_of_record
TN:c
SF:cpukit/x.c
FN:10,foo
FNDA:1,foo
BRDA:11,0,0,6
BRDA:11,0,1,0
DA:10,1
DA:13,4
end_of_record
"""


class TestMergeDeterminism(unittest.TestCase):
    """Merging is set/sum arithmetic, so input order must not show up in the
    output. A regression guard: this holds today and quietly stops holding the
    moment an accumulator becomes order-sensitive (last-wins, first-wins, or a
    dict iterated instead of sorted)."""

    def test_output_is_byte_identical_under_every_permutation(self):
        d = tempfile.mkdtemp()
        names = []
        for name, body in (("a.info", INFO_A), ("b.info", INFO_B),
                           ("c.info", INFO_C)):
            p = os.path.join(d, name)
            with open(p, "w") as f:
                f.write(body)
            names.append(p)

        outputs = {}
        for i, order in enumerate(itertools.permutations(names)):
            out = os.path.join(d, "agg%d.info" % i)
            self.assertEqual(
                merge_main(list(order) + ["--out", out, "--name", "agg"]), 0)
            with open(out, "rb") as f:
                outputs[tuple(os.path.basename(p) for p in order)] = f.read()

        self.assertEqual(len(outputs), 6)
        distinct = set(outputs.values())
        self.assertEqual(
            len(distinct), 1,
            "merge output depends on input order: %s" % sorted(outputs))
        # And the merge really did aggregate something.
        text = distinct.pop().decode()
        self.assertIn("SF:bsps/y.c", text)
        self.assertIn("SF:cpukit/x.c", text)
        self.assertIn("DA:10,6\n", text)     # 3 + 2 + 1


SRC = "/work/proj/src/main.c"

# One source construct -- `if (a || b)` on line 10, its body on line 11, the
# code after it on line 13 -- compiled into two SEPARATELY LINKED binaries.
#
# Binary A keeps both tests. The first exits INTO the body (line 11), the second
# exits PAST it (line 13), which is what `||` looks like once compiled:
#
#   90000004  bnei r5, -> 90000014   line 10, taken target line 11
#   9000000c  beqi r6, -> 9000001c   line 10, taken target line 13
BIN_A = "\n".join([
    "a.elf:     file format elf32-microblazeel",
    "",
    "Disassembly of section .text:",
    "",
    "90000000 <main>:",
    "90000000:\t3021ffe0 \taddik\tr1, r1, -32",
    "90000004:\tbc250010 \tbnei\tr5, 16\t\t// 90000014",
    "90000008:\t30e00000 \taddik\tr7, r0, 0",
    "9000000c:\tbc060010 \tbeqi\tr6, 16\t\t// 9000001c",
    "90000010:\t31000001 \taddik\tr8, r0, 1",
    "90000014:\t30a00003 \taddik\tr5, r0, 3",
    "90000018:\t30c00004 \taddik\tr6, r0, 4",
    "9000001c:\tb60f0008 \trtsd\tr15, 8",
    "90000020:\t80000000 \tor\tr0, r0, r0",
    "",
])
LOC_A = {
    0x90000004: (SRC, 10, "main"), 0x90000008: (SRC, 10, "main"),
    0x9000000c: (SRC, 10, "main"), 0x90000010: (SRC, 11, "main"),
    0x90000014: (SRC, 11, "main"), 0x9000001c: (SRC, 13, "main"),
}
# First test taken 5 times; second test evaluated and never taken (7 times).
EDGES_A = [(0x90000004, 0x90000014, 5), (0x9000000c, 0x90000010, 7)]

# Binary B is linked at a different base AND compiles `a` away (it is a constant
# there), so line 10 carries only the SECOND test -- the same source branch as
# binary A's 0x9000000c, at a different address and with a different number of
# neighbours on its line.
BIN_B = "\n".join([
    "b.elf:     file format elf32-microblazeel",
    "",
    "Disassembly of section .text:",
    "",
    "80002000 <main>:",
    "80002000:\t3021ffe0 \taddik\tr1, r1, -32",
    "80002004:\tbc06000c \tbeqi\tr6, 12\t\t// 80002010",
    "80002008:\t31000001 \taddik\tr8, r0, 1",
    "8000200c:\t30a00003 \taddik\tr5, r0, 3",
    "80002010:\tb60f0008 \trtsd\tr15, 8",
    "80002014:\t80000000 \tor\tr0, r0, r0",
    "",
])
LOC_B = {
    0x80002004: (SRC, 10, "main"), 0x80002008: (SRC, 11, "main"),
    0x80002010: (SRC, 13, "main"),
}
EDGES_B = [(0x80002004, 0x80002010, 3), (0x80002004, 0x80002008, 9)]


class TestCrossBinaryBranchMerge(unittest.TestCase):
    """Branch outcomes must merge by SOURCE identity, like line coverage.

    `block` used to be a rank of the branches a binary happened to have on the
    line, in address order. Binary A has two branches on line 10 and binary B
    has one, so B's only branch ranked 0 and merged onto A's FIRST branch -- two
    genuinely different source branches summed as one, while A's second branch
    (the one B actually shares) merged with nothing.
    """

    def _info(self, d, name, text, locs, edges):
        graph = cfg.analyze(text, cfg.get_profile("microblaze"))
        counts, _ = cfg.match_edges(graph, edges)
        recs = branches.build_records(graph.branch_points, counts, locs,
                                      {"arch": "microblaze"})
        self.assertTrue(recs, "fixture produced no branch records")
        br = os.path.join(d, name + ".br.jsonl")
        with open(br, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")
        cov = os.path.join(d, name + ".cov.jsonl")
        with open(cov, "w") as f:
            for line in (10, 11, 13):
                f.write(json.dumps({"file": SRC, "line": line,
                                    "function": "main", "count": 1}) + "\n")
        info = os.path.join(d, name + ".info")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(
                lcov_main([cov, "--branches", br, "--out", info]), 0)
        return info

    def _merged_brda(self):
        d = tempfile.mkdtemp()
        a = self._info(d, "a", BIN_A, LOC_A, EDGES_A)
        b = self._info(d, "b", BIN_B, LOC_B, EDGES_B)
        out = os.path.join(d, "agg.info")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(merge_main([a, b, "--out", out]), 0)
        brda, totals = {}, {}
        with open(out) as f:
            for line in f:
                line = line.strip()
                if line.startswith("BRDA:"):
                    ln, blk, br_, taken = line[5:].split(",")
                    brda[(int(ln), int(blk), int(br_))] = taken
                elif line.startswith(("BRF:", "BRH:")):
                    k, _, v = line.partition(":")
                    totals[k] = int(v)
        return brda, totals

    def test_distinct_source_branches_are_not_conflated(self):
        brda, totals = self._merged_brda()
        # Exactly two branches survive the merge, keyed by the line each one
        # jumps to: the `||` first test (into the body, line 11) and the second
        # test (past it, line 13). Under address ranking the keys were
        # (10,0,*) and (10,1,*), and A's first branch collected B's counts.
        self.assertEqual(sorted(brda), [(10, 11, 0), (10, 11, 1),
                                        (10, 13, 0), (10, 13, 1)])
        # Branch present only in A: its counts are A's alone, untouched by B.
        self.assertEqual(brda[(10, 11, 0)], "5")
        self.assertEqual(brda[(10, 11, 1)], "0")
        # Branch present in BOTH, at different addresses: counts summed.
        self.assertEqual(brda[(10, 13, 0)], "3")     # 0 in A + 3 in B
        self.assertEqual(brda[(10, 13, 1)], "16")    # 7 in A + 9 in B
        self.assertEqual(totals, {"BRF": 4, "BRH": 3})

    def test_key_is_stable_across_the_two_binaries(self):
        """The shared branch sits at 0x9000000c in A and 0x80002004 in B; the
        key it merges on must not mention either."""
        keys = []
        for text, locs in ((BIN_A, LOC_A), (BIN_B, LOC_B)):
            graph = cfg.analyze(text, cfg.get_profile("microblaze"))
            recs = branches.build_records(graph.branch_points, {}, locs, {})
            keys.append({(r["line"], r["block"]) for r in recs})
        a_keys, b_keys = keys
        self.assertEqual(b_keys, {(10, 13)})
        self.assertEqual(a_keys, {(10, 11), (10, 13)})
        self.assertTrue(b_keys < a_keys)          # B's branch is one of A's


class TestMergeInputFailures(unittest.TestCase):
    def test_all_inputs_unreadable_exits_nonzero(self):
        """Warn-and-continue on every input used to write an empty aggregate
        and exit 0 -- a CI-green '0.0% of 0 lines'."""
        d = tempfile.mkdtemp()
        out = os.path.join(d, "agg.info")
        missing = [os.path.join(d, "nope1.info"), os.path.join(d, "nope2.info")]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = merge_main(missing + ["--out", out])
        self.assertNotEqual(rc, 0)
        self.assertIn("none of the", err.getvalue())
        self.assertFalse(os.path.exists(out))

    def test_one_readable_input_still_succeeds(self):
        d = tempfile.mkdtemp()
        good = os.path.join(d, "a.info")
        with open(good, "w") as f:
            f.write(INFO_A)
        out = os.path.join(d, "agg.info")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = merge_main([good, os.path.join(d, "nope.info"),
                             "--out", out])
        self.assertEqual(rc, 0)
        self.assertIn("warning: skipping", err.getvalue())
        self.assertTrue(os.path.exists(out))


if __name__ == "__main__":
    unittest.main()
