"""Tests for branch records and their LCOV BRDA emission.

Covers the join of the static inventory with observed edges, the source-derived
block id that lets BRDA merge across separately-linked test binaries, and the
'-' vs '0' distinction that tells "never evaluated" apart from "evaluated, never
taken".
"""

import json
import os
import stat
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import branches, cfg  # noqa: E402
from tcgcov.format import (MAGIC, HEADER_FMT, HEADER_SIZE, FLAG_HAS_EDGES,  # noqa: E402
                           FLAG_EDGE_COUNTS)
from tcgcov.lcov import main as lcov_main  # noqa: E402

SRC = "/work/proj/src/main.c"

# Two conditional branches on the SAME source line (a short-circuit &&), plus a
# never-executed one on another line, in MicroBlaze delay-slot form.
#   90000000  addik
#   90000004  beqid  -> 90000020   (line 10)   delay slot 90000008
#   9000000c  addik
#   90000010  bneid  -> 90000020   (line 10)   delay slot 90000014
#   90000018  addik
#   9000001c  bnei   -> 90000028   (line 20, never runs)
#   90000020  addik
#   90000024  addik
#   90000028  rtsd
#   9000002c  or  (delay slot)
TEXT = "\n".join([
    "a.elf:     file format elf32-microblazeel",
    "",
    "Disassembly of section .text:",
    "",
    "90000000 <main>:",
    "90000000:\t3021ffe0 \taddik\tr1, r1, -32",
    "90000004:\tbe06001c \tbeqid\tr6, 28\t\t// 90000020",
    "90000008:\t80000000 \tor\tr0, r0, r0",
    "9000000c:\t30a00001 \taddik\tr5, r0, 1",
    "90000010:\tbe240010 \tbneid\tr4, 16\t\t// 90000020",
    "90000014:\t80000000 \tor\tr0, r0, r0",
    "90000018:\t30a00002 \taddik\tr5, r0, 2",
    "9000001c:\tbc23000c \tbnei\tr3, 12\t\t// 90000028",
    "90000020:\t30a00003 \taddik\tr5, r0, 3",
    "90000024:\t30c00004 \taddik\tr6, r0, 4",
    "90000028:\tb60f0008 \trtsd\tr15, 8",
    "9000002c:\t80000000 \tor\tr0, r0, r0",
    "",
])

# Branch addresses AND their taken/fall-through targets: the block id is the
# target's source line, so the targets must resolve too.
LOCATIONS = {
    0x90000004: (SRC, 10, "main"),   # `a && b`, first test
    0x9000000c: (SRC, 10, "main"),   #   its fall-through: still line 10
    0x90000010: (SRC, 10, "main"),   # `a && b`, second test
    0x90000018: (SRC, 11, "main"),   #   its fall-through: the then-body
    0x90000020: (SRC, 12, "main"),   # both tests exit here (the else)
    0x9000001c: (SRC, 20, "main"),   # unrelated branch on another line
    0x90000028: (SRC, 22, "main"),   #   its taken target
}


def build_cov(meta, edges, edge_counts=True):
    """Minimal TCGCOV1 buffer carrying only edge records."""
    meta_bytes = json.dumps(meta).encode("utf-8")
    flags = FLAG_HAS_EDGES | (FLAG_EDGE_COUNTS if edge_counts else 0)
    if edge_counts:
        edge_bytes = b"".join(struct.pack("<QQQ", *e) for e in edges)
    else:
        edge_bytes = b"".join(struct.pack("<QQ", e[0], e[1]) for e in edges)
    meta_off = HEADER_SIZE
    edge_off = meta_off + len(meta_bytes)
    header = struct.pack(HEADER_FMT, MAGIC, 1, 1, HEADER_SIZE, 3, flags, 0,
                         meta_off, len(meta_bytes), edge_off, 0,
                         len(edges), edge_off, len(edge_bytes))
    return header + meta_bytes + edge_bytes


# Stands in for the cross addr2line: maps the fixture's branch addresses to
# source lines in the exact `addr2line -a -f -C -i` output shape (address line,
# then function/file:line pairs), so run() can be exercised end to end without a
# toolchain.
_A2L_TABLE = {a: (v[2], "%s:%d" % (v[0], v[1])) for a, v in LOCATIONS.items()}
FAKE_ADDR2LINE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "TABLE = " + repr(_A2L_TABLE) + "\n"
    "for raw in sys.stdin:\n"
    "    raw = raw.strip()\n"
    "    if not raw:\n"
    "        continue\n"
    "    print(raw)\n"
    "    func, fileline = TABLE.get(int(raw, 16), ('??', '??:?'))\n"
    "    print(func)\n"
    "    print(fileline)\n"
)


class TestBuildRecords(unittest.TestCase):
    def setUp(self):
        self.graph = cfg.analyze(TEXT, cfg.get_profile("microblaze"))

    def records(self, edges):
        counts, _ = cfg.match_edges(self.graph, edges)
        return branches.build_records(self.graph.branch_points, counts,
                                      LOCATIONS, {"arch": "microblaze"})

    def test_every_static_branch_is_reported_even_when_never_run(self):
        recs = self.records([])
        self.assertEqual(len(recs), 3)
        self.assertTrue(all(not r["evaluated"] for r in recs))
        self.assertTrue(all(r["taken"] == 0 and r["nottaken"] == 0
                            for r in recs))

    def test_block_is_the_targets_source_line(self):
        recs = {r["address"]: r for r in self.records([])}
        # Both halves of the `&&` exit to the else at line 12, so both carry
        # block 12 -- NOT 0 and 1, which would be their rank in this binary.
        self.assertEqual(recs["0x90000004"]["block"], 12)
        self.assertEqual(recs["0x90000010"]["block"], 12)
        # The unrelated branch on line 20 jumps to line 22.
        self.assertEqual(recs["0x9000001c"]["block"], 22)
        self.assertEqual(recs["0x9000001c"]["line"], 20)

    def test_counts_join_onto_the_right_branch(self):
        recs = {r["address"]: r for r in self.records([
            (0x90000008, 0x90000020, 4),    # branch 1 taken (via delay slot)
            (0x90000014, 0x90000018, 6),    # branch 2 NOT taken
        ])}
        self.assertEqual((recs["0x90000004"]["taken"],
                          recs["0x90000004"]["nottaken"]), (4, 0))
        self.assertTrue(recs["0x90000004"]["evaluated"])
        self.assertEqual((recs["0x90000010"]["taken"],
                          recs["0x90000010"]["nottaken"]), (0, 6))
        self.assertFalse(recs["0x9000001c"]["evaluated"])

    def test_branch_without_source_mapping_is_dropped(self):
        counts, _ = cfg.match_edges(self.graph, [])
        recs = branches.build_records(self.graph.branch_points, counts,
                                      {0x90000004: (SRC, 10, "main")}, {})
        self.assertEqual([r["address"] for r in recs], ["0x90000004"])


class TestBlockIsSourceIdentity(unittest.TestCase):
    """`block` must name a branch by SOURCE, never by its position among the
    branches this particular binary happens to carry on the line.

    A rank shifts the moment one binary inlines a call site more, or folds one
    half of `a && b` away -- and merge.py, keying on (file, line, block,
    branch), would then add two unrelated branches together.
    """

    @staticmethod
    def bp(addr, taken, fallthrough):
        # block_start/block_end only matter to edge matching, not to the key.
        return cfg.BranchPoint(addr, "bnei", taken, fallthrough, addr, addr)

    def blocks(self, points, locations):
        recs = branches.build_records(points, {}, locations, {})
        return {r["address"]: r["block"] for r in recs}

    def test_same_source_branch_at_different_addresses_keys_the_same(self):
        """The whole point: relinking moves every address and must move no key.

        `if (b) then; else after;` on line 10, compiled into two separately
        linked binaries at unrelated bases.
        """
        a = self.blocks([self.bp(0x90000004, 0x90000014, 0x90000008)],
                        {0x90000004: (SRC, 10, "main"),
                         0x90000014: (SRC, 13, "main"),
                         0x90000008: (SRC, 11, "main")})
        b = self.blocks([self.bp(0x80002004, 0x80002010, 0x80002008)],
                        {0x80002004: (SRC, 10, "main"),
                         0x80002010: (SRC, 13, "main"),
                         0x80002008: (SRC, 11, "main")})
        self.assertEqual(list(a.values()), [13])
        self.assertEqual(list(b.values()), [13])

    def test_a_neighbouring_branch_appearing_does_not_renumber(self):
        """`a || b` on line 10: the first test exits into the body (line 11),
        the second past it (line 13). Fold `a` away in the second binary and the
        surviving branch must keep its key -- under address ranking it would
        drop from block 1 to block 0 and merge onto the wrong branch."""
        locs = {0x90000004: (SRC, 10, "main"), 0x90000008: (SRC, 10, "main"),
                0x9000000c: (SRC, 10, "main"), 0x90000010: (SRC, 11, "main"),
                0x90000014: (SRC, 11, "main"), 0x9000001c: (SRC, 13, "main")}
        both = self.blocks([self.bp(0x90000004, 0x90000014, 0x90000008),
                            self.bp(0x9000000c, 0x9000001c, 0x90000010)], locs)
        self.assertEqual(both, {"0x90000004": 11, "0x9000000c": 13})

        only_second = self.blocks(
            [self.bp(0x9000000c, 0x9000001c, 0x90000010)], locs)
        self.assertEqual(only_second, {"0x9000000c": 13})
        self.assertEqual(both["0x9000000c"], only_second["0x9000000c"])

    def test_falls_back_to_fallthrough_then_to_zero(self):
        point = self.bp(0x90000004, 0x90000014, 0x90000008)
        # Taken target outside the kept path set -> the fall-through's line.
        self.assertEqual(
            self.blocks([point], {0x90000004: (SRC, 10, "main"),
                                  0x90000008: (SRC, 11, "main")}),
            {"0x90000004": 11})
        # Neither target mapped -> 0, and the branch is still reported.
        self.assertEqual(
            self.blocks([point], {0x90000004: (SRC, 10, "main")}),
            {"0x90000004": 0})


class TestBranchesCommand(unittest.TestCase):
    """End-to-end run() with objdump and addr2line stubbed out."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.disasm = os.path.join(self.d, "a.dis")
        with open(self.disasm, "w") as f:
            f.write(TEXT)
        self.a2l = os.path.join(self.d, "fake-addr2line")
        with open(self.a2l, "w") as f:
            f.write(FAKE_ADDR2LINE)
        os.chmod(self.a2l, os.stat(self.a2l).st_mode | stat.S_IEXEC)
        self.cov = os.path.join(self.d, "t.cov")
        with open(self.cov, "wb") as f:
            f.write(build_cov({"test_id": "t1", "target_name": "microblazeel"},
                              [(0x90000008, 0x90000020, 4),
                               (0x90000014, 0x90000018, 6)]))
        self.out = os.path.join(self.d, "br.jsonl")

    def run_branches(self, extra=()):
        argv = ["--elf", os.path.join(self.d, "a.elf"),
                "--disasm", self.disasm, "--addr2line", self.a2l,
                "--all-paths", "--out", self.out] + list(extra)
        return branches.main(argv)

    def test_end_to_end(self):
        self.assertEqual(self.run_branches(["--cov", self.cov]), 0)
        recs = [json.loads(l) for l in open(self.out)]
        self.assertEqual(len(recs), 3)
        self.assertTrue(all(r["file"] == SRC for r in recs))
        self.assertEqual(recs[0]["test_id"], "t1")
        by_addr = {r["address"]: r for r in recs}
        self.assertEqual(by_addr["0x90000004"]["taken"], 4)
        self.assertEqual(by_addr["0x90000010"]["nottaken"], 6)
        self.assertFalse(by_addr["0x9000001c"]["evaluated"])
        # Delay-slot fall-through, recorded for downstream inspection.
        self.assertEqual(by_addr["0x90000004"]["fallthrough"], "0x9000000c")

    def test_static_only_without_cov(self):
        self.assertEqual(self.run_branches(), 0)
        recs = [json.loads(l) for l in open(self.out)]
        self.assertEqual(len(recs), 3)
        self.assertTrue(all(not r["evaluated"] for r in recs))

    def test_unsupported_arch_refuses(self):
        rc = self.run_branches(["--arch", "vax"])
        self.assertEqual(rc, 2)          # never silently wrong data
        self.assertFalse(os.path.exists(self.out))


class TestBrdaEmission(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.br = os.path.join(self.d, "br.jsonl")
        self.cov = os.path.join(self.d, "cov.jsonl")
        self.out = os.path.join(self.d, "out.info")
        with open(self.cov, "w") as f:
            for line in (10, 20):
                f.write(json.dumps({"file": SRC, "line": line,
                                    "function": "main", "count": 1}) + "\n")

    def write_branches(self, recs):
        with open(self.br, "w") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

    def brda(self):
        out = []
        for line in open(self.out):
            line = line.strip()
            if line.startswith(("BRDA:", "BRF:", "BRH:")):
                out.append(line)
        return out

    def test_dash_for_never_evaluated_zero_for_never_taken(self):
        self.write_branches([
            # Evaluated, only ever taken -> "4" and "0".
            {"file": SRC, "line": 10, "block": 0, "taken": 4, "nottaken": 0,
             "evaluated": True},
            # Never evaluated -> "-" on BOTH outcomes.
            {"file": SRC, "line": 20, "block": 0, "taken": 0, "nottaken": 0,
             "evaluated": False},
        ])
        rc = lcov_main([self.cov, "--branches", self.br, "--out", self.out])
        self.assertEqual(rc, 0)
        self.assertEqual(self.brda(), [
            "BRDA:10,0,0,4",
            "BRDA:10,0,1,0",     # evaluated but this way never went
            "BRDA:20,0,0,-",     # never evaluated at all
            "BRDA:20,0,1,-",
            "BRF:4",
            "BRH:1",             # only one outcome was actually taken
        ])

    def test_branch_records_precede_line_records(self):
        self.write_branches([{"file": SRC, "line": 10, "block": 0, "taken": 1,
                              "nottaken": 1, "evaluated": True}])
        lcov_main([self.cov, "--branches", self.br, "--out", self.out])
        keys = [l.split(":", 1)[0] for l in open(self.out)]
        self.assertLess(keys.index("BRDA"), keys.index("DA"))
        self.assertIn("BRF", keys)


if __name__ == "__main__":
    unittest.main()
