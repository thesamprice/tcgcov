"""modmap: window validation, per-section slicing, rebase arithmetic."""

import json
import os
import tempfile
import unittest

from tcgcov.format import read_all, write_cov
from tcgcov.modmap import load_map, slice_cov

MAP = [
    {"object": "dl-o1.o", "file": "/elf/dl-o1.o",
     "sections": [{"name": ".text", "addr": "0x90010000", "size": 0x100},
                  {"name": ".rodata", "addr": "0x90020000", "size": 0x40}]},
    {"object": "dl-o2.o",
     "sections": [{"name": ".text", "addr": 0x90030000, "size": 0x80},
                  {"name": ".empty", "addr": 0x90040000, "size": 0}]},
]

RECORDS = [
    (0x90010000, 3),     # o1 .text start
    (0x90010040, 7),     # o1 .text +0x40
    (0x900100FF, 1),     # o1 .text last byte
    (0x90010100, 9),     # just past o1 .text -- must NOT match
    (0x90020010, 2),     # o1 .rodata
    (0x90030008, 5),     # o2 .text
    (0xC0000000, 100),   # base image
]
EDGES = [
    (0x90010004, 0x90010040, 4),     # inside o1 .text
    (0x90010004, 0x90030008, 6),     # crosses objects -- dropped
    (0xC0000000, 0xC0000004, 50),    # base image -- dropped
]


class ModMapTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cov = os.path.join(self.dir.name, "in.cov")
        write_cov(self.cov, {"mode": "tb"}, RECORDS, EDGES)
        self.map_path = os.path.join(self.dir.name, "map.json")
        with open(self.map_path, "w") as f:
            json.dump(MAP, f)

    def test_slice_and_rebase(self):
        windows = load_map(self.map_path)
        outputs, matched, unmatched = slice_cov(
            self.cov, windows, os.path.join(self.dir.name, "out"))
        self.assertEqual(matched, 5)
        self.assertEqual(unmatched, 2)   # 0x90010100 and the base image addr

        by = {(o["object"], o["section"]): o for o in outputs}
        self.assertEqual(set(by), {("dl-o1.o", ".text"),
                                   ("dl-o1.o", ".rodata"),
                                   ("dl-o2.o", ".text")})

        o1 = by[("dl-o1.o", ".text")]
        meta, addrs, counts, edges = read_all(o1["out"])
        self.assertEqual(sorted(addrs), [0x0, 0x40, 0xFF])
        self.assertEqual(counts[0x40], 7)
        self.assertEqual(edges, [(0x4, 0x40, 4)])   # cross-object edge gone
        self.assertEqual(meta["module"], "dl-o1.o")
        self.assertEqual(meta["module_section"], ".text")
        self.assertEqual(meta["module_file"], "/elf/dl-o1.o")
        self.assertEqual(meta["rebased_from"], "0x90010000")

        o2 = by[("dl-o2.o", ".text")]
        _m, addrs2, counts2, edges2 = read_all(o2["out"])
        self.assertEqual(addrs2, [0x8])
        self.assertEqual(edges2, [])

    def test_overlap_is_an_error(self):
        bad = MAP + [{"object": "evil.o", "sections":
                      [{"name": ".text", "addr": 0x900100F0, "size": 0x20}]}]
        with open(self.map_path, "w") as f:
            json.dump(bad, f)
        with self.assertRaisesRegex(ValueError, "overlap"):
            load_map(self.map_path)

    def test_adjacent_windows_are_fine(self):
        ok = [{"object": "a.o", "sections":
               [{"name": ".text", "addr": 0x1000, "size": 0x100}]},
              {"object": "b.o", "sections":
               [{"name": ".text", "addr": 0x1100, "size": 0x100}]}]
        with open(self.map_path, "w") as f:
            json.dump(ok, f)
        self.assertEqual(len(load_map(self.map_path)), 2)

    def test_malformed_map(self):
        for bad in ({"object": "x"},                       # not a list
                    [{"sections": []}],                    # nameless
                    [{"object": "x", "sections": [{"name": ".text"}]}]):
            with open(self.map_path, "w") as f:
                json.dump(bad, f)
            with self.assertRaises(ValueError):
                load_map(self.map_path)



class GenerationReuseTest(unittest.TestCase):
    """Cross-object temporal reuse: object A's window is reused by object B
    after an unload; per-generation slicing attributes each correctly, and a
    merged map is refused. (The stock RTEMS dl tests reuse addresses only
    with the same object -- examples/rtems-dl covers that live; this pins
    the harder different-object case at the format level.)"""

    BASE = 0x80050000

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.cov = os.path.join(self.dir.name, "in.cov")
        # gen 1: object A live at BASE; gen 3: object B live at BASE.
        records = [
            (1, self.BASE + 0x10, 5),      # A's code
            (1, self.BASE + 0x20, 2),
            (3, self.BASE + 0x10, 7),      # B's code, SAME address
            (3, self.BASE + 0x40, 1),
        ]
        write_cov(self.cov, {"ctx_kind": "loader-generation"}, records,
                  ctx=True)

    def _map(self, obj, size):
        p = os.path.join(self.dir.name, obj + ".json")
        with open(p, "w") as f:
            json.dump([{"object": obj, "sections":
                        [{"name": ".text", "addr": self.BASE,
                          "size": size}]}], f)
        return p

    def test_per_generation_slices(self):
        from tcgcov.format import read_all
        wa = load_map(self._map("a.o", 0x30))
        out_a, m_a, _ = slice_cov(self.cov, wa,
                                  os.path.join(self.dir.name, "a"), ctx=1)
        self.assertEqual(m_a, 2)
        _m, addrs, counts, _e = read_all(out_a[0]["out"])
        self.assertEqual(counts[0x10], 5)          # A's count, not 12

        wb = load_map(self._map("b.o", 0x50))
        out_b, m_b, _ = slice_cov(self.cov, wb,
                                  os.path.join(self.dir.name, "b"), ctx=3)
        self.assertEqual(m_b, 2)
        _m, addrs, counts, _e = read_all(out_b[0]["out"])
        self.assertEqual(counts[0x10], 7)          # B's count at the SAME addr
        self.assertEqual(counts[0x40], 1)

    def test_merged_lifetimes_refused(self):
        both = os.path.join(self.dir.name, "both.json")
        with open(both, "w") as f:
            json.dump([
                {"object": "a.o", "sections":
                 [{"name": ".text", "addr": self.BASE, "size": 0x30}]},
                {"object": "b.o", "sections":
                 [{"name": ".text", "addr": self.BASE, "size": 0x50}]}], f)
        with self.assertRaisesRegex(ValueError, "overlap"):
            load_map(both)

if __name__ == "__main__":
    unittest.main()
