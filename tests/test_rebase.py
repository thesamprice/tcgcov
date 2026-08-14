"""write_cov/read_all roundtrip and the rebase window arithmetic."""

import tempfile
import unittest

from tcgcov.format import read_all, write_cov
from tcgcov import rebase


class RebaseTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".cov") as f:
            write_cov(f.name, {"test_id": "t"},
                      [(0x1000, 3), (0x2000, 1)],
                      [(0x1000, 0x2000, 2)])
            meta, addrs, counts, edges = read_all(f.name)
            self.assertEqual(meta["test_id"], "t")
            self.assertEqual(addrs, [0x1000, 0x2000])
            self.assertEqual(counts[0x1000], 3)
            self.assertEqual(edges, [(0x1000, 0x2000, 2)])

    def test_window_and_delta(self):
        with tempfile.NamedTemporaryFile(suffix=".cov") as src, \
             tempfile.NamedTemporaryFile(suffix=".cov") as dst:
            write_cov(src.name, {},
                      [(0xF0073000, 5), (0xF0073100, 1), (0xF0080000, 9)],
                      [(0xF0073000, 0xF0073100, 4),
                       (0xF0073000, 0xF0080000, 1)])   # second: dst outside
            rc = rebase.run(rebase.main.__wrapped__ if False else
                            type("A", (), {"cov": src.name,
                                           "base": 0xF0073000,
                                           "size": 0x4000, "to": 0,
                                           "out": dst.name})())
            self.assertEqual(rc, 0)
            meta, addrs, counts, edges = read_all(dst.name)
            self.assertEqual(addrs, [0x0, 0x100])
            self.assertEqual(counts[0x0], 5)
            self.assertEqual(edges, [(0x0, 0x100, 4)])
            self.assertEqual(meta["rebased_from"], "0xf0073000")


if __name__ == "__main__":
    unittest.main()
