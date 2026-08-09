"""Tests for the TCGCOV1 reader (tcgcov.format)."""

import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.format import (read_cov, read_all, read_edges, MAGIC, HEADER_FMT,  # noqa: E402
                           HEADER_SIZE, HEADER_FMT_V1, HEADER_SIZE_V1,
                           FLAG_HAS_COUNTS, FLAG_HAS_EDGES, FLAG_EDGE_COUNTS)


def build_cov(meta, records, has_counts, edges=None, edge_counts=False):
    """Serialize an TCGCOV1 buffer (88-byte header).

    records is [addr] or [(addr,count)]; edges is [(src,dst)] or
    [(src,dst,count)] when edge_counts.
    """
    meta_bytes = json.dumps(meta).encode("utf-8")
    if has_counts:
        rec_bytes = b"".join(struct.pack("<QQ", a, c) for a, c in records)
        flags = FLAG_HAS_COUNTS
    else:
        rec_bytes = b"".join(struct.pack("<Q", a) for a in records)
        flags = 0
    if edges is None:
        edge_bytes = b""
        edge_n = 0
    else:
        flags |= FLAG_HAS_EDGES
        edge_n = len(edges)
        if edge_counts:
            flags |= FLAG_EDGE_COUNTS
            edge_bytes = b"".join(struct.pack("<QQQ", *e) for e in edges)
        else:
            edge_bytes = b"".join(struct.pack("<QQ", e[0], e[1]) for e in edges)
    meta_off = HEADER_SIZE
    rec_off = meta_off + len(meta_bytes)
    edge_off = rec_off + len(rec_bytes)
    header = struct.pack(
        HEADER_FMT, MAGIC, 1, 1, HEADER_SIZE, 2, flags, len(records),
        meta_off, len(meta_bytes), rec_off, len(rec_bytes),
        edge_n, edge_off, len(edge_bytes))
    return header + meta_bytes + rec_bytes + edge_bytes


def build_cov_v1(meta, addrs):
    """Serialize a legacy 56-byte-header (pre-edges) artifact."""
    meta_bytes = json.dumps(meta).encode("utf-8")
    rec_bytes = b"".join(struct.pack("<Q", a) for a in addrs)
    meta_off = HEADER_SIZE_V1
    rec_off = meta_off + len(meta_bytes)
    header = struct.pack(
        HEADER_FMT_V1, MAGIC, 1, 1, HEADER_SIZE_V1, 2, 0, len(addrs),
        meta_off, len(meta_bytes), rec_off, len(rec_bytes))
    return header + meta_bytes + rec_bytes


class TestReadCov(unittest.TestCase):
    def _write(self, buf):
        f = tempfile.NamedTemporaryFile(suffix=".cov", delete=False)
        f.write(buf)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def _roundtrip(self, buf):
        return read_cov(self._write(buf))

    def test_header_is_88_bytes(self):
        self.assertEqual(HEADER_SIZE, 88)
        self.assertEqual(HEADER_FMT, "<8sHHIIIQQQQQQQQ")

    def test_plain_addresses(self):
        meta = {"mode": "tb-insn", "test_id": "t", "target_name": "microblazeel"}
        addrs = [0x80000000, 0x80000004, 0x80001000]
        m, a, c = self._roundtrip(build_cov(meta, addrs, has_counts=False))
        self.assertEqual(m["test_id"], "t")
        self.assertEqual(a, addrs)
        self.assertIsNone(c)

    def test_counts(self):
        meta = {"mode": "tb-insn", "counts_enabled": True}
        records = [(0x80000000, 5), (0x80000004, 12253), (0x8000a1f8, 1620147382)]
        m, a, c = self._roundtrip(build_cov(meta, records, has_counts=True))
        self.assertEqual(a, [r[0] for r in records])
        self.assertEqual(c, {a_: c_ for a_, c_ in records})
        self.assertEqual(c[0x8000a1f8], 1620147382)  # > 2**31, needs 64-bit

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            self._roundtrip(b"NOTRTQCV" + b"\0" * 100)

    def test_legacy_56_byte_header_still_reads(self):
        addrs = [0x1000, 0x1004]
        m, a, c = self._roundtrip(build_cov_v1({"test_id": "old"}, addrs))
        self.assertEqual(m["test_id"], "old")
        self.assertEqual(a, addrs)
        self.assertIsNone(c)
        self.assertEqual(read_edges(self._write(
            build_cov_v1({}, addrs))), [])

    def test_edges_without_counts(self):
        edges = [(0x1000, 0x2000), (0x1008, 0x1010)]
        path = self._write(build_cov({}, [0x1000], False, edges=edges))
        meta, addrs, counts, got = read_all(path)
        # Count defaults to 1 so callers need not special-case the two modes.
        self.assertEqual(got, [(0x1000, 0x2000, 1), (0x1008, 0x1010, 1)])
        self.assertEqual(read_edges(path), got)
        # read_cov keeps its 3-tuple contract for existing callers.
        self.assertEqual(read_cov(path), (meta, addrs, counts))

    def test_edges_with_counts(self):
        edges = [(0x1000, 0x2000, 7), (0x1008, 0x1010, 1 << 40)]
        path = self._write(build_cov({}, [0x1000], False, edges=edges,
                                     edge_counts=True))
        self.assertEqual(read_edges(path), edges)

    def test_no_edges_section(self):
        path = self._write(build_cov({}, [0x1000], False))
        self.assertEqual(read_edges(path), [])


if __name__ == "__main__":
    unittest.main()
