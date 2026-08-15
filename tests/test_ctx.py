"""TCGCOV2 context records: writer/reader round trip, aggregation, extraction."""

import contextlib
import io
import os
import struct
import tempfile
import unittest

from tcgcov import contexts
from tcgcov.format import (read_all, read_full, write_cov, parse_header,
                           MAGIC, MAGIC_V2, HEADER_FMT, HEADER_SIZE,
                           FLAG_HAS_COUNTS, FLAG_HAS_CTX, CTX_UNAVAILABLE)

RECORDS = [
    (0x10, 0x1000, 5),
    (0x10, 0x1008, 2),
    (0x20, 0x1000, 7),          # same addr as ctx 0x10's first record
    (0x20, 0x2000, 1),
    (CTX_UNAVAILABLE, 0x3000, 4),
]
EDGES = [
    (0x10, 0x1004, 0x1008, 3),
    (0x20, 0x1004, 0x1008, 9),  # same edge, different ctx
    (0x20, 0x2004, 0x2008, 1),
]
META = {"mode": "tb", "ctx_enabled": True,
        "contexts": {"16": {"entries": 2}, "32": {"entries": 3}}}


class CtxFormatTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".cov")
        os.close(fd)
        self.addCleanup(os.unlink, self.path)
        write_cov(self.path, META, RECORDS, EDGES, ctx=True)

    def test_magic_and_flags(self):
        with open(self.path, "rb") as f:
            data = f.read()
        self.assertEqual(data[:8], MAGIC)   # one magic; version is the signal
        hdr = parse_header(data, self.path)
        self.assertEqual(hdr["version"], 2)
        self.assertTrue(hdr["flags"] & FLAG_HAS_CTX)
        self.assertEqual(hdr["records_size"], len(RECORDS) * 24)
        self.assertEqual(hdr["edges_size"], len(EDGES) * 32)

    def test_read_full_round_trip(self):
        meta, hdr, records, edges = read_full(self.path)
        self.assertEqual(meta["contexts"]["32"]["entries"], 3)
        self.assertEqual(records, sorted(RECORDS))
        self.assertEqual(edges, sorted(EDGES))

    def test_read_all_aggregates_across_contexts(self):
        meta, addrs, counts, edges = read_all(self.path)
        self.assertEqual(sorted(addrs), [0x1000, 0x1008, 0x2000, 0x3000])
        self.assertEqual(counts[0x1000], 12)        # 5 (ctx 10) + 7 (ctx 20)
        self.assertEqual(counts[0x3000], 4)
        self.assertIn((0x1004, 0x1008, 12), edges)  # 3 + 9 merged
        self.assertIn((0x2004, 0x2008, 1), edges)

    def test_read_all_filters_one_context(self):
        meta, addrs, counts, edges = read_all(self.path, ctx=0x20)
        self.assertEqual(sorted(addrs), [0x1000, 0x2000])
        self.assertEqual(counts[0x1000], 7)
        self.assertEqual(edges, [(0x1004, 0x1008, 9), (0x2004, 0x2008, 1)])

    def test_ctx_filter_on_v1_file_is_an_error(self):
        v1 = self.path + ".v1"
        write_cov(v1, {}, [(0x1000, 1)])
        self.addCleanup(os.unlink, v1)
        with self.assertRaises(ValueError):
            read_all(v1, ctx=0x10)

    def test_has_ctx_in_v1_header_rejected(self):
        blob = b"{}"
        hdr = struct.pack(HEADER_FMT, MAGIC, 1, 1, HEADER_SIZE, 1,
                          FLAG_HAS_COUNTS | FLAG_HAS_CTX, 0,
                          HEADER_SIZE, len(blob), 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "HAS_CTX"):
            parse_header(hdr + blob, "<forged>")

    def test_legacy_magic_with_v1_rejected(self):
        blob = b"{}"
        hdr = struct.pack(HEADER_FMT, MAGIC_V2, 1, 1, HEADER_SIZE, 1,
                          FLAG_HAS_COUNTS, 0,
                          HEADER_SIZE, len(blob), 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "legacy TCGCOV2 magic"):
            parse_header(hdr + blob, "<forged>")

    def test_legacy_magic_v2_still_reads(self):
        # The 2026-08-14 writer used a TCGCOV2 magic; readers keep it working.
        with open(self.path, "rb") as f:
            data = bytearray(f.read())
        data[:8] = MAGIC_V2
        legacy = self.path + ".legacy"
        with open(legacy, "wb") as f:
            f.write(data)
        self.addCleanup(os.unlink, legacy)
        _meta, hdr, records, _edges = read_full(legacy)
        self.assertEqual(hdr["version"], 2)
        self.assertEqual(records, sorted(RECORDS))

    def test_unknown_version_rejected(self):
        blob = b"{}"
        hdr = struct.pack(HEADER_FMT, MAGIC, 3, 1, HEADER_SIZE, 1,
                          FLAG_HAS_COUNTS, 0,
                          HEADER_SIZE, len(blob), 0, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "unsupported format version"):
            parse_header(hdr + blob, "<forged>")


class _Args:
    def __init__(self, **kw):
        self.elf = None
        self.extract = None
        self.out = None
        self.__dict__.update(kw)


class ContextsCommandTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".cov")
        os.close(fd)
        self.addCleanup(os.unlink, self.path)
        write_cov(self.path, META, RECORDS, EDGES, ctx=True)

    def _run(self, **kw):
        kw.setdefault("cov", self.path)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = contexts.run(_Args(**kw))
        return rc, out.getvalue(), err.getvalue()

    def test_list(self):
        rc, out, _err = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("3 contexts", out)
        self.assertIn("ctx 0x10: 2 records, 7 execs, 2 entries", out)
        self.assertIn("ctx <unavailable>: 1 records, 4 execs", out)

    def test_extract_round_trip(self):
        dst = self.path + ".x"
        self.addCleanup(os.unlink, dst)
        rc, _out, err = self._run(extract=0x20, out=dst)
        self.assertEqual(rc, 0)
        self.assertIn("2 records, 2 edges", err)

        with open(dst, "rb") as f:
            self.assertEqual(f.read(8), MAGIC)   # plain TCGCOV1 out
        meta, addrs, counts, edges = read_all(dst)
        self.assertEqual(sorted(addrs), [0x1000, 0x2000])
        self.assertEqual(counts[0x1000], 7)
        self.assertEqual(meta["extracted_ctx"], "0x20")

    def test_extract_absent_context(self):
        dst = self.path + ".x2"
        rc, _out, err = self._run(extract=0x99, out=dst)
        self.assertEqual(rc, 1)
        self.assertFalse(os.path.exists(dst))
        self.assertIn("contexts present", err)

    def test_extract_needs_out(self):
        rc, _out, err = self._run(extract=0x20)
        self.assertEqual(rc, 2)

    def test_v1_input_rejected(self):
        v1 = self.path + ".v1"
        write_cov(v1, {}, [(0x1000, 1)])
        self.addCleanup(os.unlink, v1)
        rc, _out, err = self._run(cov=v1)
        self.assertEqual(rc, 1)
        self.assertIn("no context records", err)


if __name__ == "__main__":
    unittest.main()
