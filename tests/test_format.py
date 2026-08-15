"""Tests for the TCGCOV1 reader (tcgcov.format)."""

import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.format import (read_cov, read_all, read_edges, MAGIC, HEADER_FMT,  # noqa: E402
                           HEADER_SIZE, FLAG_HAS_COUNTS, FLAG_HAS_EDGES,
                           FLAG_EDGE_COUNTS)

# The pre-rename layout: 56 bytes, no edge fields. FORMAT.md section 7 is
# explicit that the magic changed in the same release that added the edge
# fields, so a short header under the TCGCOV1 magic is a CORRUPT file, and
# accepting it means decoding a truncated header as if it were whole.
SHORT_HEADER_FMT = "<8sHHIIIQQQQQ"
SHORT_HEADER_SIZE = struct.calcsize(SHORT_HEADER_FMT)   # 56


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


def build_short_header_cov(meta, addrs):
    """Serialize a 56-byte-header artifact (a truncated/corrupt TCGCOV1)."""
    meta_bytes = json.dumps(meta).encode("utf-8")
    rec_bytes = b"".join(struct.pack("<Q", a) for a in addrs)
    meta_off = SHORT_HEADER_SIZE
    rec_off = meta_off + len(meta_bytes)
    header = struct.pack(
        SHORT_HEADER_FMT, MAGIC, 1, 1, SHORT_HEADER_SIZE, 2, 0, len(addrs),
        meta_off, len(meta_bytes), rec_off, len(rec_bytes))
    return header + meta_bytes + rec_bytes


def patch_header(buf, field_offset, fmt, value):
    """Return `buf` with one header field overwritten."""
    packed = struct.pack(fmt, value)
    return buf[:field_offset] + packed + buf[field_offset + len(packed):]


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


VALID = build_cov({"test_id": "t", "target_name": "microblazeel"},
                  [(0x1000, 3), (0x1008, 1), (0x1010, 9)], has_counts=True,
                  edges=[(0x1000, 0x1008, 2), (0x1008, 0x1010, 4)],
                  edge_counts=True)


class TestHeaderValidation(unittest.TestCase):
    """A corrupt artifact must fail as a ValueError with a clear message.

    struct.error is NOT a subclass of ValueError, but every caller in the
    package catches (OSError, ValueError) -- so any field the reader trusts
    without checking turns a damaged file into an uncaught traceback instead of
    an error message, or worse, into plausible-looking wrong numbers.
    """

    def _write(self, buf):
        f = tempfile.NamedTemporaryFile(suffix=".cov", delete=False)
        f.write(buf)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def _expect_value_error(self, buf, needle=None):
        with self.assertRaises(ValueError) as ctx:
            read_all(self._write(buf))
        if needle:
            self.assertIn(needle, str(ctx.exception).lower())
        return ctx.exception

    def test_the_baseline_file_is_valid(self):
        meta, addrs, counts, edges = read_all(self._write(VALID))
        self.assertEqual(meta["test_id"], "t")
        self.assertEqual(addrs, [0x1000, 0x1008, 0x1010])
        self.assertEqual(counts[0x1010], 9)
        self.assertEqual(edges, [(0x1000, 0x1008, 2), (0x1008, 0x1010, 4)])

    def test_every_truncation_raises_valueerror(self):
        """The property test: no prefix of a valid file may decode.

        struct.unpack_from on a short buffer raises struct.error, which slips
        past every caller's except clause -- so this walks all 1..N-1 prefixes.
        """
        for length in range(len(VALID)):
            with self.subTest(length=length):
                try:
                    read_all(self._write(VALID[:length]))
                except ValueError:
                    pass
                except struct.error as e:      # not a ValueError subclass
                    self.fail(f"truncation at {length} raised struct.error "
                              f"({e}), which callers do not catch")
                else:
                    self.fail(f"truncation at {length} decoded successfully")

    def test_bad_magic(self):
        self._expect_value_error(b"RTQCov1\0" + VALID[8:], "magic")

    def test_short_header_is_rejected_not_reinterpreted(self):
        # 56-byte header: the pre-rename layout. Under the TCGCOV1 magic it can
        # only be a truncated/corrupt file (FORMAT.md section 7).
        self._expect_value_error(
            build_short_header_cov({"test_id": "old"}, [0x1000, 0x1004]))

    def test_bad_version(self):
        # version 2 became legal with the context records (same layout when
        # HAS_CTX is clear), so the unknown-version guard now starts at 3.
        self._expect_value_error(patch_header(VALID, 8, "<H", 3), "version")

    def test_big_endian_says_so(self):
        e = self._expect_value_error(patch_header(VALID, 10, "<H", 2))
        # Not "bad file": the field is legal, this reader just cannot do it.
        self.assertIn("big-endian", str(e).lower())

    def test_bad_endian(self):
        self._expect_value_error(patch_header(VALID, 10, "<H", 7), "endian")

    def test_header_size_below_88(self):
        self._expect_value_error(patch_header(VALID, 12, "<I", 56),
                                 "header_size")

    def test_records_size_not_a_multiple_of_the_stride(self):
        # 16-byte {addr,count} records (HAS_COUNTS is set in VALID).
        self._expect_value_error(patch_header(VALID, 56, "<Q", 40),
                                 "records_size")

    def test_edges_size_not_a_multiple_of_the_stride(self):
        # 24-byte {src,dst,count} edges (EDGE_COUNTS is set in VALID).
        self._expect_value_error(patch_header(VALID, 80, "<Q", 40),
                                 "edges_size")

    def test_section_offset_past_end_of_file(self):
        self._expect_value_error(patch_header(VALID, 48, "<Q", 1 << 40),
                                 "past the end")

    def test_section_size_past_end_of_file(self):
        self._expect_value_error(patch_header(VALID, 40, "<Q", 1 << 20),
                                 "past the end")

    def test_section_overlapping_the_header(self):
        self._expect_value_error(patch_header(VALID, 32, "<Q", 4), "header")

    def test_metadata_that_is_not_json(self):
        buf = bytearray(VALID)
        buf[HEADER_SIZE:HEADER_SIZE + 4] = b"\xff\xfe{ "
        self._expect_value_error(bytes(buf))


if __name__ == "__main__":
    unittest.main()
