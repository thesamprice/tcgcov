"""Tests for redacting an artifact so it can be shared (tcgcov.dump).

An artifact embeds the absolute path of the ELF it was recorded against, so
that the host tools need no separate manifest. Attaching one to a bug report
therefore discloses the filesystem layout of the machine that produced it.

The fixtures spell a user's home as '/u/<name>/' rather than '/home/<name>/'.
Nothing here depends on the prefix -- the scrub only cares that a value has
directory components -- and CI rejects committed '/home/...' and '/Users/...'
literals. Exempting this file from that check would leave the one file whose
subject is leaked paths unguarded against leaking a real one.
"""

import json
import os
import struct
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from tcgcov import dump, format as fmt  # noqa: E402


def build_cov(path, elf, test_id="", n_addrs=3, n_edges=2):
    """Write a minimal but valid TCGCOV1 artifact with counts and edges."""
    meta = json.dumps({
        "format": "tcgcov", "version": 1, "mode": "tb-insn",
        "target_name": "riscv32", "system_emulation": True,
        "test_id": test_id, "bsp": "rv32imafdc", "elf": elf,
        "address_kind": "vaddr", "counts_enabled": True,
        "record_count": n_addrs, "edges_enabled": True,
        "edge_count": n_edges, "filters": [],
    }).encode() + b"\n"
    recs = b"".join(struct.pack("<QQ", 0x1000 + 4 * i, i + 1)
                    for i in range(n_addrs))
    edges = b"".join(struct.pack("<QQQ", 0x1000 + 4 * i, 0x1004 + 4 * i, i + 1)
                     for i in range(n_edges))
    hsize = struct.calcsize(fmt.HEADER_FMT)
    hdr = struct.pack(
        fmt.HEADER_FMT, fmt.MAGIC, 1, 1, hsize, 2,
        fmt.FLAG_HAS_COUNTS | fmt.FLAG_HAS_EDGES | fmt.FLAG_EDGE_COUNTS,
        n_addrs, hsize, len(meta), hsize + len(meta), len(recs),
        n_edges, hsize + len(meta) + len(recs), len(edges))
    with open(path, "wb") as f:
        f.write(hdr + meta + recs + edges)
    return path


class TestScrubMetadata(unittest.TestCase):

    def test_absolute_elf_path_becomes_a_basename(self):
        meta = {"elf": "/u/someone/build/tests/hello.exe", "bsp": "x"}
        out = dump.scrub_metadata(meta)
        self.assertEqual(out["elf"], "hello.exe")
        self.assertEqual(out["bsp"], "x")
        self.assertTrue(out["scrubbed"])

    def test_basename_is_kept_not_dropped(self):
        """The basename identifies which test the artifact is for, which is
        usually why it is being shared, and is not itself a disclosure."""
        self.assertEqual(
            dump.scrub_metadata({"elf": "/a/b/ticker.exe"})["elf"],
            "ticker.exe")

    def test_free_form_labels_are_scrubbed_only_when_they_are_paths(self):
        """test_id and bsp are user supplied; a caller may have put a path
        in one, but an ordinary label must survive untouched."""
        out = dump.scrub_metadata({"test_id": "/u/me/runs/run7",
                                   "bsp": "rv32imafdc"})
        self.assertEqual(out["test_id"], "run7")
        self.assertEqual(out["bsp"], "rv32imafdc")

    def test_scrub_is_idempotent(self):
        once = dump.scrub_metadata({"elf": "/a/b/hello.exe"})
        self.assertEqual(dump.scrub_metadata(once), once)


class TestScrubbedArtifact(unittest.TestCase):

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.src = build_cov(os.path.join(self.d, "in.cov"),
                             "/u/someone/build/hello.exe")
        self.dst = os.path.join(self.d, "out.cov")

    def test_payload_survives_the_header_rebuild(self):
        """The metadata changes LENGTH, so the record and edge sections move
        and the header offsets must be recomputed. Everything else must come
        through byte for byte."""
        dump.write_scrubbed(self.src, self.dst)
        a = fmt.read_all(self.src)
        b = fmt.read_all(self.dst)
        self.assertEqual(a[1], b[1])            # addresses
        self.assertEqual(a[2], b[2])            # counts
        self.assertEqual(a[3], b[3])            # edges
        self.assertEqual(b[0]["elf"], "hello.exe")
        self.assertTrue(b[0]["scrubbed"])

    def test_no_directory_path_survives(self):
        dump.write_scrubbed(self.src, self.dst)
        with open(self.src, "rb") as f:
            self.assertIn(b"/u/someone/", f.read())
        with open(self.dst, "rb") as f:
            self.assertNotIn(b"/u/someone/", f.read())

    def test_result_is_a_valid_artifact(self):
        """It must still parse -- a scrubbed artifact that cannot be read is
        of no use to the person you sent it to."""
        dump.write_scrubbed(self.src, self.dst)
        with open(self.dst, "rb") as f:
            hdr = fmt.parse_header(f.read(), self.dst)
        self.assertEqual(hdr["record_count"], 3)
        self.assertEqual(hdr["edge_count"], 2)

    def test_writing_is_atomic(self):
        """A partial file must never appear at the destination."""
        dump.write_scrubbed(self.src, self.dst)
        self.assertFalse(os.path.exists(self.dst + ".tmp"))


if __name__ == "__main__":
    unittest.main()
