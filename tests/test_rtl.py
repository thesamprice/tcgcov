"""rtl: --obj-path resolution, verification, and the per-generation split.

The objects here are tiny synthetic ELF32 relocatables built in-process, so
the resolution rules are pinned without a cross toolchain: the live checks
against RTEMS dl01/dl09 and the pay_a/pay_b reuse fixture are in
examples/rtems-dl/README.md.
"""

import contextlib
import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import rtl                                        # noqa: E402
from tcgcov.format import FLAG_HAS_EDGES, read_all, read_full, write_cov  # noqa

ALLOC, EXEC = 0x2, 0x4


def make_elf(sections, symbols=(), debug=True, e_type=1):
    """ELF32 LE bytes: sections [(name, size, align, flags)], symbols
    [(name, value)] (absolute), plus .debug_info when debug=True."""
    secs = [(n, sz, al, fl, 1) for n, sz, al, fl in sections]   # PROGBITS
    if debug:
        secs.append((".debug_info", 4, 1, 0, 1))
    names = [""] + [s[0] for s in secs] + [".symtab", ".strtab", ".shstrtab"]
    shstr = b"\0"
    off_of = {}
    for n in names[1:]:
        off_of[n] = len(shstr)
        shstr += n.encode() + b"\0"
    strtab, syms = b"\0", [b"\0" * 16]
    for n, v in symbols:
        syms.append(struct.pack("<IIIBBH", len(strtab), v, 0, 0x10, 0, 0xFFF1))
        strtab += n.encode() + b"\0"
    symtab = b"".join(syms)

    body = b""
    hdrs = [b"\0" * 40]
    base = 52
    for n, sz, al, fl, typ in secs:
        hdrs.append(struct.pack("<10I", off_of[n], typ, fl, 0,
                                base + len(body), sz, 0, 0, al, 0))
        body += b"\x13" * sz
    nsec = len(secs) + 1
    hdrs.append(struct.pack("<10I", off_of[".symtab"], 2, 0, 0,
                            base + len(body), len(symtab), nsec + 1, 1, 4, 16))
    body += symtab
    hdrs.append(struct.pack("<10I", off_of[".strtab"], 3, 0, 0,
                            base + len(body), len(strtab), 0, 0, 1, 0))
    body += strtab
    hdrs.append(struct.pack("<10I", off_of[".shstrtab"], 3, 0, 0,
                            base + len(body), len(shstr), 0, 0, 1, 0))
    body += shstr
    shoff = base + len(body)
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", e_type, 243, 1, 0, 0, shoff,
                               0, 52, 0, 0, 40, len(hdrs), len(hdrs) - 1)
    return ehdr + body + b"".join(hdrs)


def make_ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        hdr = ("%-16s%-12s%-6s%-6s%-8s%-10d`\n"
               % (name + "/", 0, 0, 0, 644, len(data))).encode()
        out += hdr + data + (b"\n" if len(data) & 1 else b"")
    return out


A_SECS = [(".text.f", 0x40, 4, ALLOC | EXEC), (".text.g", 0x20, 4,
          ALLOC | EXEC), (".rodata", 0x10, 8, ALLOC)]
B_SECS = [(".text.h", 0x60, 4, ALLOC | EXEC)]


def snap(name, base, secs, offsets=True, const=0):
    """A plugin-style snapshot entry for an object laid out from `base`."""
    out, running = [], {0: 0, 1: 0}
    for n, sz, al, fl in secs:
        rap = 0 if fl & EXEC else 1
        off = (running[rap] + al - 1) // al * al
        running[rap] = off + sz
        e = {"name": n, "size": sz, "rap": rap}
        if offsets:
            e["offset"] = off
        out.append(e)
    entry = {"object": name, "text": "0x%x" % base, "sections": out}
    if const:
        entry["const"] = "0x%x" % const
    return entry


class Fixture(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def put(self, rel, data):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p


class ResolveTest(Fixture):
    def test_basename_found_recursively(self):
        p = self.put("build/sub/a.o", make_elf(A_SECS))
        res = rtl.resolve(rtl.ObjectPath([os.path.join(self.d, "build")]),
                          "/a.o", snap("/a.o", 0x1000, A_SECS)["sections"])
        self.assertIsNone(res.error)
        self.assertEqual(res.cand.path, p)

    def test_relative_path_under_a_dir(self):
        p = self.put("root/lib/a.o", make_elf(A_SECS))
        self.put("root/other/a.o", make_elf(B_SECS))      # wrong one
        res = rtl.resolve(rtl.ObjectPath([os.path.join(self.d, "root")]),
                          "/lib/a.o", snap("/lib/a.o", 0, A_SECS)["sections"])
        self.assertEqual(res.cand.path, p)

    def test_archive_member(self):
        self.put("libs/libx.a", make_ar([("a.o", make_elf(A_SECS)),
                                         ("b.o", make_elf(B_SECS))]))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "b.o",
                          snap("b.o", 0, B_SECS)["sections"])
        self.assertIsNone(res.error)
        self.assertEqual(res.cand.member, "b.o")

    def test_size_mismatch_is_a_conflict(self):
        self.put("a.o", make_elf(B_SECS))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "a.o",
                          snap("a.o", 0, A_SECS)["sections"])
        self.assertEqual(res.kind, "conflict")
        self.assertIn("no section .text.f", res.error)

    def test_rebuilt_object_with_changed_size_is_rejected(self):
        changed = [(".text.f", 0x44, 4, ALLOC | EXEC)] + A_SECS[1:]
        self.put("a.o", make_elf(changed))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "a.o",
                          snap("a.o", 0, A_SECS)["sections"])
        self.assertEqual(res.kind, "conflict")
        self.assertIn("68 bytes, the target loaded 64", res.error)

    def test_no_verify_takes_the_first(self):
        self.put("a.o", make_elf(B_SECS))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "a.o",
                          snap("a.o", 0, A_SECS)["sections"], no_verify=True)
        self.assertIsNone(res.error)

    def test_two_different_matches_are_ambiguous(self):
        self.put("x/a.o", make_elf(A_SECS))
        self.put("y/a.o", make_elf(A_SECS, symbols=[("extra", 1)]))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "a.o",
                          snap("a.o", 0, A_SECS)["sections"])
        self.assertEqual(res.kind, "conflict")
        self.assertIn("ambiguous", res.error)

    def test_identical_copies_are_not_ambiguous(self):
        self.put("x/a.o", make_elf(A_SECS))
        self.put("y/a.o", make_elf(A_SECS))
        res = rtl.resolve(rtl.ObjectPath([self.d]), "a.o",
                          snap("a.o", 0, A_SECS)["sections"])
        self.assertIsNone(res.error)

    def test_missing(self):
        res = rtl.resolve(rtl.ObjectPath([self.d]), "nope.o", [])
        self.assertEqual(res.kind, "missing")


class StrippedTest(Fixture):
    """The target loads a stripped object; the host keeps the debug twin."""

    def setUp(self):
        super().setUp()
        self.stripped = self.put("target/a.o", make_elf(A_SECS, debug=False))
        self.sections = snap("/a.o", 0, A_SECS)["sections"]

    def test_stripped_only_resolves_with_a_warning(self):
        res = rtl.resolve(rtl.ObjectPath([os.path.join(self.d, "target")]),
                          "/a.o", self.sections)
        self.assertEqual(res.cand.path, self.stripped)
        self.assertIn("no DWARF", res.warning)

    def test_suffixed_twin_wins_over_the_exact_stripped_hit(self):
        for twin in ("host/a.o.debug", "host2/a.debug"):
            p = self.put(twin, make_elf(A_SECS))
            dirs = [os.path.join(self.d, "target"),
                    os.path.join(self.d, os.path.dirname(twin))]
            res = rtl.resolve(rtl.ObjectPath(dirs, [".debug"]), "/a.o",
                              self.sections)
            self.assertIsNone(res.error)
            self.assertEqual(res.cand.path, p)
            self.assertIsNone(res.warning)

    def test_suffix_replacing_the_extension(self):
        p = self.put("host/a.dbg.o", make_elf(A_SECS))
        res = rtl.resolve(rtl.ObjectPath([self.d], [".dbg.o"]), "/a.o",
                          self.sections)
        self.assertEqual(res.cand.path, p)

    def test_without_the_suffix_the_twin_is_not_found(self):
        self.put("host/a.o.debug", make_elf(A_SECS))
        res = rtl.resolve(rtl.ObjectPath([os.path.join(self.d, "host")]),
                          "/a.o", self.sections)
        self.assertEqual(res.kind, "missing")


class WindowsTest(unittest.TestCase):
    def test_recorded_offsets_are_used_verbatim(self):
        e = snap("a.o", 0x1000, A_SECS, const=0x2000)
        e["sections"][1]["offset"] = 0x48          # loader padded more
        w = {n: s for s, _e, n, _r in rtl.object_windows(e)}
        self.assertEqual(w[".text.g"], 0x1048)
        self.assertEqual(w[".rodata"], 0x2000)

    def test_old_snapshots_are_laid_out_with_the_object_alignment(self):
        secs = [(".text.a", 6, 2, ALLOC | EXEC), (".text.b", 8, 8,
                ALLOC | EXEC)]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.o")
            with open(p, "wb") as f:
                f.write(make_elf(secs))
            e = snap("a.o", 0x1000, secs, offsets=False)
            w = {n: s for s, _e, n, _r in
                 rtl.object_windows(e, rtl.Candidate(p))}
        self.assertEqual(w[".text.b"], 0x1008)     # 6 rounded up to 8


class SplitTest(Fixture):
    BASE = 0x80050000

    def setUp(self):
        super().setUp()
        self.objs = os.path.join(self.d, "objs")
        self.put("objs/a.o", make_elf(A_SECS))
        self.put("objs/b.o", make_elf(B_SECS))
        # gen 1: A at BASE. gen 2: nothing. gen 3: B at BASE (reuse).
        # gen 5: A again at a different address (second lifetime).
        gens = {"1": [snap("/a.o", self.BASE, A_SECS)], "2": [],
                "3": [snap("/b.o", self.BASE, B_SECS)],
                "5": [snap("/a.o", self.BASE + 0x1000, A_SECS)]}
        recs = [
            (0, 0x80000000, 9),                  # base image, boot
            (1, self.BASE + 0x10, 5),            # A .text.f +0x10
            (1, self.BASE + 0x44, 1),            # A .text.g +0x04
            (1, 0x80000000, 1),                  # base image during gen 1
            (3, self.BASE + 0x10, 7),            # B .text.h +0x10, SAME addr
            (5, self.BASE + 0x1010, 2),          # A again, .text.f +0x10
        ]
        edges = [(1, self.BASE + 0x8, self.BASE + 0x10, 4),
                 (3, self.BASE + 0x8, self.BASE + 0x10, 6),
                 (1, self.BASE + 0x8, 0x80000000, 1)]   # crosses -> dropped
        self.cov = os.path.join(self.d, "run.cov")
        write_cov(self.cov, {"ctx_kind": "loader-generation",
                             "rtl_generations": gens, "elf": "/base.exe"},
                  recs, edges, ctx=True)

    def split(self, **kw):
        objpath = rtl.ObjectPath([self.objs], kw.pop("suffixes", ()))
        return rtl.split(self.cov, objpath, os.path.join(self.d, "out"), **kw)

    def test_reuse_and_lifetimes(self):
        s = self.split()
        by = {(os.path.basename(m["object"]), m["section"]): m
              for m in s["modules"]}
        meta, addrs, counts, edges = read_all(by[("a.o", ".text.f")]["out"])
        self.assertEqual(counts, {0x10: 7})       # 5 (gen 1) + 2 (gen 5)
        self.assertEqual(meta["module_generations"], [1, 5])
        self.assertTrue(meta["module_file"].endswith("objs/a.o"))
        self.assertEqual(edges, [(0x8, 0x10, 4)])
        _m, _a, counts_b, edges_b = read_all(by[("b.o", ".text.h")]["out"])
        self.assertEqual(counts_b, {0x10: 7})     # B's own 7, not A's
        self.assertEqual(edges_b, [(0x8, 0x10, 6)])
        self.assertEqual(s["crossing_edges"], 1)

        _m, _a, base_counts, _e = read_all(s["base"])
        self.assertEqual(base_counts, {0x80000000: 10})
        self.assertNotIn("rtl_generations", _m)

    def test_unexecuted_text_gets_an_empty_slice_with_edges_flag(self):
        s = self.split()
        g = [m for m in s["modules"] if m["section"] == ".text.g"][0]
        self.assertEqual(g["records"], 1)
        # .rodata is not executable and never ran: no slice.
        self.assertFalse([m for m in s["modules"]
                          if m["section"] == ".rodata"])
        # an edges=on artifact's slices keep the edge flag even when empty
        _meta, hdr, _r, _e = read_full(g["out"])
        self.assertTrue(hdr["flags"] & FLAG_HAS_EDGES)

    def test_unresolved_is_counted_not_misattributed(self):
        os.remove(os.path.join(self.objs, "b.o"))
        s = self.split()
        self.assertEqual(s["unresolved"]["/b.o"]["kind"], "missing")
        self.assertEqual(s["unresolved"]["/b.o"]["addrs"], 1)
        _m, _a, base_counts, _e = read_all(s["base"])
        self.assertNotIn(self.BASE + 0x10, base_counts)

    def test_self_overlapping_snapshot_is_an_error(self):
        gens = {"1": [snap("/a.o", self.BASE, A_SECS),
                      snap("/b.o", self.BASE + 0x8, B_SECS)]}
        write_cov(self.cov, {"ctx_kind": "loader-generation",
                             "rtl_generations": gens}, [(1, self.BASE, 1)],
                  ctx=True)
        with self.assertRaisesRegex(ValueError, "overlaps itself"):
            self.split()

    def test_plain_artifact_is_refused(self):
        write_cov(self.cov, {"elf": "/x"}, [(0x1000, 1)])
        with self.assertRaisesRegex(ValueError, "not a loader-generation"):
            self.split()

    def test_cli_exit_codes(self):
        err = io.StringIO()
        argv = ["--cov", self.cov, "--obj-path", self.objs,
                "--out-dir", os.path.join(self.d, "o")]
        with contextlib.redirect_stderr(err):
            self.assertEqual(self._cli(argv), 0)
            self.put("objs/b.o", make_elf(A_SECS))       # wrong contents
            self.assertEqual(self._cli(argv), 1)
            os.remove(os.path.join(self.objs, "b.o"))
            self.assertEqual(self._cli(argv), 2)
        self.assertIn("records (addr x generation) dropped", err.getvalue())

    def _cli(self, argv):
        import argparse
        ap = argparse.ArgumentParser()
        rtl.add_arguments(ap)
        return rtl.run(ap.parse_args(argv))


class RtemsArgsTest(Fixture):
    def run_args(self, path, *extra):
        import argparse
        ap = argparse.ArgumentParser()
        rtl.add_args_arguments(ap)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = rtl.run_args(ap.parse_args([path] + list(extra)))
        return rc, out.getvalue().strip(), err.getvalue()

    def test_symbols_become_plugin_options(self):
        p = self.put("img.exe", make_elf(
            [], symbols=[("_rtld_debug_state", 0x8000b9cc),
                         ("_rtld_debug", 0x800304d8),
                         ("rtems_rtl_debugger_load", 0x8000ba00)], e_type=2))
        rc, out, _ = self.run_args(p)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "rtl_state=0x8000b9cc,rtl_debug=0x800304d8,"
                              "rtl_load=0x8000ba00,elf=%s" % p)
        rc, out, _ = self.run_args(p, "--no-load-hook")
        self.assertNotIn("rtl_load", out)

    def test_image_without_libdl(self):
        p = self.put("img.exe", make_elf([], symbols=[("main", 1)]))
        rc, _out, err = self.run_args(p)
        self.assertEqual(rc, 1)
        self.assertIn("not linked with libdl", err)


if __name__ == "__main__":
    unittest.main()
