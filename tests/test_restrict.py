"""Tests for restricting an aggregate .info to a target ELF (tcgcov.restrict).

The number this command prints is a qualification figure -- "how well is the
code that SHIPS tested" -- so the failure mode that matters is not a crash but
a plausible wrong figure. Every way of ending up with nothing to report (an
empty aggregate, an empty target inventory, two sides normalized differently)
used to write a 0-line .info and exit 0, which reads as a clean run.
"""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.restrict import main as restrict_main  # noqa: E402

# Aggregate covers foo (cpukit/x.c) and bar (cpukit/y.c). The target ELF only
# contains foo, so bar (and its file) must be dropped entirely.
AGGREGATE = """\
TN:agg
SF:cpukit/x.c
FN:10,foo
FNDA:5,foo
BRDA:10,0,0,5
BRDA:10,0,1,0
BRDA:12,0,0,-
BRDA:12,0,1,-
DA:10,5
DA:11,3
DA:12,0
end_of_record
TN:agg
SF:cpukit/y.c
FN:40,bar
FNDA:2,bar
BRDA:40,0,0,2
BRDA:40,0,1,0
DA:40,2
DA:41,0
end_of_record
"""

# Target coverable: only foo's lines in cpukit/x.c (note line 12 is NOT in the
# target -> must be dropped even though the aggregate listed it).
TARGET_COVERABLE = [
    {"file": "cpukit/x.c", "line": 10, "function": "foo"},
    {"file": "cpukit/x.c", "line": 11, "function": "foo"},
]

# The --elf path builds the same inventory through objdump + addr2line. Both
# are stubbed so no toolchain is needed; the ELF path is only ever handed to
# the stubs. Addresses 0x10/0x14 map to /src/x.c:10 and :11.
FAKE_OBJDUMP = (
    "#!/usr/bin/env python3\n"
    "print('a.elf:\\tfile format elf32-microblazeel\\n')\n"
    "print('00000010 <foo>:')\n"
    "print('      10:\\t20 00 00 00 \\taddik\\tr1, r0, 0')\n"
    "print('      14:\\t20 00 00 00 \\taddik\\tr1, r0, 0')\n"
)

FAKE_ADDR2LINE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "TABLE = {0x10: ('foo', '/src/x.c:10'), 0x14: ('foo', '/src/x.c:11')}\n"
    "for raw in sys.stdin:\n"
    "    raw = raw.strip()\n"
    "    if not raw:\n"
    "        continue\n"
    "    print(raw)\n"
    "    func, fileline = TABLE.get(int(raw, 16), ('??', '??:?'))\n"
    "    print(func)\n"
    "    print(fileline)\n"
)

# Same two lines as the stubbed ELF, under the absolute paths --all-paths keeps.
ABS_AGGREGATE = """\
TN:agg
SF:/src/x.c
FN:10,foo
FNDA:5,foo
BRDA:10,0,0,3
BRDA:10,0,1,0
DA:10,5
DA:11,0
DA:99,1
end_of_record
"""


def write_exe(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)


def parse_records(path):
    """Return {record type: [payloads]} plus a per-SF view of the .info."""
    by_sf = {}
    cur = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("SF:"):
                cur = line[3:]
                by_sf.setdefault(cur, [])
            elif line and cur is not None:
                by_sf[cur].append(line)
    return by_sf


class TestRestrict(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.agg = os.path.join(self.d, "agg.info")
        self.cab = os.path.join(self.d, "target.jsonl")
        self.out = os.path.join(self.d, "restricted.info")
        with open(self.agg, "w") as f:
            f.write(AGGREGATE)
        with open(self.cab, "w") as f:
            for r in TARGET_COVERABLE:
                f.write(json.dumps(r) + "\n")

    def _run(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = restrict_main(["--aggregate", self.agg, "--coverable",
                                self.cab, "--out", self.out] + list(extra))
        return rc, err.getvalue()

    def test_drops_non_target_symbols(self):
        rc, _ = self._run("--name", "qual")
        self.assertEqual(rc, 0)

        sf = None
        da = {}
        fns = []
        brda = []
        with open(self.out) as f:
            lines = f.read().splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("SF:"):
                sf = line[3:]
            elif line.startswith("DA:"):
                ln, _, hits = line[3:].partition(",")
                da[(sf, int(ln))] = int(hits)
            elif line.startswith("FN:"):
                fns.append(line[3:].partition(",")[2])
            elif line.startswith("BRDA:"):
                brda.append((sf, line[5:]))

        # bar / cpukit/y.c dropped; foo kept with its counts.
        self.assertEqual(fns, ["foo"])
        self.assertEqual(da, {("cpukit/x.c", 10): 5, ("cpukit/x.c", 11): 3})
        # line 12 (in aggregate but not in target) must be gone.
        self.assertNotIn(("cpukit/x.c", 12), da)
        # nothing from y.c survives.
        self.assertFalse(any(k[0] == "cpukit/y.c" for k in da))
        # Branch records follow the same filter: line 10 kept, line 12 (not in
        # the target) and all of y.c dropped.
        self.assertEqual(brda, [("cpukit/x.c", "10,0,0,5"),
                                ("cpukit/x.c", "10,0,1,0")])

    def test_per_file_branch_totals_match_the_kept_records(self):
        """BRF/BRH must count the FILTERED branches, not the aggregate's.

        The two dropped BRDA:12 outcomes would make BRF:4 -- a denominator for
        branches the target does not contain.
        """
        rc, _ = self._run()
        self.assertEqual(rc, 0)
        body = parse_records(self.out)["cpukit/x.c"]
        self.assertIn("BRF:2", body)
        self.assertIn("BRH:1", body)

    def test_summary_reports_branch_totals(self):
        """emit_branches' return value was discarded, so the summary line
        never mentioned branches even when the output carried BRDA records."""
        rc, err = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("1/2 branches", err)

    def test_empty_aggregate_is_an_error(self):
        """A .info with no DA records can only produce an empty report."""
        with open(self.agg, "w") as f:
            f.write("")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("aggregate is empty", err)
        self.assertFalse(os.path.exists(self.out))

    def test_no_overlap_refuses_to_write_an_empty_report(self):
        """The normalization-mismatch case: every line filtered out.

        This used to exit 0 after writing a 0-byte .info and printing
        "0 -> 0 coverable lines kept, 0 covered (0.0%)".
        """
        with open(self.cab, "w") as f:
            f.write(json.dumps({"file": "/elsewhere/z.c", "line": 1,
                                "function": "zap"}) + "\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("normalized differently", err)
        self.assertFalse(os.path.exists(self.out))

    def test_empty_target_inventory_is_an_error(self):
        with open(self.cab, "w") as f:
            f.write("")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("no source lines", err)
        self.assertFalse(os.path.exists(self.out))

    def test_malformed_coverable_record_names_the_file_and_line(self):
        """A foreign JSONL used to escape as a bare KeyError traceback."""
        with open(self.cab, "w") as f:
            f.write(json.dumps({"file": "cpukit/x.c", "line": 10}) + "\n")
            f.write(json.dumps({"lineno": 11}) + "\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("target.jsonl:2", err)

    def test_truncated_coverable_json_is_reported_not_traced(self):
        with open(self.cab, "w") as f:
            f.write('{"file": "cpukit/x.c", "line": 10}\n')
            f.write('{"file": "cpukit/x.c", "lin\n')
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("target.jsonl:2", err)


class TestRestrictFromElf(unittest.TestCase):
    """The --elf path: objdump + addr2line instead of a precomputed JSONL."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.objdump = os.path.join(self.d, "fake-objdump")
        self.a2l = os.path.join(self.d, "fake-addr2line")
        write_exe(self.objdump, FAKE_OBJDUMP)
        write_exe(self.a2l, FAKE_ADDR2LINE)
        self.agg = os.path.join(self.d, "agg.info")
        with open(self.agg, "w") as f:
            f.write(ABS_AGGREGATE)
        self.out = os.path.join(self.d, "restricted.info")

    def _run(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = restrict_main(["--aggregate", self.agg,
                                "--elf", os.path.join(self.d, "a.elf"),
                                "--objdump", self.objdump,
                                "--addr2line", self.a2l, "--all-paths",
                                "--out", self.out] + list(extra))
        return rc, err.getvalue()

    def test_elf_inventory_filters_the_aggregate(self):
        """--elf was completely broken: disassemble_addresses returns
        (addresses, text) and restrict passed the whole tuple to addr2line,
        dying with `TypeError: %x format: an integer is required, not list`
        on every single --elf invocation."""
        rc, err = self._run()
        self.assertEqual(rc, 0)
        body = parse_records(self.out)["/src/x.c"]
        # Lines 10 and 11 are in the ELF; line 99 is not.
        self.assertIn("DA:10,5", body)
        self.assertIn("DA:11,0", body)
        self.assertNotIn("DA:99,1", body)
        self.assertIn("LF:2", body)
        self.assertIn("LH:1", body)
        self.assertIn("50.0%", err)

    def test_objdump_producing_no_instructions_is_an_error(self):
        write_exe(self.objdump, "#!/usr/bin/env python3\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("no executable code", err)
        self.assertFalse(os.path.exists(self.out))

    def test_unparsable_disassembly_is_not_an_empty_inventory(self):
        write_exe(self.objdump,
                  "#!/usr/bin/env python3\n"
                  "print('some format we do not understand')\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("unrecognized disassembly layout", err)

    def test_objdump_failure_is_reported(self):
        write_exe(self.objdump,
                  "#!/usr/bin/env python3\n"
                  "import sys\n"
                  "sys.stderr.write('boom\\n')\n"
                  "sys.exit(3)\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("boom", err)


class TestRestrictHtml(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.agg = os.path.join(self.d, "agg.info")
        self.cab = os.path.join(self.d, "target.jsonl")
        self.out = os.path.join(self.d, "restricted.info")
        with open(self.agg, "w") as f:
            f.write(AGGREGATE)
        with open(self.cab, "w") as f:
            for r in TARGET_COVERABLE:
                f.write(json.dumps(r) + "\n")

    def test_missing_genhtml_warns_and_keeps_the_info(self):
        """genhtml is optional; a missing one raised FileNotFoundError AFTER
        the .info had been written, turning a good run into a traceback."""
        empty_bin = os.path.join(self.d, "nobin")
        os.mkdir(empty_bin)
        saved = os.environ.get("PATH")
        os.environ["PATH"] = empty_bin
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = restrict_main(["--aggregate", self.agg, "--coverable",
                                    self.cab, "--out", self.out,
                                    "--html", os.path.join(self.d, "html")])
        finally:
            if saved is None:
                del os.environ["PATH"]
            else:
                os.environ["PATH"] = saved
        self.assertEqual(rc, 0)
        self.assertIn("genhtml could not be run", err.getvalue())
        # The real output survived.
        with open(self.out) as f:
            self.assertIn("DA:10,5", f.read())


if __name__ == "__main__":
    unittest.main()
