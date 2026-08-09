"""Tests for the app-minus-baseline gap report (tcgcov.gap).

`gap` answers "what does the app run that the suite never tests", so the
dangerous failure is not a crash but a small, believable gap. Anything that
silently empties one side of the set difference -- an input parsed as the wrong
format, a baseline with no covered lines, two sides normalized differently, a
count of 0 dropping a line -- moves that number without moving the exit code.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.gap import main as gap_main  # noqa: E402

# App executes lines 10,11 (foo) and 20 (baz) in cpukit/x.c.
APP = [
    {"file": "cpukit/x.c", "line": 10, "function": "foo", "count": 4},
    {"file": "cpukit/x.c", "line": 11, "function": "foo", "count": 4},
    {"file": "cpukit/x.c", "line": 20, "function": "baz", "count": 9},
]

# The suite (baseline) covers line 10 but NOT 11 or 20 -> 11 and 20 are the gap.
BASELINE = """\
TN:suite
SF:cpukit/x.c
FN:10,foo
FNDA:1,foo
DA:10,1
DA:11,0
end_of_record
"""


def write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def read_info(path):
    """Return (list of record strings, {line: hits})."""
    body = []
    da = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            body.append(line)
            if line.startswith("DA:"):
                ln, _, hits = line[3:].partition(",")
                da[int(ln)] = int(hits)
    return body, da


class TestGap(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.app = os.path.join(self.d, "app.jsonl")
        self.base = os.path.join(self.d, "suite.info")
        self.out = os.path.join(self.d, "gap.info")
        write_jsonl(self.app, APP)
        with open(self.base, "w") as f:
            f.write(BASELINE)

    def _run(self, *extra, app=None):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = gap_main(["--app", app or self.app, "--baseline", self.base,
                           "--out", self.out] + list(extra))
        return rc, err.getvalue()

    def test_app_minus_baseline(self):
        rc, _ = self._run()
        self.assertEqual(rc, 0)
        _, da = read_info(self.out)

        # Universe = app-executed lines {10,11,20}.
        self.assertEqual(set(da), {10, 11, 20})
        # Line 10 covered by baseline -> hit (app count 4). 11 and 20 are the
        # gap -> 0 (red).
        self.assertEqual(da[10], 4)
        self.assertEqual(da[11], 0)
        self.assertEqual(da[20], 0)

    def test_format_comes_from_the_content_not_the_extension(self):
        """`--app app.json` (or app.JSONL, or app.cov) used to be parsed as
        LCOV because the dispatch was `path.endswith('.jsonl')`. It then found
        no SF: record, reported "app executes 0 lines ... 0 GAP lines" and
        exited 0 -- a clean bill of health for an unread file."""
        for name in ("app.json", "app.JSONL", "app.coverage"):
            path = os.path.join(self.d, name)
            write_jsonl(path, APP)
            rc, err = self._run(app=path)
            self.assertEqual(rc, 0, name)
            _, da = read_info(self.out)
            self.assertEqual(set(da), {10, 11, 20}, name)
            self.assertIn("2 GAP lines", err)

    def test_lcov_content_under_a_jsonl_name_is_still_lcov(self):
        """The mirror image: an .info that happens to be called .jsonl."""
        path = os.path.join(self.d, "app.jsonl")
        with open(path, "w") as f:
            f.write("TN:app\nSF:cpukit/x.c\nDA:10,4\nDA:11,4\n"
                    "end_of_record\n")
        rc, _ = self._run(app=path)
        self.assertEqual(rc, 0)
        _, da = read_info(self.out)
        self.assertEqual(set(da), {10, 11})

    def test_unrecognizable_app_file_is_an_error(self):
        path = os.path.join(self.d, "app.txt")
        with open(path, "w") as f:
            f.write("this is not coverage data\n")
        rc, err = self._run(app=path)
        self.assertEqual(rc, 1)
        self.assertIn("not recognizable", err)
        self.assertFalse(os.path.exists(self.out))

    def test_zero_count_record_stays_in_the_app_universe(self):
        """A symbolized record exists because the line RAN; a count of 0 lost
        the `cnt > app_count.get(k, 0)` comparison and the line vanished from
        the denominator, shrinking the reported gap."""
        recs = list(APP) + [{"file": "cpukit/x.c", "line": 30,
                             "function": "qux", "count": 0}]
        write_jsonl(self.app, recs)
        rc, err = self._run()
        self.assertEqual(rc, 0)
        body, da = read_info(self.out)
        self.assertIn(30, da)
        self.assertIn("LF:4", body)
        self.assertIn("3 GAP lines", err)

    def test_baseline_covered_line_is_never_written_as_a_gap(self):
        """DA:<line>,0 renders red (a gap) while LH counts it as covered: the
        header and the body would disagree for a zero-count app line."""
        write_jsonl(self.app, [{"file": "cpukit/x.c", "line": 10,
                                "function": "foo", "count": 0}])
        rc, _ = self._run()
        self.assertEqual(rc, 0)
        body, da = read_info(self.out)
        self.assertEqual(da[10], 1)
        self.assertIn("LH:1", body)

    def test_empty_baseline_is_an_error(self):
        """No covered lines in the baseline makes every app line a gap -- a
        100%-gap report that used to exit 0."""
        with open(self.base, "w") as f:
            f.write("")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("no covered lines", err)
        self.assertFalse(os.path.exists(self.out))

    def test_baseline_with_only_uncovered_lines_is_an_error(self):
        with open(self.base, "w") as f:
            f.write("TN:suite\nSF:cpukit/x.c\nDA:10,0\nDA:11,0\n"
                    "end_of_record\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("no covered lines", err)

    def test_empty_app_is_an_error(self):
        """"0 GAP lines" from an empty app file reads as "nothing untested"."""
        with open(self.app, "w") as f:
            f.write("")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("no executed lines", err)
        self.assertFalse(os.path.exists(self.out))

    def test_disjoint_source_paths_are_called_out(self):
        """Absolute-vs-relative paths make the whole app look untested."""
        write_jsonl(self.app, [{"file": "/abs/cpukit/x.c", "line": 10,
                                "function": "foo", "count": 1}])
        rc, err = self._run()
        self.assertEqual(rc, 0)
        self.assertIn("no source file in common", err)
        self.assertIn("/abs/cpukit/x.c", err)
        self.assertIn("cpukit/x.c", err)

    def test_overlapping_paths_do_not_warn(self):
        rc, err = self._run()
        self.assertEqual(rc, 0)
        self.assertNotIn("no source file in common", err)

    def test_malformed_app_record_names_the_file_and_line(self):
        with open(self.app, "w") as f:
            f.write(json.dumps({"file": "cpukit/x.c", "line": 10}) + "\n")
            f.write(json.dumps({"file": "cpukit/x.c"}) + "\n")
        rc, err = self._run()
        self.assertEqual(rc, 1)
        self.assertIn("app.jsonl:2", err)

    def test_cov_and_app_together_is_refused(self):
        """Ignoring one of them silently reports on a different app."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = gap_main(["--app", self.app, "--cov",
                           os.path.join(self.d, "x.cov"),
                           "--elf", os.path.join(self.d, "x.elf"),
                           "--baseline", self.base, "--out", self.out])
        self.assertEqual(rc, 2)
        self.assertIn("only one", err.getvalue())

    def test_missing_genhtml_warns_and_keeps_the_info(self):
        empty_bin = os.path.join(self.d, "nobin")
        os.mkdir(empty_bin)
        saved = os.environ.get("PATH")
        os.environ["PATH"] = empty_bin
        try:
            rc, err = self._run("--html", os.path.join(self.d, "html"))
        finally:
            if saved is None:
                del os.environ["PATH"]
            else:
                os.environ["PATH"] = saved
        self.assertEqual(rc, 0)
        self.assertIn("genhtml could not be run", err)
        with open(self.out) as f:
            self.assertIn("DA:10,4", f.read())


# App .info: foo ran (lines 10,11 and both outcomes of the branch at line 10);
# `never` is declared but never executed (FNDA:0, its line uncovered).
APP_INFO = """\
TN:app
SF:cpukit/x.c
FN:10,foo
FN:50,never
FNDA:3,foo
FNDA:0,never
BRDA:10,0,0,5
BRDA:10,0,1,2
BRDA:30,0,0,-
BRDA:30,0,1,-
DA:10,5
DA:11,2
DA:50,0
end_of_record
"""

# Baseline: covers line 10 and the TAKEN outcome of the branch at line 10, but
# not the fall-through. It also covers line 50 -- which the app never runs.
BASELINE_INFO = """\
TN:suite
SF:cpukit/x.c
FN:10,foo
FN:50,never
FNDA:1,foo
FNDA:1,never
BRDA:10,0,0,7
BRDA:10,0,1,0
DA:10,1
DA:11,0
DA:50,4
end_of_record
"""


class TestGapFromInfo(unittest.TestCase):
    """The --app <LCOV .info> input: branch records and function accounting."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.app = os.path.join(self.d, "app.info")
        self.base = os.path.join(self.d, "suite.info")
        self.out = os.path.join(self.d, "gap.info")
        with open(self.app, "w") as f:
            f.write(APP_INFO)
        with open(self.base, "w") as f:
            f.write(BASELINE_INFO)

    def _run(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = gap_main(["--app", self.app, "--baseline", self.base,
                           "--out", self.out] + list(extra))
        return rc, err.getvalue()

    def test_branch_outcomes_the_app_took_become_the_branch_universe(self):
        """BRDA records were parsed by merge.parse_info and then dropped on
        the floor: the gap report carried no branch information at all."""
        rc, err = self._run()
        self.assertEqual(rc, 0)
        body, _ = read_info(self.out)
        # The app took both outcomes at line 10; the baseline took only the
        # first, so the fall-through is a GAP outcome (0 = red).
        self.assertIn("BRDA:10,0,0,5", body)
        self.assertIn("BRDA:10,0,1,0", body)
        self.assertIn("BRF:2", body)
        self.assertIn("BRH:1", body)
        # The app never evaluated the branch at line 30, so it is not part of
        # "what the app runs" and must not enter the denominator.
        self.assertFalse(any(r.startswith("BRDA:30") for r in body))
        self.assertIn("1/2 branch outcomes", err)

    def test_functions_the_app_never_ran_are_not_counted(self):
        """FNF/FNH came from every FN record in the app .info, so a function
        the app never enters inflated the denominator -- and, when the
        baseline covered it, the numerator too: FNF:2/FNH:2 for one function
        that ran, i.e. a confident 100% of the app's functions."""
        rc, _ = self._run()
        self.assertEqual(rc, 0)
        body, _ = read_info(self.out)
        self.assertIn("FN:10,foo", body)
        self.assertNotIn("FN:50,never", body)
        self.assertIn("FNF:1", body)
        self.assertIn("FNH:1", body)

    def test_line_universe_is_the_app_covered_lines(self):
        rc, _ = self._run()
        self.assertEqual(rc, 0)
        body, da = read_info(self.out)
        self.assertEqual(set(da), {10, 11})   # DA:50,0 is not app-executed
        self.assertEqual(da[10], 5)
        self.assertEqual(da[11], 0)
        self.assertIn("LF:2", body)
        self.assertIn("LH:1", body)


if __name__ == "__main__":
    unittest.main()
