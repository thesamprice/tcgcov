"""Tests for the covered/coverable join in tcgcov.lcov.

The percentage this module prints is the number a human reads and believes, so
the failure mode that matters is not a crash but a plausible wrong figure. The
denominator is:

    coverable = <lines from --coverable> | <lines covered>

The union is there so a hit is never lost, but it has no FLOOR: if the
coverable inventory is empty or was built for a different binary, the covered
lines become their own denominator and the report reads 100.0% at exit 0.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov.lcov import main as lcov_main  # noqa: E402


def write_jsonl(path, records):
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def covered_records(lines, sf="cpukit/x.c"):
    return [{"file": sf, "line": n, "function": "foo", "count": 1}
            for n in lines]


class TestCoverableDenominator(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.cov = os.path.join(self.d, "cov.jsonl")
        self.cab = os.path.join(self.d, "coverable.jsonl")
        self.out = os.path.join(self.d, "out.info")
        write_jsonl(self.cov, covered_records([10, 11]))

    def _run(self, *extra):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = lcov_main([self.cov, "--out", self.out] + list(extra))
        return rc, err.getvalue()

    def _totals(self):
        lf = lh = None
        with open(self.out) as f:
            for line in f:
                if line.startswith("LF:"):
                    lf = int(line[3:])
                elif line.startswith("LH:"):
                    lh = int(line[3:])
        return lh, lf

    def test_real_coverable_gives_a_real_percentage(self):
        write_jsonl(self.cab, covered_records([10, 11, 12, 13]))
        rc, err = self._run("--coverable", self.cab)
        self.assertEqual(rc, 0)
        self.assertEqual(self._totals(), (2, 4))       # 50%
        self.assertNotIn("warning", err)

    def test_empty_coverable_file_does_not_pass_as_100_percent(self):
        open(self.cab, "w").close()
        rc, err = self._run("--coverable", self.cab)
        # The union still reports 2/2 -- the number itself cannot be repaired
        # without inventing lines -- but it must not go out unannounced.
        self.assertEqual(self._totals(), (2, 2))
        self.assertIn("warning", err.lower())
        self.assertIn("denominator", err.lower())
        self.assertIn(self.cab, err)

    def test_coverable_from_the_wrong_binary_is_flagged(self):
        # Right shape, wrong file: nothing it lists survives the union, so the
        # denominator again collapses onto the covered set.
        write_jsonl(self.cab, covered_records([10, 11]))
        _rc, err = self._run("--coverable", self.cab)
        self.assertEqual(self._totals(), (2, 2))
        self.assertIn("warning", err.lower())

    def test_no_coverable_flag_is_not_warned_about(self):
        # Covered-only mode is a documented mode, not a broken denominator.
        rc, err = self._run()
        self.assertEqual(rc, 0)
        self.assertEqual(self._totals(), (2, 2))
        self.assertNotIn("warning", err.lower())

    def test_covered_line_missing_from_coverable_is_never_dropped(self):
        # The union's original purpose still holds: a hit outside the
        # inventory stays a hit.
        write_jsonl(self.cab, covered_records([12, 13]))
        rc, err = self._run("--coverable", self.cab)
        self.assertEqual(rc, 0)
        self.assertEqual(self._totals(), (2, 4))
        self.assertNotIn("warning", err.lower())


if __name__ == "__main__":
    unittest.main()
