"""tcgcov.genhtml: the genhtml command line, and lcov 2's consistency check.

lcov 2 rejects "line is hit but no branches on line have been evaluated",
which tcgcov reports faithfully when the optimizer duplicates a line and the
copy that ran holds no branch.  Seen on newlib's vfprintf.c:1428 for
riscv32 (microblaze-v-testsuite), where genhtml refused the whole report.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tcgcov import genhtml                                    # noqa: E402


class TestCommand(unittest.TestCase):
    def setUp(self):
        genhtml._MAJOR.clear()

    def _cmd(self, major, **kw):
        with mock.patch.object(genhtml, "lcov_major", return_value=major):
            return genhtml.command("/a.info", "/html", **kw)

    def _ignored(self, cmd):
        return cmd[cmd.index("--ignore-errors") + 1].split(",")

    def test_lcov2_ignores_inconsistent(self):
        self.assertEqual(self._ignored(self._cmd(2)),
                         ["source", "inconsistent"])

    def test_lcov1_does_not_know_inconsistent(self):
        self.assertEqual(self._ignored(self._cmd(1)), ["source"])

    def test_unknown_version_is_treated_as_lcov1(self):
        self.assertEqual(self._ignored(self._cmd(None)), ["source"])

    def test_branch_flag_and_extra_args_come_last(self):
        cmd = self._cmd(2, branch_coverage=True, extra=["--title", "x"])
        self.assertEqual(cmd[:4], ["genhtml", "/a.info",
                                   "--output-directory", "/html"])
        self.assertEqual(cmd[-3:], ["--branch-coverage", "--title", "x"])


class TestVersionProbe(unittest.TestCase):
    def setUp(self):
        genhtml._MAJOR.clear()
        self.d = tempfile.mkdtemp()

    def _fake(self, text):
        path = os.path.join(self.d, "genhtml")
        with open(path, "w") as f:
            f.write("#!/bin/sh\necho '%s'\n" % text)
        os.chmod(path, 0o755)
        return path

    def test_reads_lcov2(self):
        self.assertEqual(genhtml.lcov_major(
            self._fake("genhtml: LCOV version 2.5-0")), 2)

    def test_reads_lcov1(self):
        self.assertEqual(genhtml.lcov_major(
            self._fake("genhtml: LCOV version 1.16")), 1)

    def test_missing_genhtml_is_none(self):
        self.assertIsNone(genhtml.lcov_major(
            os.path.join(self.d, "no-such-genhtml")))

    def test_unrecognised_output_is_none(self):
        self.assertIsNone(genhtml.lcov_major(self._fake("hello")))

    def test_not_fooled_by_a_mocked_subprocess_run(self):
        with mock.patch.object(subprocess, "run",
                               side_effect=AssertionError("run called")):
            self.assertEqual(genhtml.lcov_major(
                self._fake("genhtml: LCOV version 2.0-1")), 2)


if __name__ == "__main__":
    unittest.main()
