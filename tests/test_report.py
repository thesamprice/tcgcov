"""tcgcov report: the one-command driver's orchestration.

Every step this command runs has its own tests; what is untested until here is
the wiring between them, and the wiring is where a silently wrong percentage
comes from:

  * the covered and the coverable side must receive the SAME path options, or
    `lcov` joins two different key spaces and reports a number belonging to
    neither;
  * the coverable inventory is cached per ELF, so the cache key must include
    those options -- reusing an inventory built under a different
    --source-root is exactly that same wrong join, one run later;
  * an artifact whose ELF is missing is skipped, and a run in which EVERY
    artifact was skipped must be an error rather than an empty aggregate that
    reads as "this campaign covered nothing".

The subcommands are stubbed here: this is about which arguments reach them,
not about what they compute. ci/integration.sh runs the same command against a
real toolchain and asserts the number.
"""

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import report                                     # noqa: E402
from tcgcov.format import write_cov                           # noqa: E402


class StepStub:
    """Stands in for a subcommand's main(): records argv, writes its --out.

    Before recording, the argv is parsed by the REAL subcommand's parser. A
    stub that accepts anything would let a misspelled or removed option --
    `--denominator` renamed, say -- pass every test here and fail the first
    time a user runs the command, which is the one failure mode a stubbed
    driver test is otherwise blind to.
    """

    def __init__(self, module, rc=0, payload="{}\n"):
        self.calls = []
        self.rc = rc
        self.payload = payload
        self.parser = argparse.ArgumentParser(prog=module.__name__)
        module.add_arguments(self.parser)

    def __call__(self, argv):
        try:
            self.parser.parse_args(argv)
        except SystemExit:
            raise AssertionError(
                "%s rejects the argv the driver built: %s"
                % (self.parser.prog, " ".join(argv)))
        self.calls.append(list(argv))
        if self.rc == 0 and "--out" in argv:
            out = argv[argv.index("--out") + 1]
            with open(out, "w") as f:
                f.write(self.payload)
        return self.rc() if callable(self.rc) else self.rc

    @property
    def argv(self):
        """The single call's argv (fails loudly if it ran more than once)."""
        assert len(self.calls) == 1, "%d calls, expected 1" % len(self.calls)
        return self.calls[0]

    def opt(self, argv, name):
        return argv[argv.index(name) + 1]

    def positionals(self, argv, suffix):
        """The bare file arguments, i.e. not the value of some --option."""
        out, skip = [], False
        for i, a in enumerate(argv):
            if skip:
                skip = False
                continue
            if a.startswith("--"):
                skip = i + 1 < len(argv) and not argv[i + 1].startswith("--")
                continue
            if a.endswith(suffix):
                out.append(a)
        return out


class ReportTestCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.raw = os.path.join(self.d, "raw")
        self.out = os.path.join(self.d, "out")
        os.makedirs(self.raw)
        self.elf = os.path.join(self.d, "prog.elf")
        with open(self.elf, "w") as f:
            f.write("not really an ELF; the steps are stubbed\n")

        self.symbolize = StepStub(report.symbolize_mod)
        self.coverable = StepStub(report.coverable_mod)
        self.branches = StepStub(report.branches_mod)
        self.lcov = StepStub(report.lcov_mod, payload="TN:x\nend_of_record\n")
        self.merge = StepStub(report.merge_mod,
                              payload="TN:agg\nend_of_record\n")
        self.disassemble = mock.Mock(return_value="disassembly\n")

    def make_cov(self, name, elf=None, target="riscv64", dirname=None,
                 **extra_meta):
        path = os.path.join(dirname or self.raw, name + ".cov")
        meta = {"format": "tcgcov", "version": 1, "target_name": target,
                "test_id": name, "bsp": "", "elf": self.elf if elf is None
                else elf}
        meta.update(extra_meta)
        write_cov(path, meta, [(0x1000, 1), (0x1004, 1)])
        return path

    def run_report(self, *extra):
        """Run the driver with every step stubbed; return (rc, stderr)."""
        argv = ["--out-dir", self.out] + list(extra)
        err = io.StringIO()
        with mock.patch.object(report.symbolize_mod, "main", self.symbolize), \
                mock.patch.object(report.coverable_mod, "main", self.coverable), \
                mock.patch.object(report.branches_mod, "main", self.branches), \
                mock.patch.object(report.lcov_mod, "main", self.lcov), \
                mock.patch.object(report.merge_mod, "main", self.merge), \
                mock.patch.object(report.cfg, "disassemble", self.disassemble), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            rc = report.main(argv)
        return rc, err.getvalue()


class TestWiring(ReportTestCase):
    def test_end_to_end_stubbed(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        agg = os.path.join(self.out, "lcov", "aggregate-riscv64.info")
        self.assertTrue(os.path.exists(agg), "aggregate not written")
        # The per-test .info the lcov step wrote is what merge was handed.
        self.assertIn(os.path.join(self.out, "lcov", "per-test", "t1.info"),
                      self.merge.argv)

    def test_arch_defaults_to_the_recorded_target(self):
        self.make_cov("t1", target="microblaze")
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertIn("microblaze", err)
        self.assertEqual(self.symbolize.opt(self.symbolize.argv, "--arch"),
                         "microblaze")
        self.assertEqual(self.coverable.opt(self.coverable.argv, "--arch"),
                         "microblaze")
        self.assertTrue(os.path.exists(
            os.path.join(self.out, "lcov", "aggregate-microblaze.info")))

    def test_explicit_arch_wins(self):
        self.make_cov("t1", target="riscv64")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--arch", "rv32")
        self.assertEqual(rc, 0)
        self.assertEqual(self.symbolize.opt(self.symbolize.argv, "--arch"),
                         "rv32")

    def test_elf_override_replaces_the_recorded_path(self):
        # A scrubbed artifact records no usable ELF path at all.
        self.make_cov("t1", elf="/gone/prog.elf")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--elf", self.elf)
        self.assertEqual(rc, 0)
        self.assertEqual(self.symbolize.opt(self.symbolize.argv, "--elf"),
                         self.elf)

    def test_positional_artifacts_and_raw_dir_combine_and_dedupe(self):
        a = self.make_cov("t1")
        other = os.path.join(self.d, "more")
        os.makedirs(other)
        b = self.make_cov("t2", dirname=other)
        rc, _ = self.run_report("--raw-dir", self.raw, a, b, "--all-paths")
        self.assertEqual(rc, 0)
        # 'a' appears twice on the command line; it must be processed once.
        self.assertEqual(len(self.symbolize.calls), 2)

    def test_duplicate_basenames_do_not_overwrite_each_other(self):
        other = os.path.join(self.d, "more")
        os.makedirs(other)
        self.make_cov("t1")
        self.make_cov("t1", dirname=other)
        rc, _ = self.run_report("--raw-dir", self.raw, "--raw-dir", other,
                                "--all-paths")
        self.assertEqual(rc, 0)
        infos = self.merge.positionals(self.merge.argv, ".info")
        self.assertEqual(len(set(infos)), 2, "per-test .info files collided")


class TestModmapSlices(ReportTestCase):
    """A slice cut by `tcgcov modmap` names its own object and section.

    The slice inherits `elf` from the artifact it was cut out of -- the BASE
    IMAGE -- so an ELF read straight from that key symbolizes a dynamically
    loaded object against the wrong binary. `module_file`/`module_section`
    are what modmap stamps for exactly this, and preferring them is what lets
    a directory of slices be reported with no per-object flags.
    """

    def setUp(self):
        super().setUp()
        self.dso = os.path.join(self.d, "dl-o1.o")
        with open(self.dso, "w") as f:
            f.write("the loaded object, stubbed\n")

    def test_module_file_and_section_win_over_the_inherited_elf(self):
        self.make_cov("dl-o1__text", module_file=self.dso,
                      module_section=".text")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        argv = self.symbolize.argv
        self.assertEqual(self.symbolize.opt(argv, "--elf"), self.dso)
        self.assertEqual(self.symbolize.opt(argv, "--section"), ".text")
        # The base image must not be what anything was analysed against.
        self.assertNotIn(self.elf, argv)

    def test_the_section_reaches_the_denominator_too(self):
        self.make_cov("dl-o1__text", module_file=self.dso,
                      module_section=".text")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertEqual(self.coverable.opt(self.coverable.argv, "--section"),
                         ".text")
        self.assertEqual(self.branches.opt(self.branches.argv, "--section"),
                         ".text")

    def test_two_sections_of_one_object_get_their_own_inventory(self):
        self.make_cov("dl-o1__text", module_file=self.dso,
                      module_section=".text")
        self.make_cov("dl-o1__rodata", module_file=self.dso,
                      module_section=".rodata")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        outs = {self.coverable.opt(c, "--out") for c in self.coverable.calls}
        self.assertEqual(len(outs), 2,
                         "the section is part of what a denominator describes")
        self.assertEqual(self.disassemble.call_count, 1,
                         "one objdump per ELF: it dumps every section at once")

    def test_explicit_flags_still_win(self):
        self.make_cov("dl-o1__text", module_file=self.dso,
                      module_section=".text")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--elf", self.elf, "--section", ".init")
        self.assertEqual(rc, 0)
        argv = self.symbolize.argv
        self.assertEqual(self.symbolize.opt(argv, "--elf"), self.elf)
        self.assertEqual(self.symbolize.opt(argv, "--section"), ".init")

    def test_plain_artifacts_pass_no_section(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertNotIn("--section", self.symbolize.argv)
        self.assertNotIn("--section", self.coverable.argv)

    def test_slices_and_plain_artifacts_mix_in_one_run(self):
        self.make_cov("base")
        self.make_cov("dl-o1__text", module_file=self.dso,
                      module_section=".text")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        by_elf = {self.symbolize.opt(c, "--elf"): c
                  for c in self.symbolize.calls}
        self.assertEqual(set(by_elf), {self.elf, self.dso})
        self.assertNotIn("--section", by_elf[self.elf])
        self.assertIn("--section", by_elf[self.dso])


class TestPathOptionAgreement(ReportTestCase):
    """The covered and coverable sides must be normalized identically."""

    OPTS = ["--source-root", "/src", "--exclude", "tests/**",
            "--keep", "/vendor/", "--preset", "rtems"]

    def _path_opts(self, argv):
        keep = ("--source-root", "--exclude", "--keep", "--preset",
                "--all-paths", "--include-testsuites", "--section")
        out, i = [], 0
        while i < len(argv):
            if argv[i] in keep:
                out.append(argv[i])
                if argv[i] not in ("--all-paths", "--include-testsuites"):
                    out.append(argv[i + 1])
                    i += 1
            i += 1
        return out

    def test_every_producer_gets_the_same_options(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, *self.OPTS)
        self.assertEqual(rc, 0)
        expected = self._path_opts(self.symbolize.argv)
        self.assertEqual(sorted(expected), sorted(self.OPTS))
        self.assertEqual(self._path_opts(self.coverable.argv), expected)
        self.assertEqual(self._path_opts(self.branches.argv), expected)


class TestCoverableCache(ReportTestCase):
    def test_shared_elf_is_inventoried_once(self):
        self.make_cov("t1")
        self.make_cov("t2")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.symbolize.calls), 2)
        self.assertEqual(len(self.coverable.calls), 1,
                         "the denominator is test-agnostic; compute it once")
        self.assertEqual(self.disassemble.call_count, 1,
                         "one objdump per ELF, not per artifact")

    def test_changing_path_options_invalidates_the_cache(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--source-root", "/a")
        self.assertEqual(rc, 0)
        first = self.coverable.opt(self.coverable.calls[0], "--out")
        rc, _ = self.run_report("--raw-dir", self.raw, "--source-root", "/b")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.coverable.calls), 2,
                         "a different --source-root needs a new denominator")
        second = self.coverable.opt(self.coverable.calls[1], "--out")
        self.assertNotEqual(os.path.basename(first).replace(".tmp", ""),
                            os.path.basename(second).replace(".tmp", ""))

    def test_unchanged_options_reuse_the_cache(self):
        self.make_cov("t1")
        self.run_report("--raw-dir", self.raw, "--source-root", "/a")
        self.run_report("--raw-dir", self.raw, "--source-root", "/a")
        self.assertEqual(len(self.coverable.calls), 1)


class TestDegradedInputs(ReportTestCase):
    def test_missing_elf_is_skipped_not_fatal(self):
        self.make_cov("good")
        self.make_cov("bad", elf=os.path.join(self.d, "absent.elf"))
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertIn("skipping", err)
        self.assertEqual(len(self.symbolize.calls), 1)
        infos = self.merge.positionals(self.merge.argv, ".info")
        self.assertEqual(len(infos), 1)

    def test_every_elf_missing_is_an_error(self):
        self.make_cov("bad", elf=os.path.join(self.d, "absent.elf"))
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 1)
        self.assertIn("no artifact could be processed", err)
        self.assertEqual(self.merge.calls, [],
                         "an empty aggregate would read as 0% coverage")

    def test_no_artifacts_is_an_error(self):
        rc, err = self.run_report("--raw-dir", self.raw)
        self.assertEqual(rc, 1)
        self.assertIn("no .cov artifacts", err)

    def test_raw_dir_must_exist(self):
        rc, err = self.run_report("--raw-dir", os.path.join(self.d, "nope"))
        self.assertEqual(rc, 1)
        self.assertIn("not a directory", err)

    def test_a_failing_step_fails_the_run(self):
        self.make_cov("t1")
        self.symbolize.rc = 1
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 1)
        self.assertIn("1 of 1 artifacts failed", err)
        self.assertEqual(self.merge.calls, [])


class TestBranches(ReportTestCase):
    def test_unsupported_arch_degrades_to_line_coverage(self):
        # Exit 2 from `branches` means "no profile for this ISA" -- expected.
        self.make_cov("t1")
        self.branches.rc = 2
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertIn("no branch profile", err)
        self.assertNotIn("--branches", self.lcov.argv)

    def test_branch_failure_is_not_downgraded_to_a_note(self):
        # Anything else is a real failure; dropping branch data silently looks
        # exactly like a coverage regression.
        self.make_cov("t1")
        self.branches.rc = 1
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 1)
        self.assertIn("branch analysis failed", err)

    def test_branch_records_reach_lcov(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        self.assertEqual(self.lcov.opt(self.lcov.argv, "--branches"),
                         os.path.join(self.out, "branches", "t1.jsonl"))

    def test_no_branches_skips_the_step(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--no-branches")
        self.assertEqual(rc, 0)
        self.assertEqual(self.branches.calls, [])
        self.assertNotIn("--branches", self.lcov.argv)

    def test_arch_profiles_are_forwarded(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--arch-profile", "/p/mine.json")
        self.assertEqual(rc, 0)
        self.assertEqual(self.branches.opt(self.branches.argv,
                                           "--arch-profile"), "/p/mine.json")


class TestNoToolchain(ReportTestCase):
    def test_dwarf_denominator_without_branches_never_disassembles(self):
        # The point of the DWARF denominator is a report on a machine with no
        # target binutils installed; running objdump anyway would defeat it.
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--denominator", "dwarf", "--no-branches")
        self.assertEqual(rc, 0)
        self.disassemble.assert_not_called()
        self.assertNotIn("--disasm", self.coverable.argv)
        self.assertFalse(os.path.exists(os.path.join(self.out, "disasm")))

    def test_disassembly_is_shared_when_branches_are_on(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--denominator", "dwarf")
        self.assertEqual(rc, 0)
        self.assertEqual(self.disassemble.call_count, 1)
        self.assertIn("--disasm", self.branches.argv)


class TestParallel(ReportTestCase):
    def test_jobs_produce_the_same_result_and_readable_output(self):
        for i in range(6):
            self.make_cov("t%d" % i)
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths",
                                  "--jobs", "4")
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.symbolize.calls), 6)
        infos = self.merge.positionals(self.merge.argv, ".info")
        self.assertEqual(len(infos), 6)
        # Per-artifact stderr is flushed in one piece, not interleaved.
        self.assertIn("4 parallel jobs", err)

    def test_jobs_are_capped_at_the_artifact_count(self):
        self.make_cov("t1")
        rc, err = self.run_report("--raw-dir", self.raw, "--all-paths",
                                  "--jobs", "16")
        self.assertEqual(rc, 0)
        self.assertNotIn("parallel jobs", err)


class TestHtml(ReportTestCase):
    def _run_with_genhtml(self, proc_rc, *extra):
        self.make_cov("t1")
        seen = {}

        def fake_run(cmd, cwd=None):
            seen["cmd"] = cmd
            seen["cwd"] = cwd
            os.makedirs(cmd[cmd.index("--output-directory") + 1],
                        exist_ok=True)
            return mock.Mock(returncode=proc_rc)

        with mock.patch.object(report.subprocess, "run", fake_run):
            rc, err = self.run_report("--raw-dir", self.raw, "--all-paths",
                                      *extra)
        return rc, err, seen

    def test_html_is_opt_in(self):
        self.make_cov("t1")
        with mock.patch.object(report.subprocess, "run") as sub:
            rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths")
        self.assertEqual(rc, 0)
        sub.assert_not_called()

    def test_html_default_directory_and_branch_flag(self):
        rc, _, seen = self._run_with_genhtml(0, "--html")
        self.assertEqual(rc, 0)
        self.assertEqual(seen["cmd"][seen["cmd"].index("--output-directory")
                                     + 1],
                         os.path.abspath(os.path.join(self.out, "html")))
        self.assertIn("--branch-coverage", seen["cmd"])

    def test_html_directory_override_and_source_root_cwd(self):
        dest = os.path.join(self.d, "site")
        rc, _, seen = self._run_with_genhtml(0, "--html", dest,
                                             "--source-root", self.d)
        self.assertEqual(rc, 0)
        self.assertEqual(seen["cwd"], self.d)
        self.assertEqual(seen["cmd"][seen["cmd"].index("--output-directory")
                                     + 1], os.path.abspath(dest))

    def test_genhtml_failure_fails_the_run(self):
        rc, err, _ = self._run_with_genhtml(1, "--html")
        self.assertEqual(rc, 1)
        self.assertIn("genhtml failed", err)

    def test_branch_flag_omitted_without_branch_data(self):
        self.branches.rc = 2
        rc, _, seen = self._run_with_genhtml(0, "--html")
        self.assertEqual(rc, 0)
        self.assertNotIn("--branch-coverage", seen["cmd"])


class TestOutputNaming(ReportTestCase):
    def test_out_overrides_the_aggregate_path(self):
        self.make_cov("t1")
        dest = os.path.join(self.d, "deep", "custom.info")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--out", dest)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(dest))

    def test_name_overrides_the_aggregate_test_name(self):
        self.make_cov("t1")
        rc, _ = self.run_report("--raw-dir", self.raw, "--all-paths",
                                "--name", "nightly")
        self.assertEqual(rc, 0)
        self.assertEqual(self.merge.opt(self.merge.argv, "--name"), "nightly")


class TestMetadataReader(unittest.TestCase):
    """format.read_metadata: the driver's only read of a whole artifact."""

    def test_reads_metadata_without_the_records(self):
        from tcgcov.format import read_metadata
        d = tempfile.mkdtemp()
        path = os.path.join(d, "big.cov")
        meta = {"format": "tcgcov", "version": 1, "elf": "/x/prog.elf",
                "target_name": "riscv64"}
        write_cov(path, meta, [(a, 1) for a in range(0x1000, 0x3000, 4)])
        self.assertEqual(read_metadata(path)["elf"], "/x/prog.elf")
        self.assertEqual(read_metadata(path)["target_name"], "riscv64")

    def test_rejects_a_non_artifact(self):
        from tcgcov.format import read_metadata
        d = tempfile.mkdtemp()
        path = os.path.join(d, "not.cov")
        with open(path, "w") as f:
            f.write("nope")
        with self.assertRaises(ValueError):
            read_metadata(path)

    def test_matches_the_full_reader(self):
        from tcgcov.format import read_metadata, read_cov
        d = tempfile.mkdtemp()
        path = os.path.join(d, "a.cov")
        meta = {"format": "tcgcov", "version": 1, "elf": "/x/p.elf",
                "test_id": "t", "filters": ["a", "b"]}
        write_cov(path, meta, [(0x10, 2)])
        self.assertEqual(json.dumps(read_metadata(path), sort_keys=True),
                         json.dumps(read_cov(path)[0], sort_keys=True))


if __name__ == "__main__":
    unittest.main()
