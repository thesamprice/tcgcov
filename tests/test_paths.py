"""Tests for source-path normalization (tcgcov.paths).

Two behaviours are covered: the project-agnostic default (source-root-relative,
nothing project-specific hardcoded) and the `rtems` preset, which reproduces
the original RTEMS-only behaviour through plain markers/roots/excludes.
"""

import argparse
import contextlib
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import paths  # noqa: E402
from tcgcov.paths import normalize_path, path_options  # noqa: E402

SRC = "/src/rtems"
PROJ = "/work/proj"


def opts(**kw):
    """Build a PathOptions the way the CLI does, from parsed-args defaults."""
    ns = argparse.Namespace(source_root=None, preset=None, keep=[], exclude=[],
                            include_testsuites=False, all_paths=False)
    for k, v in kw.items():
        setattr(ns, k, v)
    return path_options(ns)


def norm(raw, o):
    """normalize_path() driven by a PathOptions bundle, as the producers do."""
    return normalize_path(raw, o.source_root, o.markers, o.roots, o.excludes,
                          o.all_paths)


class TestGeneralDefault(unittest.TestCase):
    """No preset: everything under --source-root is kept, verbatim trees."""

    def test_source_root_relative(self):
        o = opts(source_root=PROJ)
        self.assertEqual(norm("/work/proj/src/main.c", o), "src/main.c")
        self.assertEqual(norm("/work/proj/lib/vendor/util.c", o),
                         "lib/vendor/util.c")

    def test_source_root_resolves_dotdot(self):
        # Build paths routinely contain '..'; realpath collapses them before
        # the root comparison.
        o = opts(source_root=PROJ)
        self.assertEqual(
            norm("/work/proj/build/a/b/../../../src/main.c", o), "src/main.c")

    def test_no_tree_is_privileged(self):
        # 'testsuites' is an RTEMS convention, not a general one: with no
        # preset it is ordinary source under the root.
        o = opts(source_root=PROJ)
        self.assertEqual(norm("/work/proj/testsuites/t1/init.c", o),
                         "testsuites/t1/init.c")

    def test_outside_source_root_dropped(self):
        o = opts(source_root=PROJ)
        self.assertIsNone(norm("/opt/toolchain/newlib/libc/foo.c", o))
        self.assertIsNone(norm("/usr/include/stdio.h", o))
        self.assertIsNone(norm("/other/tree/generated.c", o))

    def test_marker_keeps_code_outside_source_root(self):
        o = opts(source_root=PROJ, keep=["/thirdparty/"])
        self.assertEqual(norm("/elsewhere/thirdparty/zlib/inflate.c", o),
                         "thirdparty/zlib/inflate.c")
        self.assertIsNone(norm("/elsewhere/other/x.c", o))

    def test_source_root_prefix_is_component_wise(self):
        # /work/proj-old must not be treated as living under /work/proj.
        o = opts(source_root=PROJ)
        self.assertIsNone(norm("/work/proj-old/src/main.c", o))


class TestNoOptionsFallback(unittest.TestCase):
    """Nothing given: keep absolute paths and say so, never drop everything."""

    def setUp(self):
        paths._warned_no_root = False

    def test_keeps_absolute_and_warns(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            out = norm("/anywhere/at/all/main.c", opts())
        self.assertEqual(out, "/anywhere/at/all/main.c")
        self.assertIn("warning", err.getvalue())
        self.assertIn("--source-root", err.getvalue())

    def test_warning_emitted_once(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            norm("/anywhere/one.c", opts())
            norm("/anywhere/two.c", opts())
            norm("/anywhere/three.c", opts())
        self.assertEqual(err.getvalue().count("warning"), 1)

    def test_no_warning_with_source_root(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            norm("/work/proj/src/quiet.c", opts(source_root=PROJ))
            norm("/opt/toolchain/quiet.c", opts(source_root=PROJ))
        self.assertEqual(err.getvalue(), "")

    def test_no_warning_with_markers(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            norm("/x/navcube/src/quiet.c", opts(keep=["/navcube/"]))
            norm("/opt/toolchain/quiet.c", opts(keep=["/navcube/"]))
        self.assertEqual(err.getvalue(), "")

    def test_no_warning_with_all_paths(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            norm("/anywhere/quiet/all.c", opts(all_paths=True))
        self.assertEqual(err.getvalue(), "")


class TestMarkers(unittest.TestCase):
    def test_marker_strips_from_component(self):
        self.assertEqual(
            norm("/work/navcube/src/app.c", opts(keep=["/navcube/"])),
            "navcube/src/app.c")

    def test_first_marker_wins(self):
        o = opts(keep=["/b/", "/a/"])
        self.assertEqual(norm("/root/a/b/c.c", o), "b/c.c")

    def test_unmatched_path_dropped_when_markers_given(self):
        self.assertIsNone(
            norm("/opt/toolchain/newlib/libc/foo.c", opts(keep=["/navcube/"])))


class TestAllPaths(unittest.TestCase):
    def test_keeps_absolute(self):
        out = norm("/work/navcube/src/app.c", opts(all_paths=True))
        self.assertTrue(out.startswith("/"))
        self.assertTrue(out.endswith("navcube/src/app.c"))

    def test_no_exclusions_by_default(self):
        self.assertEqual(norm("/x/testsuites/y/z.c", opts(all_paths=True)),
                         "/x/testsuites/y/z.c")

    def test_beats_source_root(self):
        out = norm("/work/proj/src/main.c", opts(source_root=PROJ,
                                                 all_paths=True))
        self.assertEqual(out, "/work/proj/src/main.c")


class TestExclude(unittest.TestCase):
    def test_glob_on_normalized_path(self):
        o = opts(source_root=PROJ, exclude=["tests/**"])
        self.assertIsNone(norm("/work/proj/tests/unit/t.c", o))
        self.assertEqual(norm("/work/proj/src/main.c", o), "src/main.c")

    def test_suffix_glob(self):
        o = opts(source_root=PROJ, exclude=["*.h"])
        self.assertIsNone(norm("/work/proj/src/api.h", o))
        self.assertEqual(norm("/work/proj/src/api.c", o), "src/api.c")

    def test_repeatable(self):
        o = opts(source_root=PROJ, exclude=["tests/**", "build/**"])
        self.assertIsNone(norm("/work/proj/tests/t.c", o))
        self.assertIsNone(norm("/work/proj/build/gen.c", o))
        self.assertEqual(norm("/work/proj/src/main.c", o), "src/main.c")

    def test_relative_pattern_anchors_at_any_boundary(self):
        # So the same pattern works against the absolute paths --all-paths
        # produces, not only against repo-relative ones.
        o = opts(all_paths=True, exclude=["tests/**"])
        self.assertIsNone(norm("/work/proj/tests/unit/t.c", o))
        self.assertEqual(norm("/work/proj/src/main.c", o),
                         "/work/proj/src/main.c")

    def test_non_matching_pattern_keeps_everything(self):
        o = opts(source_root=PROJ, exclude=["nothing-like-this/**"])
        self.assertEqual(norm("/work/proj/src/main.c", o), "src/main.c")


class TestRtemsPreset(unittest.TestCase):
    """The original RTEMS behaviour, now opt-in via --preset rtems."""

    def setUp(self):
        self.o = opts(source_root=SRC, preset="rtems")

    def test_contrib_prefix_preserved(self):
        # The bug this guards: the '/cpukit/' marker must not eat the
        # 'contrib/' prefix. Build path with .. that resolves under
        # contrib/cpukit.
        raw = "/src/rtems/build/mb/x/../../../contrib/cpukit/jffs2/nodelist.c"
        self.assertEqual(norm(raw, self.o), "contrib/cpukit/jffs2/nodelist.c")

    def test_cpukit_kept(self):
        self.assertEqual(norm("/src/rtems/cpukit/score/src/x.c", self.o),
                         "cpukit/score/src/x.c")

    def test_bsps_kept(self):
        self.assertEqual(norm("/src/rtems/bsps/microblaze/x.c", self.o),
                         "bsps/microblaze/x.c")

    def test_testsuites_excluded_by_default(self):
        p = "/src/rtems/testsuites/sptests/sp01/init.c"
        self.assertIsNone(norm(p, self.o))
        inc = opts(source_root=SRC, preset="rtems", include_testsuites=True)
        self.assertEqual(norm(p, inc), "testsuites/sptests/sp01/init.c")

    def test_newlib_excluded(self):
        # Not under the source root and no cpukit/bsps marker -> dropped.
        self.assertIsNone(norm("/opt/toolchain/newlib/libc/foo.c", self.o))

    def test_unknown_under_root_excluded(self):
        # Under the source root but not an OS tree -> dropped (no marker).
        self.assertIsNone(norm("/src/rtems/spec/build/x.yml", self.o))

    def test_marker_fallback_without_source_root(self):
        o = opts(preset="rtems")
        self.assertEqual(norm("/anywhere/cpukit/rtems/src/taskcreate.c", o),
                         "cpukit/rtems/src/taskcreate.c")
        self.assertEqual(norm("/anywhere/contrib/cpukit/jffs2/n.c", o),
                         "contrib/cpukit/jffs2/n.c")

    def test_testsuites_marker_without_source_root(self):
        p = "/anywhere/testsuites/sptests/sp01/init.c"
        self.assertIsNone(norm(p, opts(preset="rtems")))
        self.assertEqual(
            norm(p, opts(preset="rtems", include_testsuites=True)),
            "testsuites/sptests/sp01/init.c")

    def test_all_paths_excludes_testsuites(self):
        o = opts(preset="rtems", all_paths=True)
        self.assertIsNone(norm("/x/testsuites/y/z.c", o))
        self.assertEqual(norm("/x/cpukit/y/z.c", o), "/x/cpukit/y/z.c")

    def test_extra_keep_marker_still_works(self):
        o = opts(source_root=SRC, preset="rtems", keep=["/navcube/"])
        self.assertEqual(norm("/work/navcube/src/app.c", o),
                         "navcube/src/app.c")
        self.assertEqual(norm("/src/rtems/cpukit/score/src/x.c", o),
                         "cpukit/score/src/x.c")

    def test_preset_is_pure_expansion(self):
        # A preset must add no behaviour of its own: spelling out its markers,
        # roots and excludes by hand has to give the same bundle.
        o = path_options(argparse.Namespace(
            source_root=SRC, preset="rtems", keep=[], exclude=[],
            include_testsuites=False, all_paths=False))
        self.assertEqual(o.markers, paths.PRESETS["rtems"]["markers"])
        self.assertEqual(o.roots, paths.PRESETS["rtems"]["roots"])
        self.assertEqual(o.excludes, paths.PRESETS["rtems"]["excludes"])


class TestCache(unittest.TestCase):
    """The cache is keyed on every option, so it never answers a stale call."""

    RAW = "/src/cachetest/pkg/mod/file.c"

    def test_same_path_different_options(self):
        first = norm(self.RAW, opts(source_root="/src/cachetest"))
        self.assertEqual(first, "pkg/mod/file.c")

        deeper = opts(source_root="/src/cachetest/pkg")
        self.assertEqual(norm(self.RAW, deeper), "mod/file.c")
        self.assertEqual(norm(self.RAW, opts(keep=["/mod/"])), "mod/file.c")
        self.assertEqual(norm(self.RAW, opts(all_paths=True)), self.RAW)
        self.assertIsNone(norm(self.RAW, opts(source_root="/src/other")))
        self.assertIsNone(norm(self.RAW, opts(source_root="/src/cachetest",
                                              exclude=["pkg/**"])))
        self.assertIsNone(norm(self.RAW, opts(source_root="/src/cachetest",
                                              preset="rtems")))

        # ... and the original answer is unchanged after all of that.
        self.assertEqual(norm(self.RAW, opts(source_root="/src/cachetest")),
                         first)

    def test_repeat_call_is_cached(self):
        o = opts(source_root="/src/cachetest")
        key = (self.RAW, o.source_root, o.markers, o.roots, o.excludes,
               o.all_paths)
        norm(self.RAW, o)
        self.assertIn(key, paths._norm_cache)
        self.assertEqual(paths._norm_cache[key], norm(self.RAW, o))


if __name__ == "__main__":
    unittest.main()
