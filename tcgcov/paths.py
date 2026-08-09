"""Source-path normalization shared by the covered and coverable producers.

Identical normalization on both sides is what lets coverage merge by
(source path + line) instead of by address.
"""

import fnmatch
import os
import sys
from collections import namedtuple

# Named option bundles for a known project layout. A preset is exactly
# equivalent to passing the plain options it expands to -- nothing downstream
# special-cases a preset name:
#   markers  -- "keep from here" path substrings (same meaning as --keep), in
#               priority order: the FIRST one found in the path wins
#   roots    -- top-level trees under --source-root that count as coverage;
#               anything else under the root falls through to marker stripping.
#               Empty means "keep everything under the source root".
#   excludes -- fnmatch patterns dropped from the normalized result
# To add a preset, add one entry here and nothing else: --preset offers the
# dict's keys as its choices and path_options() expands whichever is selected.
PRESETS = {
    # RTEMS: cpukit/bsps are the core OS, contrib holds vendored OS code (e.g.
    # contrib/cpukit/jffs2), testsuites is the test code rather than the OS.
    # "/contrib/" is listed FIRST so a vendored path keeps its contrib/ prefix
    # instead of having it eaten by the later "/cpukit/".
    "rtems": {
        "markers": ("/contrib/", "/cpukit/", "/bsps/"),
        "roots": ("cpukit", "bsps", "contrib"),
        "excludes": ("testsuites/**",),
    },
}

# What the --include-testsuites alias has to undo to restore the pre-preset
# RTEMS behaviour of keeping the testsuites tree.
_TESTSUITES_MARKER = "/testsuites/"
_TESTSUITES_ROOT = "testsuites"
_TESTSUITES_EXCLUDE = "testsuites/**"

# The immutable bundle of path options every producer normalizes with. Field
# order matches normalize_path()'s parameters, and being a tuple of tuples it
# is hashable, so it doubles as part of the normalization cache key.
PathOptions = namedtuple("PathOptions",
                         "source_root markers roots excludes all_paths")

# Cache: realpath() does filesystem stats, and normalize_path is called once
# per addr2line frame (tens of thousands of times) but over few unique paths.
_norm_cache = {}
_MISS = object()

# One-shot latch for the "no source root" warning below: worth saying once per
# process, not once per frame.
_warned_no_root = False


def path_options(args):
    """Build the PathOptions bundle from parsed command-line arguments.

    Resolves --preset (and the --include-testsuites alias) into plain
    markers/roots/excludes here, once, so the normalizer itself knows nothing
    about any particular project layout.
    """
    preset = PRESETS.get(getattr(args, "preset", None) or "", {})
    markers = (tuple(preset.get("markers", ()))
               + tuple(getattr(args, "keep", None) or ()))
    roots = tuple(preset.get("roots", ()))
    excludes = (tuple(preset.get("excludes", ()))
                + tuple(getattr(args, "exclude", None) or ()))

    if getattr(args, "include_testsuites", False):
        # Alias kept for the original RTEMS workflow: cancel the preset's
        # testsuites exclusion and make the tree reachable again by whichever
        # of the two paths (source root, markers) the preset uses.
        excludes = tuple(p for p in excludes if p != _TESTSUITES_EXCLUDE)
        if roots and _TESTSUITES_ROOT not in roots:
            roots += (_TESTSUITES_ROOT,)
        if markers and _TESTSUITES_MARKER not in markers:
            markers += (_TESTSUITES_MARKER,)

    return PathOptions(getattr(args, "source_root", None), markers, roots,
                       excludes, bool(getattr(args, "all_paths", False)))


def normalize_path(raw, source_root=None, markers=(), roots=(), excludes=(),
                   all_paths=False):
    """Normalize an absolute build path to a stable, mergeable form.

    Returns None for paths that should be excluded from coverage.

    Modes, tried in this order:
      * all_paths=True: keep every real source file by its ABSOLUTE path. Best
        for a single-binary report -- absolute paths defeat cross-binary
        merge-by-source, so it is opt-in.
      * source_root: keep every source file under the root, normalized
        relative to it (via realpath, which resolves '..' and symlink prefixes
        like /local), and drop everything outside it -- toolchain headers,
        libc, crt objects, generated files in other trees. If `roots` is
        non-empty only those top-level trees under the root are kept and the
        rest falls through to marker stripping.
      * markers: "keep from here" substrings, for source that lives outside
        the source root. The first marker found wins, and the path is kept
        from that component on, so '/w/navcube/src/app.c' with marker
        '/navcube/' becomes 'navcube/src/app.c'.
      * none of the above: keep by absolute path (as all_paths) and warn once,
        because dropping everything instead is silent total data loss.

    `excludes` are fnmatch patterns applied last, to the normalized path.
    `markers`, `roots` and `excludes` must be tuples (they are part of the
    cache key).
    """
    if not raw or raw == "??":
        return None

    key = (raw, source_root, tuple(markers), tuple(roots), tuple(excludes),
           all_paths)
    cached = _norm_cache.get(key, _MISS)
    if cached is not _MISS:
        return cached

    result = _normalize_uncached(raw, source_root, key[2], key[3], key[4],
                                 all_paths)
    _norm_cache[key] = result
    return result


def _normalize_uncached(raw, source_root, markers, roots, excludes, all_paths):
    global _warned_no_root

    real = os.path.realpath(raw)
    sep = os.sep
    result = None

    if all_paths:
        result = real
    else:
        if source_root:
            sr = os.path.realpath(source_root)
            if real.startswith(sr + sep):
                rel = os.path.relpath(real, sr)
                if not roots or rel.split(sep, 1)[0] in roots:
                    result = rel
        if result is None:
            result = _strip_marker(real, markers)
        if result is None and not source_root and not markers:
            if not _warned_no_root:
                _warned_no_root = True
                print("warning: no --source-root, --keep or --all-paths "
                      "given: keeping absolute source paths, so this report "
                      "cannot be merged with reports from other binaries "
                      "(pass --source-root to make paths repo-relative)",
                      file=sys.stderr)
            result = real

    if result is None or (excludes and _excluded(result, excludes)):
        return None
    return result


def _strip_marker(real, markers):
    """Return `real` kept from the first matching marker on, or None.

    Both spellings of a marker mean the same thing and must give the same
    answer: '--keep /cpukit/' and '--keep cpukit/' both turn
    '/w/rtems/cpukit/score/x.c' into 'cpukit/score/x.c'. Only the leading-slash
    spelling has a separator to skip past -- dropping a character
    unconditionally turned the other one into 'pukit/score/x.c'.
    """
    slashed = real if real.startswith("/") else "/" + real
    for marker in markers:
        idx = slashed.find(marker)
        if idx != -1:
            if marker.startswith("/"):
                idx += 1        # keep from AFTER the separator
            return slashed[idx:]
    return None


def _excluded(path, excludes):
    """True if the normalized `path` matches any fnmatch exclude pattern.

    A pattern is matched against the whole normalized path; a relative pattern
    (one that does not start with a separator or a wildcard) additionally
    matches at any directory boundary, so 'testsuites/**' drops both the
    repo-relative 'testsuites/x.c' and the absolute '/src/testsuites/x.c' that
    --all-paths produces.
    """
    for pat in excludes:
        if fnmatch.fnmatch(path, pat):
            return True
        if not pat.startswith(("/", "*", "?", "[")) and \
                fnmatch.fnmatch(path, "*/" + pat):
            return True
    return False
