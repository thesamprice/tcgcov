"""Drive the whole chain in one command: .cov artifacts -> LCOV .info.

    <raw>/*.cov
      -> <out>/symbolized/*.jsonl          (symbolize)
      -> <out>/coverable/*.jsonl           (coverable, cached per ELF)
      -> <out>/branches/*.jsonl            (branches)
      -> <out>/lcov/per-test/*.info        (lcov)
      -> <out>/lcov/aggregate-<arch>.info  (merge)
      -> <out>/html/index.html             (genhtml, only with --html)

The ELF for each artifact is read from that artifact's own embedded metadata,
so there is no manifest to maintain; --elf overrides it for every artifact,
which is what a `dump --scrub-out` copy (whose paths have been redacted) needs.
A slice cut by `tcgcov modmap` carries its own object and section instead, and
is analysed against those, so a directory of dynamically-loaded-object slices
reports with no per-object flags either.

An artifact recorded in the plugin's RTEMS loader mode is split first (see
`tcgcov rtl-split`): its base-image addresses are reported against the base
ELF, and its dynamically loaded objects against their own `.o` files, found
on --obj-path and checked against the sections the target actually loaded.

The path-selection options are the reason this command exists rather than a
README recipe: the covered and the coverable side must be normalized
IDENTICALLY or the join in `lcov` silently compares two different key spaces
and the percentage is wrong. Here they are given once and threaded to every
producer, and they are folded into the coverable cache key so that re-running
with a different --source-root cannot reuse an inventory built under the old
one.

Each step is the same subcommand a hand-run pipeline would use, called
in-process; nothing here reimplements them.
"""

import argparse
import io
import os
import re
import subprocess
import sys
import threading
import zlib
from concurrent.futures import ThreadPoolExecutor

from . import addr2line as symbolize_mod
from . import branches as branches_mod
from . import cfg
from . import coverable as coverable_mod
from . import lcov as lcov_mod
from . import merge as merge_mod
from . import rtl as rtl_mod
from .cliargs import add_symbolize_args
from .coverable import DENOMINATOR_SOURCES
from .format import read_metadata

# Per-artifact outcomes.
OK, SKIPPED, FAILED = "ok", "skipped", "failed"


def add_arguments(parser):
    parser.add_argument("cov", nargs="*", metavar="COV",
                        help="input .cov artifacts (shell globs are fine); "
                             "may be combined with --raw-dir")
    parser.add_argument("--raw-dir", action="append", default=[],
                        metavar="DIR",
                        help="directory of *.cov artifacts (repeatable)")
    parser.add_argument("--out-dir", required=True, metavar="DIR",
                        help="output tree: symbolized/, coverable/, "
                             "branches/, lcov/ and (with --html) html/")
    parser.add_argument("--out", metavar="FILE",
                        help="aggregate .info path "
                             "(default: <out-dir>/lcov/aggregate-<arch>.info)")
    parser.add_argument("--name", metavar="NAME",
                        help="aggregate LCOV test name (TN); default: the arch")
    parser.add_argument("--elf", metavar="FILE",
                        help="use this ELF for every artifact, overriding the "
                             "path each one records. For an unstripped copy "
                             "of a stripped image (the artifact names the "
                             "binary that ran, which carries no DWARF), for a "
                             "tree that has moved since the run, and for a "
                             "`dump --scrub-out` copy whose paths were "
                             "redacted")
    add_symbolize_args(parser)
    rtl_mod.add_obj_path_args(parser)
    parser.add_argument("--objdump", help="explicit objdump path")
    parser.add_argument("--denominator", choices=DENOMINATOR_SOURCES,
                        default="auto",
                        help="coverable-line source: 'objdump', 'dwarf' (no "
                             "target toolchain needed) or 'auto'. "
                             "Default: auto")
    parser.add_argument("--no-cross-check", dest="cross_check",
                        action="store_false", default=True,
                        help="skip comparing the objdump denominator against "
                             "the DWARF line table")
    parser.add_argument("--no-branches", dest="do_branches",
                        action="store_false", default=True,
                        help="skip branch analysis (line coverage only)")
    parser.add_argument("--arch-profile", action="append", default=[],
                        metavar="FILE",
                        help="JSON arch profile(s) for branch analysis on an "
                             "ISA the package does not ship (repeatable)")
    parser.add_argument("--jobs", "-j", type=int, metavar="N",
                        help="artifacts to process at once "
                             "(default: CPU count; 1 for serial)")
    parser.add_argument("--html", nargs="?", const="", metavar="DIR",
                        help="also render HTML with genhtml "
                             "(default directory: <out-dir>/html)")
    parser.add_argument("--genhtml", default="genhtml",
                        help="genhtml path (default: genhtml)")


# --- helpers ----------------------------------------------------------------

def _safe(path):
    """A filesystem-safe, collision-resistant cache stem for a path.

    The basename alone collides across build trees (every RTEMS test links its
    own `test.exe`), and a mangled full path is both unreadable and unbounded,
    so keep the readable half and disambiguate with a hash of the whole thing.
    """
    real = os.path.abspath(path).encode("utf-8", "surrogateescape")
    tag = "%08x" % (zlib.crc32(real) & 0xFFFFFFFF)
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path)) or "elf"
    return "%s.%s" % (stem, tag)


def _nonempty(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _write_atomic(path, text, tag):
    """Write via a per-worker temp file and rename.

    Two workers can want the same cache entry at the same moment; a rename is
    atomic, so the loser overwrites with identical bytes instead of a reader
    seeing a half-written file.
    """
    tmp = "%s.%s.tmp" % (path, tag)
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


class _KeyedLocks:
    """One lock per key, created on demand.

    Per-ELF work (disassembly, the coverable inventory) is shared by every
    artifact that links that ELF. Without this, a cold cache has N workers
    doing the same objdump and the same addr2line run concurrently -- the
    expensive half of the pipeline, duplicated N ways.
    """

    def __init__(self):
        self._guard = threading.Lock()
        self._locks = {}

    def __call__(self, key):
        with self._guard:
            lock = self._locks.get(key)
            if lock is None:
                lock = self._locks[key] = threading.Lock()
            return lock


class _FanOutStderr:
    """A sys.stderr that buffers per worker thread.

    Every subcommand reports its counts and its warnings on stderr, and those
    warnings are the ones that matter ("coverable adds no lines", "no
    .debug_info"). Interleaved line by line across N artifacts they become
    untraceable, so each worker collects its own and flushes it in one piece.
    """

    def __init__(self, real):
        self._real = real
        self._local = threading.local()

    def capture(self, buf):
        self._local.buf = buf

    def release(self):
        self._local.buf = None

    def _target(self):
        return getattr(self._local, "buf", None) or self._real

    def write(self, s):
        return self._target().write(s)

    def flush(self):
        self._target().flush()

    def __getattr__(self, name):        # isatty, encoding, fileno, ...
        return getattr(self._real, name)


def _path_argv(args):
    """The path-selection options, exactly as every producer must see them."""
    argv = []
    if args.source_root:
        argv += ["--source-root", args.source_root]
    if args.all_paths:
        argv += ["--all-paths"]
    for marker in args.keep:
        argv += ["--keep", marker]
    for pattern in args.exclude:
        argv += ["--exclude", pattern]
    if args.preset:
        argv += ["--preset", args.preset]
    if args.include_testsuites:
        argv += ["--include-testsuites"]
    return argv


def _target_of(args, meta):
    """The (ELF, section) an artifact should be analysed against.

    `tcgcov modmap` stamps each slice it cuts with the object it came from
    (`module_file`) and the section the addresses are offsets into
    (`module_section`), because a dynamically loaded object is symbolized
    against its own `.o` and not against the base image -- whose path the
    slice still carries in `elf`, inherited from the artifact it was cut out
    of. Preferring the module keys is what lets a directory of slices be
    reported with no per-object flags at all; --elf/--section still win.
    """
    if meta.get("rtl_split_from") and meta.get("module_file"):
        # Cut by this run's RTEMS split: the object was resolved and verified
        # on --obj-path, and --elf/--section describe the base image.
        return meta["module_file"], meta.get("module_section") or ""
    elf = args.elf or meta.get("module_file") or meta.get("elf", "")
    section = args.section or meta.get("module_section") or ""
    return elf, section


def _tool_argv(args):
    argv = ["--toolchain-prefix", args.toolchain_prefix]
    if args.addr2line:
        argv += ["--addr2line", args.addr2line]
    return argv


def _collect_covs(args):
    """Positional artifacts plus every *.cov under each --raw-dir, deduped."""
    found = list(args.cov)
    for raw in args.raw_dir:
        if not os.path.isdir(raw):
            raise ValueError("%s: not a directory" % raw)
        found += [os.path.join(raw, n) for n in sorted(os.listdir(raw))
                  if n.endswith(".cov")]
    seen, covs = set(), []
    for path in found:
        key = os.path.abspath(path)
        if key not in seen:
            seen.add(key)
            covs.append(path)
    return covs


def _base_names(covs):
    """Map each artifact to a unique per-test output stem.

    Artifacts from different directories can share a basename, and two of them
    writing one `<base>.info` would drop a whole run's coverage from the
    aggregate while still exiting 0.
    """
    stems = {}
    for path in covs:
        stem = os.path.basename(path)
        stem = stem[:-4] if stem.endswith(".cov") else (stem or "artifact")
        stems.setdefault(stem, []).append(path)
    names = {}
    for stem, paths in stems.items():
        for path in paths:
            names[path] = stem if len(paths) == 1 else "%s.%s" % (
                stem, _safe(path).rsplit(".", 1)[1])
    return names


# --- the per-artifact pipeline ----------------------------------------------

class _Run:
    """Everything the workers share: resolved options, dirs, caches."""

    def __init__(self, args, covs, arch):
        self.args = args
        self.arch = arch
        self.names = _base_names(covs)
        self.path_argv = _path_argv(args)
        self.tool_argv = _tool_argv(args)
        self.locks = _KeyedLocks()
        self.note_lock = threading.Lock()
        self.notes = set()
        self.branch_infos = 0

        out = args.out_dir
        self.sym_dir = os.path.join(out, "symbolized")
        self.cab_dir = os.path.join(out, "coverable")
        self.dis_dir = os.path.join(out, "disasm")
        self.br_dir = os.path.join(out, "branches")
        self.pt_dir = os.path.join(out, "lcov", "per-test")
        dirs = [self.sym_dir, self.cab_dir, self.pt_dir]
        if self.need_disasm:
            dirs.append(self.dis_dir)
        if args.do_branches:
            dirs.append(self.br_dir)
        for d in dirs:
            os.makedirs(d, exist_ok=True)

        # The coverable inventory is keyed by NORMALIZED source path, so the
        # same ELF analysed under a different --source-root/--keep/--exclude
        # yields a different, incompatible denominator. Keying the cache on the
        # ELF alone silently reuses the wrong one across runs.
        sig = "\0".join([arch, args.denominator] + self.path_argv)
        self.sig = "%08x" % (zlib.crc32(sig.encode("utf-8", "surrogateescape"))
                             & 0xFFFFFFFF)

    @property
    def need_disasm(self):
        """objdump output is shared by the coverable and the branch side.

        With --denominator dwarf and --no-branches nothing needs it at all,
        and that combination is the whole point of the DWARF denominator: a
        report with no target toolchain installed.
        """
        return self.args.do_branches or self.args.denominator != "dwarf"

    def note_once(self, text):
        with self.note_lock:
            if text in self.notes:
                return
            self.notes.add(text)
        print("note: %s" % text, file=sys.stderr)

    def disasm_for(self, elf):
        """Disassemble an ELF once per run, however many artifacts use it."""
        path = os.path.join(self.dis_dir, _safe(elf) + ".txt")
        with self.locks(("disasm", path)):
            if not _nonempty(path):
                objdump = (self.args.objdump or
                           self.args.toolchain_prefix + "objdump")
                _write_atomic(path, cfg.disassemble(objdump, elf),
                              str(threading.get_ident()))
        return path

    def coverable_for(self, elf, section, disasm):
        """The denominator: test-agnostic, so computed once per (ELF, options)."""
        stem = _safe(elf) + (".%s" % re.sub(r"[^A-Za-z0-9._-]", "_", section)
                             if section else "")
        path = os.path.join(self.cab_dir, "%s.%s.jsonl" % (stem, self.sig))
        with self.locks(("coverable", path)):
            if _nonempty(path):
                return path
            tmp = "%s.%d.tmp" % (path, threading.get_ident())
            argv = (["--elf", elf, "--arch", self.arch, "--out", tmp,
                     "--denominator", self.args.denominator]
                    + self.tool_argv + self.path_argv
                    + (["--section", section] if section else []))
            if disasm:
                argv += ["--disasm", disasm]
            if self.args.objdump:
                argv += ["--objdump", self.args.objdump]
            if not self.args.cross_check:
                argv += ["--no-cross-check"]
            if coverable_mod.main(argv) != 0:
                return None
            os.replace(tmp, path)
        return path


def _process_one(cov, run):
    """Symbolize, inventory, analyse branches and emit one per-test .info."""
    args = run.args
    base = run.names[cov]

    try:
        meta = read_metadata(cov)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return FAILED
    elf, section = _target_of(args, meta)
    if not elf or not os.path.isfile(elf):
        print("warning: ELF not found for %s (%s); skipping"
              % (base, elf or "no 'elf' key in the artifact metadata"),
              file=sys.stderr)
        run.note_once("an artifact names a binary this machine does not have; "
                      "--elf FILE analyses every artifact against one ELF "
                      "instead (an unstripped copy, or a moved tree)")
        return SKIPPED
    sec_argv = ["--section", section] if section else []

    try:
        disasm = run.disasm_for(elf) if run.need_disasm else None
    except (OSError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return FAILED

    sym = os.path.join(run.sym_dir, base + ".jsonl")
    if symbolize_mod.main(["--cov", cov, "--elf", elf, "--arch", run.arch,
                           "--out", sym]
                          + run.tool_argv + run.path_argv + sec_argv) != 0:
        return FAILED

    cab = run.coverable_for(elf, section, disasm)
    if cab is None:
        return FAILED

    br_argv = []
    if args.do_branches:
        br = os.path.join(run.br_dir, base + ".jsonl")
        argv = (["--cov", cov, "--elf", elf, "--disasm", disasm,
                 "--arch", run.arch, "--out", br]
                + run.tool_argv + run.path_argv + sec_argv)
        for profile in args.arch_profile:
            argv += ["--arch-profile", profile]
        rc = branches_mod.main(argv)
        # Exit 2 means this architecture has no branch profile -- an expected,
        # benign gap, so carry on with line coverage. Anything else is a real
        # failure (unparseable disassembly, corrupt .cov) and must not be
        # downgraded to a note: silently dropping branch data looks exactly
        # like a genuine coverage regression.
        if rc == 0:
            br_argv = ["--branches", br]
            with run.note_lock:
                run.branch_infos += 1
        elif rc == 2:
            run.note_once("no branch profile for arch '%s'; line coverage only"
                          % run.arch)
        else:
            print("error: branch analysis failed for %s (rc=%d)" % (base, rc),
                  file=sys.stderr)
            return FAILED

    info = os.path.join(run.pt_dir, base + ".info")
    if lcov_mod.main([sym, "--coverable", cab, "--out", info]
                     + br_argv) != 0:
        return FAILED
    return OK


def _run_all(covs, run, jobs):
    """Process every artifact, returning its outcome, in input order."""
    if jobs == 1:
        return [_process_one(cov, run) for cov in covs]

    print("processing %d artifacts with %d parallel jobs" % (len(covs), jobs),
          file=sys.stderr)
    fan = _FanOutStderr(sys.stderr)
    real_stderr = sys.stderr
    sys.stderr = fan

    def worker(cov):
        buf = io.StringIO()
        fan.capture(buf)
        try:
            return _process_one(cov, run), buf.getvalue()
        finally:
            fan.release()

    try:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(worker, covs))
    finally:
        sys.stderr = real_stderr
    outcomes = []
    for outcome, text in results:
        real_stderr.write(text)
        outcomes.append(outcome)
    real_stderr.flush()
    return outcomes


def _split_rtl(args, covs):
    """Replace each RTEMS loader-generation artifact by its split slices.

    The base-image slice and every per-object slice then run through the
    ordinary per-artifact pipeline. An object that is on --obj-path but does
    not match what the target loaded is an error (it would be reported
    against the wrong source); one that is simply absent is a warning.
    """
    objpath = None
    if args.obj_path:
        objpath = rtl_mod.ObjectPath(rtl_mod.split_path_args(args.obj_path),
                                     args.obj_suffix)
    out, conflicts, missing = [], 0, 0
    names = _base_names(covs)
    for cov in covs:
        if not rtl_mod.is_rtl_artifact(read_metadata(cov)):
            out.append(cov)
            continue
        summary = rtl_mod.split(
            cov, objpath, os.path.join(args.out_dir, "rtl", names[cov]),
            obj_dir=os.path.join(args.out_dir, "rtl", "objs"),
            no_verify=args.obj_no_verify, stem=names[cov])
        rtl_mod.print_summary(cov, summary)
        for u in summary["unresolved"].values():
            if u["kind"] == "conflict":
                conflicts += 1
            else:
                missing += 1
        out.append(summary["base"])
        out += [m["out"] for m in summary["modules"]]
    if missing and not args.obj_path:
        print("note: loaded-object coverage was not attributed; pass "
              "--obj-path DIR with the host copies of the loaded .o files",
              file=sys.stderr)
    if conflicts:
        raise ValueError("%d loaded object(s) matched no file on --obj-path "
                         "consistently (see above); fix the path, or pass "
                         "--obj-no-verify to accept the first candidate"
                         % conflicts)
    return out


def _genhtml(args, agg, branch_coverage):
    """Render the aggregate, from the source root so relative SF paths resolve."""
    html_dir = args.html or os.path.join(args.out_dir, "html")
    os.makedirs(html_dir, exist_ok=True)
    cmd = [args.genhtml, os.path.abspath(agg),
           "--output-directory", os.path.abspath(html_dir),
           "--quiet", "--ignore-errors", "source"]
    if branch_coverage:
        cmd.append("--branch-coverage")
    # genhtml resolves relative SF paths against cwd; absolute paths
    # (--all-paths) resolve anywhere, so fall back to '/' with no source root.
    try:
        proc = subprocess.run(cmd, cwd=args.source_root or os.sep)
    except OSError as e:
        print("error: %s: %s (install lcov, or pass --genhtml)"
              % (args.genhtml, e), file=sys.stderr)
        return None
    if proc.returncode != 0:
        print("error: genhtml failed (rc=%d)" % proc.returncode,
              file=sys.stderr)
        return None
    return os.path.join(html_dir, "index.html")


def run(args):
    try:
        covs = _collect_covs(args)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    if not covs:
        where = ", ".join(args.raw_dir) or "the arguments"
        print("error: no .cov artifacts in %s" % where, file=sys.stderr)
        return 1

    try:
        covs = _split_rtl(args, covs)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    # Default the arch label to the target the plugin recorded.
    arch = args.arch
    if not arch:
        try:
            arch = read_metadata(covs[0]).get("target_name", "")
        except (OSError, ValueError) as e:
            print("error: %s" % e, file=sys.stderr)
            return 1
        if arch:
            print("arch not given; using the target from %s metadata: %s"
                  % (os.path.basename(covs[0]), arch), file=sys.stderr)
        else:
            arch = "unknown"

    try:
        run_ctx = _Run(args, covs, arch)
    except OSError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    jobs = args.jobs if args.jobs else (os.cpu_count() or 4)
    jobs = max(1, min(jobs, len(covs)))
    outcomes = _run_all(covs, run_ctx, jobs)

    failed = outcomes.count(FAILED)
    skipped = outcomes.count(SKIPPED)
    infos = [os.path.join(run_ctx.pt_dir, run_ctx.names[cov] + ".info")
             for cov, outcome in zip(covs, outcomes) if outcome == OK]
    if failed:
        print("error: %d of %d artifacts failed" % (failed, len(covs)),
              file=sys.stderr)
        return 1
    if not infos:
        # Every artifact was skipped. Merging nothing would produce an empty
        # .info that reads as "this campaign covered nothing" rather than as
        # "the ELFs the artifacts name are not on this machine".
        print("error: no artifact could be processed (%d skipped); the ELF "
              "each one names must exist, or be overridden with --elf"
              % skipped, file=sys.stderr)
        return 1

    agg = args.out or os.path.join(args.out_dir, "lcov",
                                   "aggregate-%s.info" % arch)
    os.makedirs(os.path.dirname(os.path.abspath(agg)), exist_ok=True)
    if merge_mod.main(["--name", args.name or arch, "--out", agg]
                      + sorted(infos)) != 0:
        return 1

    if skipped:
        print("note: %d of %d artifacts skipped (ELF not found)"
              % (skipped, len(covs)), file=sys.stderr)
    print("aggregate: %s" % agg)
    if args.html is not None:
        index = _genhtml(args, agg, run_ctx.branch_infos > 0)
        if index is None:
            return 1
        print("report: %s" % index)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
