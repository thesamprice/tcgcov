"""Show code an app executes that a baseline (e.g. the test suite) does NOT cover.

Computes the set difference: lines covered by --cov/--app (the app run) that are
NOT covered in --baseline (the suite aggregate). The output .info uses the
app-executed lines as the universe; a line is marked covered iff the baseline
also covers it, so in the HTML the **uncovered (red) lines are the gap** -- code
the app runs but the suite never tests -- and the percentage is "how much of the
app-executed code the baseline covers".

Branch outcomes are treated the same way when the app side is an LCOV .info
carrying BRDA records: the universe is the outcomes the app took, and an
outcome counts as covered only if the baseline took it too.

Both sides must share normalization, so symbolize the app .cov with the same
path flags as the baseline (default RTEMS-OS-only, cpukit/bsps/contrib relative);
pass the source root used to build the app so contrib/ paths line up. When the
two sides share no source file at all that is nearly always a normalization
mismatch rather than a 100% gap, so it is called out loudly.
"""

import argparse
import json
import sys
from collections import defaultdict

from .format import read_cov
from .symbolize import iter_covered_lines
from .lcov import emit_branches
from .merge import parse_info
from .restrict import run_genhtml
from .cliargs import add_symbolize_args
from .paths import path_options

# LCOV record types that can legally open a .info file. Used to tell a .info
# from a JSONL by its CONTENT -- guessing from the file extension made
# `--app app.json` (or app.JSONL, or app.cov.jsonl.txt) parse as LCOV, find no
# SF:, and report a confident "0 GAP lines".
_LCOV_PREFIXES = ("TN:", "SF:", "DA:", "FN:", "FNDA:", "FNF:", "FNH:",
                  "BRDA:", "BRF:", "BRH:", "LF:", "LH:", "VER:",
                  "end_of_record")


def sniff_app_format(path):
    """Return "jsonl" or "info" for an --app file, by looking inside it."""
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("{"):
                return "jsonl"
            if raw.startswith(_LCOV_PREFIXES):
                return "info"
            raise ValueError(
                f"{path}: not recognizable as tcgcov JSONL (records start "
                f"with '{{') or as LCOV .info (records start with TN:/SF:/"
                f"DA:/...); first line was: {raw[:60]!r}")
    raise ValueError(f"{path}: file is empty, so the app side has no "
                     f"executed lines to compare against the baseline")


def load_app(args):
    """Return (app_count{(sf,line):count}, func_decl{(sf,name):line},
    func_lines{(sf,name):set(lines)} or None, app_branches{sf:{key:taken}}).

    app_branches holds only outcomes the app actually TOOK (taken > 0) -- the
    branch analogue of "the app executed this line". Only the LCOV .info input
    carries branch records; the JSONL and .cov inputs have none, so the branch
    section is simply absent for them."""
    app_count = {}
    func_decl = {}
    func_lines = defaultdict(set)
    app_branches = {}

    if args.cov:
        addr2line = args.addr2line or (args.toolchain_prefix + "addr2line")
        meta, addrs, counts = read_cov(args.cov)
        for norm, line, func, _depth, addr in iter_covered_lines(
                addr2line, args.elf, addrs, path_options(args)):
            # The address is in the .cov, so the line RAN: floor the count at
            # 1. A 0 (missing from the counts table) used to lose the "is
            # greater than" race below and drop the line from the app's
            # universe entirely -- silently shrinking the gap denominator.
            c = max(1, counts.get(addr, 0)) if counts else 1
            k = (norm, line)
            if c > app_count.get(k, 0):
                app_count[k] = c
            fk = (norm, func)
            if func and (fk not in func_decl or line < func_decl[fk]):
                func_decl[fk] = line
            if func:
                func_lines[fk].add(line)
        return app_count, func_decl, func_lines, app_branches

    # --app FILE: JSONL (symbolized) or LCOV .info, decided by content.
    path = args.app
    if sniff_app_format(path) == "jsonl":
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                    sf, ln = rec["file"], int(rec["line"])
                    # A symbolized record exists because the line executed;
                    # count 0 must not drop it from the app's universe.
                    cnt = max(1, int(rec.get("count", 1)))
                except (ValueError, KeyError, TypeError) as e:
                    raise ValueError(f"{path}:{lineno}: not a symbolized "
                                     f"coverage record ({e})")
                k = (sf, ln)
                if cnt > app_count.get(k, 0):
                    app_count[k] = cnt
                fn = rec.get("function")
                if fn:
                    fk = (sf, fn)
                    if fk not in func_decl or ln < func_decl[fk]:
                        func_decl[fk] = ln
                    func_lines[fk].add(ln)
        return app_count, func_decl, func_lines, app_branches

    # LCOV .info: covered lines only (DA hits > 0); no per-line function map.
    cov = defaultdict(set)
    lh = defaultdict(dict)
    fl = defaultdict(dict)
    fh = defaultdict(dict)
    bd = defaultdict(dict)
    parse_info(path, cov, lh, fl, fh, bd)
    for sf, lines in lh.items():
        for ln, cnt in lines.items():
            app_count[(sf, ln)] = cnt
    for sf, fns in fl.items():
        for name, ln in fns.items():
            # Only functions the app RAN belong in an app-executed universe:
            # counting every declared function inflated FNF (and FNH, whenever
            # the baseline covered a function the app never entered).
            if fh.get(sf, {}).get(name, 0) > 0 or (sf, ln) in app_count:
                func_decl[(sf, name)] = ln
    for sf, branches in bd.items():
        taken_only = {k: v for k, v in branches.items() if v}
        if taken_only:
            app_branches[sf] = taken_only
    return app_count, func_decl, None, app_branches


def load_baseline_covered(path):
    """Return (covered{(sf, line)}, branches{sf: {(line,block,branch)}}).

    Covered means DA hits > 0 for lines and BRDA taken > 0 for branch
    outcomes -- what the baseline demonstrably exercised."""
    cov = defaultdict(set)
    lh = defaultdict(dict)
    fl = defaultdict(dict)
    fh = defaultdict(dict)
    bd = defaultdict(dict)
    parse_info(path, cov, lh, fl, fh, bd)
    lines = {(sf, ln) for sf, lines_ in lh.items() for ln in lines_}
    branches = {sf: {k for k, v in b.items() if v} for sf, b in bd.items()}
    return lines, branches


def add_arguments(parser):
    parser.add_argument("--baseline", required=True,
                        help="baseline LCOV .info to subtract (e.g. the suite "
                             "aggregate)")
    parser.add_argument("--cov", help="app .cov (TCGCOV1); needs --elf")
    parser.add_argument("--elf", help="app ELF (with --cov)")
    parser.add_argument("--app", help="precomputed app coverage: symbolized "
                        "JSONL or LCOV .info, told apart by content, not by "
                        "file extension (alternative to --cov/--elf)")
    add_symbolize_args(parser)
    parser.add_argument("--name", default="gap",
                        help="LCOV test name (TN), default 'gap'")
    parser.add_argument("--html", metavar="DIR", help="also run genhtml into DIR")
    parser.add_argument("--out", required=True, help="output .info file")


def run(args):
    if args.cov and not args.elf:
        print("error: --cov requires --elf", file=sys.stderr)
        return 2
    if not args.cov and not args.app:
        print("error: provide --cov/--elf or --app", file=sys.stderr)
        return 2
    if args.cov and args.app:
        # Silently ignoring one of them means reporting on a different app
        # than the user named.
        print("error: --cov and --app are alternatives; pass only one",
              file=sys.stderr)
        return 2

    try:
        app_count, func_decl, func_lines, app_branches = load_app(args)
        suite, suite_branches = load_baseline_covered(args.baseline)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # An empty side makes the difference meaningless, and both empty cases
    # print as a clean run: no app lines reads as "0 GAP lines" (nothing
    # untested!) and no baseline lines reads as "0.0% covered" of everything.
    if not app_count:
        src = args.cov or args.app
        print(f"error: {src}: no executed lines for the app side, so there is "
              f"nothing to diff against the baseline. Check the app really "
              f"produced coverage and that the path options match the "
              f"baseline's. Refusing to write {args.out}.", file=sys.stderr)
        return 1
    if not suite:
        print(f"error: {args.baseline}: no covered lines (no DA record with a "
              f"non-zero count), so every app line would be reported as a "
              f"gap. Check this is the suite aggregate from `tcgcov merge`. "
              f"Refusing to write {args.out}.", file=sys.stderr)
        return 1

    # Group app lines/functions by source file.
    lines_by_sf = defaultdict(set)
    for (sf, ln) in app_count:
        lines_by_sf[sf].add(ln)
    funcs_by_sf = defaultdict(dict)
    for (sf, name), ln in func_decl.items():
        funcs_by_sf[sf][name] = ln

    # Disjoint file sets are usually a normalization mismatch (absolute vs
    # repo-relative paths, a different --source-root), not a real 100% gap.
    baseline_sfs = {sf for sf, _ln in suite}
    if not (set(lines_by_sf) & baseline_sfs):
        print(f"warning: the app and the baseline have no source file in "
              f"common, so EVERY app line below is reported as a gap. This is "
              f"usually a path-normalization mismatch: symbolize both sides "
              f"with the same --source-root/--preset/--keep flags. App has "
              f"e.g. {sorted(lines_by_sf)[0]!r}; baseline has e.g. "
              f"{sorted(baseline_sfs)[0]!r}.", file=sys.stderr)

    total = covered = total_brf = total_brh = 0
    with open(args.out, "w") as out:
        for sf in sorted(set(lines_by_sf) | set(app_branches)):
            lines = lines_by_sf.get(sf, set())
            funcs = funcs_by_sf.get(sf, {})
            out.write(f"TN:{args.name}\n")
            out.write(f"SF:{sf}\n")
            ordered = sorted(funcs, key=lambda n: (funcs[n], n))

            def fn_covered(name):
                if func_lines is not None:
                    return any((sf, l) in suite for l in func_lines[(sf, name)])
                return (sf, funcs[name]) in suite

            for name in ordered:
                out.write(f"FN:{funcs[name]},{name}\n")
            fnh = 0
            for name in ordered:
                hit = 1 if fn_covered(name) else 0
                fnh += hit
                out.write(f"FNDA:{hit},{name}\n")
            if funcs:
                out.write(f"FNF:{len(funcs)}\n")
                out.write(f"FNH:{fnh}\n")
            # Branch outcomes the app took, marked hit iff the baseline took
            # them too -- the same rule as lines, so red is the gap here as
            # well. Only the .info app input carries BRDA records; they used
            # to be parsed away and dropped.
            base_br = suite_branches.get(sf, set())
            bd = {key: (taken if key in base_br else 0)
                  for key, taken in app_branches.get(sf, {}).items()}
            if bd:
                brf, brh = emit_branches(out, bd)
                total_brf += brf
                total_brh += brh
            lh = 0
            for ln in sorted(lines):
                if (sf, ln) in suite:
                    # Counts are floored at 1 when loaded, so a covered line
                    # can never be written DA:,0 -- which would render red (a
                    # gap) while LH counted it as covered.
                    out.write(f"DA:{ln},{app_count[(sf, ln)]}\n")
                    lh += 1
                else:
                    out.write(f"DA:{ln},0\n")                      # gap (red)
            out.write(f"LF:{len(lines)}\n")
            out.write(f"LH:{lh}\n")
            out.write("end_of_record\n")
            total += len(lines)
            covered += lh

    gap = total - covered
    pct = (100.0 * covered / total) if total else 0.0
    summary = (f"gap: app executes {total} baseline-scoped lines, {covered} "
               f"also covered by baseline ({pct:.1f}%); {gap} GAP lines (app "
               f"runs, baseline does not)")
    if total_brf:
        bgap = total_brf - total_brh
        summary += (f"; {total_brh}/{total_brf} branch outcomes also covered, "
                    f"{bgap} GAP outcomes")
    print(f"{summary} -> {args.out}", file=sys.stderr)

    if args.html:
        run_genhtml(args.out, args.html, args.source_root,
                    f"gap: HTML -> {args.html}/index.html (red = the gap)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
