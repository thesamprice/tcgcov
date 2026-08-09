"""Convert symbolized tcgcov JSONL into a per-test LCOV .info file.

With --coverable, combines the coverable-line inventory with the covered lines
and emits DA:<line>,<count> for hit lines and DA:<line>,0 for coverable-but-not-
hit lines, so genhtml reports true percentages (covered / coverable). Without
it, covered-only (every covered line DA:,1).

With --branches (output of `tcgcov branches`), also emits branch records:

    BRDA:<line>,<block>,<branch>,<taken|->
    BRF:<branches found>
    BRH:<branches hit>

The '-' vs '0' distinction is load-bearing and genhtml renders them
differently: '-' means the branch was never EVALUATED (the code never ran), '0'
means it ran but that outcome never happened -- an untested else-path, which is
exactly what branch coverage exists to surface. Branch 0 of each block is the
taken outcome, branch 1 the fall-through.
"""

import argparse
import json
import sys
from collections import defaultdict


def load(path):
    """Parse symbolized JSONL.

    Returns (lines_by_file{set}, funcs_by_file{name:min_line}, test_id, arch,
    line_count{(sf,line):max_count}). line_count is the per-line execution count
    (max across the line's records); it is 1 for plain coverage files.
    """
    lines_by_file = defaultdict(set)
    funcs_by_file = defaultdict(dict)
    line_count = {}
    test_id = arch = ""
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            rec = json.loads(raw)
            sf = rec["file"]
            ln = int(rec["line"])
            fn = rec.get("function") or ""
            cnt = int(rec.get("count", 1))
            lines_by_file[sf].add(ln)
            k = (sf, ln)
            if cnt > line_count.get(k, 0):
                line_count[k] = cnt
            test_id = test_id or rec.get("test_id", "")
            arch = arch or rec.get("arch", "")
            if fn:
                cur = funcs_by_file[sf].get(fn)
                if cur is None or ln < cur:
                    funcs_by_file[sf][fn] = ln
    return lines_by_file, funcs_by_file, test_id, arch, line_count


_MISSING = object()


def load_branches(path):
    """Parse `tcgcov branches` JSONL -> {sf: {(line, block, branch): taken}}.

    `taken` is None when the branch was never evaluated (LCOV '-') and an
    integer otherwise. Branch 0 is the taken outcome, branch 1 the fall-through.
    Records for the same key from several inputs are summed, so a per-test run
    that saw a branch twice still reports one entry.
    """
    by_file = defaultdict(dict)
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            rec = json.loads(raw)
            sf = rec["file"]
            key_base = (int(rec["line"]), int(rec.get("block", 0)))
            evaluated = bool(rec.get("evaluated"))
            for idx, field in ((0, "taken"), (1, "nottaken")):
                key = key_base + (idx,)
                value = int(rec.get(field, 0)) if evaluated else None
                cur = by_file[sf].get(key, _MISSING)
                if cur is _MISSING or cur is None:
                    by_file[sf][key] = value
                elif value is not None:
                    by_file[sf][key] = cur + value
    return by_file


def emit_branches(out, branches):
    """Write the BRDA/BRF/BRH block for one source file; return (found, hit)."""
    found = hit = 0
    for key in sorted(branches):
        line, block, branch = key
        taken = branches[key]
        # '-' = never evaluated, '0' = evaluated but this outcome never taken.
        text = "-" if taken is None else str(taken)
        out.write(f"BRDA:{line},{block},{branch},{text}\n")
        found += 1
        if taken:
            hit += 1
    if found:
        out.write(f"BRF:{found}\n")
        out.write(f"BRH:{hit}\n")
    return found, hit


def add_arguments(parser):
    parser.add_argument("jsonl", help="covered .jsonl from `tcgcov symbolize`")
    parser.add_argument("--coverable", help="coverable .jsonl from "
                        "`tcgcov coverable` (enables real percentages)")
    parser.add_argument("--branches", help="branch .jsonl from "
                        "`tcgcov branches` (adds BRDA/BRF/BRH records)")
    parser.add_argument("--out", required=True, help="output .info file")
    parser.add_argument("--test-name", help="LCOV test name (TN); "
                        "default derived from test_id+arch")


def run(args):
    try:
        cov_lines, cov_funcs, test_id, arch, cov_count = load(args.jsonl)
        if args.coverable:
            cab_lines, cab_funcs, _, _, _ = load(args.coverable)
        else:
            cab_lines, cab_funcs = cov_lines, cov_funcs
        branches = load_branches(args.branches) if args.branches else {}
    except (OSError, ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    tn = args.test_name or "-".join(x for x in (test_id, arch) if x) or "tcgcov"

    # The universe of source files is the coverable set, plus any covered file
    # not present in coverable (shouldn't happen, but never drop a hit).
    all_files = set(cab_lines) | set(cov_lines) | set(branches)

    total_lf = total_lh = total_brf = total_brh = 0
    # Lines the coverable inventory contributes that are not already covered.
    # The union below has no floor: with an empty/mismatched --coverable file
    # every covered line becomes its own denominator and the report reads
    # 100.0%. Counting the surplus is what makes that detectable.
    coverable_surplus = 0
    with open(args.out, "w") as out:
        for sf in sorted(all_files):
            covered = cov_lines.get(sf, set())
            declared = cab_lines.get(sf, set())
            coverable = declared | covered  # never lose a hit
            coverable_surplus += len(declared - covered)
            # Functions: union; declaration line preferred from coverable.
            funcs = dict(cab_funcs.get(sf, {}))
            for fn, ln in cov_funcs.get(sf, {}).items():
                if fn not in funcs or ln < funcs[fn]:
                    funcs[fn] = ln
            covered_fn_lines = cov_funcs.get(sf, {})
            covered_fns = set(covered_fn_lines)

            out.write(f"TN:{tn}\n")
            out.write(f"SF:{sf}\n")
            ordered = sorted(funcs, key=lambda n: (funcs[n], n))
            for fn in ordered:
                out.write(f"FN:{funcs[fn]},{fn}\n")
            for fn in ordered:
                # Function hit count = the count at its (covered) declaration
                # line; an executed function is always at least 1.
                if fn in covered_fns:
                    fc = max(1, cov_count.get((sf, covered_fn_lines[fn]), 1))
                else:
                    fc = 0
                out.write(f"FNDA:{fc},{fn}\n")
            if funcs:
                out.write(f"FNF:{len(funcs)}\n")
                out.write(f"FNH:{len(covered_fns)}\n")
            if sf in branches:
                brf, brh = emit_branches(out, branches[sf])
                total_brf += brf
                total_brh += brh
            for ln in sorted(coverable):
                hits = cov_count.get((sf, ln), 0) if ln in covered else 0
                out.write(f"DA:{ln},{hits}\n")
            out.write(f"LF:{len(coverable)}\n")
            out.write(f"LH:{len(covered)}\n")
            out.write("end_of_record\n")
            total_lf += len(coverable)
            total_lh += len(covered)

    if args.coverable and not coverable_surplus:
        print(f"warning: {args.coverable} adds no lines beyond the covered "
              f"set, so the denominator is missing and every percentage below "
              f"is 100% by construction. Either the coverable inventory is "
              f"empty/was produced for a different binary, or (implausibly) "
              f"every coverable line really was executed. Re-run "
              f"`tcgcov coverable` and check it is non-empty.",
              file=sys.stderr)

    pct = (100.0 * total_lh / total_lf) if total_lf else 0.0
    summary = (f"{args.jsonl}: {len(all_files)} files, "
               f"{total_lh}/{total_lf} lines ({pct:.1f}%)")
    if total_brf:
        bpct = 100.0 * total_brh / total_brf
        summary += f", {total_brh}/{total_brf} branches ({bpct:.1f}%)"
    print(f"{summary} -> {args.out}", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
