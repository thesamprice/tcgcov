"""Merge many per-test LCOV .info files into one aggregate .info.

Merging is by SOURCE IDENTITY (source path + line) -- the same cpukit/bsps line
lives at different addresses in different test binaries, so address-based
merging would be wrong. Coverable vs covered are tracked separately so real
percentages survive: a line is covered in the aggregate if any input covers it;
coverable if any input lists it. Execution counts are SUMMED across tests.

Branch records merge the same way, keyed by (source file, line, block, branch)
-- the analogous source identity for a branch outcome. Counts are summed, and
the LCOV '-' (never evaluated) survives only if EVERY input says '-': as soon as
one test evaluated the branch, the aggregate knows the outcome count, so '-'
would understate it.
"""

import argparse
import glob
import sys
from collections import defaultdict

from .lcov import emit_branches

# Distinguishes "key not seen yet" from "seen, and it was '-'".
_UNSEEN = object()


def parse_info(path, coverable, line_hits, func_line, func_hits,
               branch_data=None):
    """Accumulate one .info. line_hits/func_hits SUM execution counts across
    tests (total executions for counts mode; number of covering tests for plain
    coverage). coverable is the union of all DA lines.

    branch_data (optional) is sf -> {(line, block, branch): taken}, where taken
    is None for a never-evaluated outcome ('-'); it is summed across inputs and
    stays None only while every input reported '-'."""
    cur_sf = None
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if raw.startswith("SF:"):
                cur_sf = raw[3:]
            elif raw == "end_of_record":
                cur_sf = None
            elif cur_sf is None:
                continue
            elif raw.startswith("DA:"):
                lno_s, _, hits_s = raw[3:].partition(",")
                try:
                    lno = int(lno_s)
                    hits = int(hits_s) if hits_s else 0
                except ValueError:
                    continue
                coverable[cur_sf].add(lno)
                if hits > 0:
                    lh = line_hits[cur_sf]
                    lh[lno] = lh.get(lno, 0) + hits
            elif raw.startswith("FN:"):
                lno_s, _, name = raw[3:].partition(",")
                try:
                    lno = int(lno_s)
                except ValueError:
                    continue
                if name:
                    cur = func_line[cur_sf].get(name)
                    if cur is None or lno < cur:
                        func_line[cur_sf][name] = lno
            elif raw.startswith("BRDA:") and branch_data is not None:
                parts = raw[5:].split(",")
                if len(parts) != 4:
                    continue
                try:
                    key = (int(parts[0]), int(parts[1]), int(parts[2]))
                except ValueError:
                    continue
                taken = None if parts[3].strip() == "-" else parts[3].strip()
                if taken is not None:
                    try:
                        taken = int(taken)
                    except ValueError:
                        continue
                bd = branch_data[cur_sf]
                cur = bd.get(key, _UNSEEN)
                if cur is _UNSEEN or cur is None:
                    bd[key] = taken
                elif taken is not None:
                    bd[key] = cur + taken
            elif raw.startswith("FNDA:"):
                hits_s, _, name = raw[5:].partition(",")
                try:
                    hits = int(hits_s)
                except ValueError:
                    continue
                if name and hits > 0:
                    fh = func_hits[cur_sf]
                    fh[name] = fh.get(name, 0) + hits


def add_arguments(parser):
    parser.add_argument("inputs", nargs="+",
                        help="per-test .info files (globs allowed)")
    parser.add_argument("--out", required=True, help="aggregate .info output")
    parser.add_argument("--name", default="aggregate",
                        help="aggregate test name (TN), default 'aggregate'")


def run(args):
    paths = []
    for pat in args.inputs:
        expanded = glob.glob(pat)
        paths.extend(expanded if expanded else [pat])
    if not paths:
        print("error: no input files", file=sys.stderr)
        return 1

    coverable = defaultdict(set)
    line_hits = defaultdict(dict)     # sf -> {line: summed count}
    func_line = defaultdict(dict)
    func_hits = defaultdict(dict)     # sf -> {name: summed count}
    branch_data = defaultdict(dict)   # sf -> {(line,block,branch): taken|None}
    parsed = 0
    for p in paths:
        try:
            parse_info(p, coverable, line_hits, func_line, func_hits,
                       branch_data)
        except OSError as e:
            print(f"warning: skipping {p}: {e}", file=sys.stderr)
        else:
            parsed += 1

    if not parsed:
        # Skipping every input used to leave an empty aggregate and exit 0,
        # i.e. a CI-green "0.0% of 0 lines". No input read is a hard error.
        print(f"error: none of the {len(paths)} input file(s) could be read; "
              f"refusing to write an empty aggregate to {args.out}",
              file=sys.stderr)
        return 1

    total_lf = total_lh = total_brf = total_brh = 0
    with open(args.out, "w") as out:
        for sf in sorted(set(coverable) | set(branch_data)):
            cab = coverable[sf]
            lh = line_hits.get(sf, {})
            funcs = func_line.get(sf, {})
            fh = func_hits.get(sf, {})
            out.write(f"TN:{args.name}\n")
            out.write(f"SF:{sf}\n")
            ordered = sorted(funcs, key=lambda n: (funcs[n], n))
            for fn in ordered:
                out.write(f"FN:{funcs[fn]},{fn}\n")
            for fn in ordered:
                out.write(f"FNDA:{fh.get(fn, 0)},{fn}\n")
            if funcs:
                out.write(f"FNF:{len(funcs)}\n")
                out.write(f"FNH:{sum(1 for fn in funcs if fh.get(fn, 0) > 0)}\n")
            bd = branch_data.get(sf)
            if bd:
                brf, brh = emit_branches(out, bd)
                total_brf += brf
                total_brh += brh
            for ln in sorted(cab):
                out.write(f"DA:{ln},{lh.get(ln, 0)}\n")
            out.write(f"LF:{len(cab)}\n")
            out.write(f"LH:{len(lh)}\n")
            out.write("end_of_record\n")
            total_lf += len(cab)
            total_lh += len(lh)

    pct = (100.0 * total_lh / total_lf) if total_lf else 0.0
    summary = (f"merged {len(paths)} files -> "
               f"{len(set(coverable) | set(branch_data))} source files, "
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
