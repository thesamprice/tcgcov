"""Restrict an aggregate LCOV .info to the symbols present in a target ELF.

Drops coverage for any source line / function that is not part of the target
binary, keeping the suite's covered counts and denominator for what remains
(filter-only: the result never adds target lines the suite never had). A common
use is qualification -- point --elf at a deliverable binary to see how well the
test campaign covered just the code that ships.

Membership oracle: the target's coverable inventory (same `(file, line)`
normalization as the aggregate), built via objdump+addr2line like
`tcgcov coverable`. Build it with the source root used to build the target so
`contrib/` paths are preserved.
"""

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict

from .symbolize import iter_covered_lines
from .coverable import disassemble_addresses
from .lcov import emit_branches
from .merge import parse_info
from .cliargs import add_symbolize_args
from .paths import path_options


def load_target_inventory(args):
    """Return (keep_lines{(sf,line)}, keep_funcs{(sf,function)}) for the target.

    From a precomputed --coverable JSONL, or built from --elf via objdump +
    addr2line using the same normalization as the aggregate.
    """
    keep_lines = set()
    keep_funcs = set()

    if args.coverable:
        with open(args.coverable) as f:
            for lineno, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                    sf = rec["file"]
                    line = int(rec["line"])
                except (ValueError, KeyError, TypeError) as e:
                    # A truncated/foreign JSONL used to abort with a bare
                    # KeyError traceback, or a JSONDecodeError naming no file.
                    raise ValueError(f"{args.coverable}:{lineno}: not a "
                                     f"coverable record ({e})")
                keep_lines.add((sf, line))
                fn = rec.get("function")
                if fn:
                    keep_funcs.add((sf, fn))
        return keep_lines, keep_funcs

    objdump = args.objdump or (args.toolchain_prefix + "objdump")
    addr2line = args.addr2line or (args.toolchain_prefix + "addr2line")
    # disassemble_addresses returns (addresses, raw text); the text is only
    # needed to tell an empty binary from an unparsable disassembly.
    addrs, text = disassemble_addresses(objdump, args.elf)
    if not addrs:
        if text.strip():
            raise RuntimeError(
                f"{args.elf}: {objdump} produced {len(text.splitlines())} "
                f"lines of output but no instruction addresses were parsed "
                f"from it -- unrecognized disassembly layout")
        raise RuntimeError(f"{args.elf}: {objdump} disassembled no "
                           f"executable code at all")
    for norm, line, func, _depth, _addr in iter_covered_lines(
            addr2line, args.elf, addrs, path_options(args)):
        keep_lines.add((norm, line))
        keep_funcs.add((norm, func))
    return keep_lines, keep_funcs


def run_genhtml(info, html_dir, source_root, ok_message):
    """Run genhtml, reporting rather than raising when it cannot be run.

    genhtml is optional (lcov is not installed everywhere): letting the
    FileNotFoundError escape turned a written, valid .info into a traceback and
    a non-zero exit, AFTER the real output had already been produced. Shared
    with `gap`, which offers the same --html option.
    """
    cwd = source_root or "/"
    try:
        rc = subprocess.run(
            ["genhtml", os.path.abspath(info),
             "--output-directory", os.path.abspath(html_dir),
             "--quiet", "--ignore-errors", "source"],
            cwd=cwd).returncode
    except OSError as e:
        print(f"warning: --html requested but genhtml could not be run "
              f"({e}); the .info was written to {info}", file=sys.stderr)
        return
    if rc != 0:
        print(f"warning: genhtml exited {rc}", file=sys.stderr)
    else:
        print(ok_message, file=sys.stderr)


def add_arguments(parser):
    parser.add_argument("--aggregate", required=True,
                        help="aggregate LCOV .info to restrict")
    parser.add_argument("--elf", help="target ELF (its symbols define what is "
                        "kept); or use --coverable")
    parser.add_argument("--coverable",
                        help="precomputed target coverable JSONL "
                             "(skips objdump/addr2line)")
    add_symbolize_args(parser)
    parser.add_argument("--objdump", help="explicit objdump path")
    parser.add_argument("--name", default="restricted",
                        help="LCOV test name (TN), default 'restricted'")
    parser.add_argument("--html", metavar="DIR",
                        help="also run genhtml into DIR")
    parser.add_argument("--out", required=True, help="output .info file")


def run(args):
    if not args.elf and not args.coverable:
        print("error: --elf or --coverable is required", file=sys.stderr)
        return 2

    try:
        keep_lines, keep_funcs = load_target_inventory(args)
    except (OSError, RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not keep_lines:
        # Everything would be filtered out, and the resulting empty .info
        # reads as a successful "0 covered of 0 lines" run.
        src = args.coverable or args.elf
        print(f"error: {src}: the target inventory has no source lines, so "
              f"the restricted report would be empty. Check the target was "
              f"built with debug info and that the inventory is non-empty.",
              file=sys.stderr)
        return 1

    coverable = defaultdict(set)
    line_hits = defaultdict(dict)
    func_line = defaultdict(dict)
    func_hits = defaultdict(dict)
    branch_data = defaultdict(dict)
    try:
        parse_info(args.aggregate, coverable, line_hits, func_line, func_hits,
                   branch_data)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    in_lf = sum(len(v) for v in coverable.values())
    if not in_lf:
        print(f"error: {args.aggregate}: no DA records -- the aggregate is "
              f"empty, so restricting it can only produce an empty report. "
              f"Check the aggregate was written by `tcgcov merge`.",
              file=sys.stderr)
        return 1

    # Filter first, write second: an empty result must not leave a plausible
    # 0-line .info behind for genhtml (or a reader) to call a clean run.
    kept = []
    for sf in sorted(coverable):
        cab = {ln for ln in coverable[sf] if (sf, ln) in keep_lines}
        if cab:
            kept.append((sf, cab))
    if not kept:
        print(f"error: none of the {in_lf} aggregate line(s) are in the "
              f"target inventory, so the restricted report would be empty. "
              f"Either the campaign never touched this binary's code, or -- "
              f"far more likely -- the two sides were normalized differently "
              f"(same --source-root/--preset/--keep flags on both?). "
              f"Refusing to write an empty report to {args.out}.",
              file=sys.stderr)
        return 1

    out_lf = out_lh = out_brf = out_brh = 0
    with open(args.out, "w") as out:
        for sf, cab in kept:
            lh = line_hits.get(sf, {})
            funcs = {fn: ln for fn, ln in func_line.get(sf, {}).items()
                     if (sf, fn) in keep_funcs}
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
            # Branch records follow the same filter as lines: a branch on a
            # line the target ELF does not contain is not the target's branch.
            bd = {k: v for k, v in branch_data.get(sf, {}).items()
                  if k[0] in cab}
            if bd:
                brf, brh = emit_branches(out, bd)
                out_brf += brf
                out_brh += brh
            covered = 0
            for ln in sorted(cab):
                hits = lh.get(ln, 0)
                if hits > 0:
                    covered += 1
                out.write(f"DA:{ln},{hits}\n")
            out.write(f"LF:{len(cab)}\n")
            out.write(f"LH:{covered}\n")
            out.write("end_of_record\n")
            out_lf += len(cab)
            out_lh += covered

    pct = (100.0 * out_lh / out_lf) if out_lf else 0.0
    summary = (f"restrict: {in_lf} -> {out_lf} coverable lines kept, "
               f"{out_lh} covered ({pct:.1f}%)")
    if out_brf:
        bpct = 100.0 * out_brh / out_brf
        summary += f", {out_brh}/{out_brf} branches ({bpct:.1f}%)"
    print(f"{summary} -> {args.out}", file=sys.stderr)

    if args.html:
        run_genhtml(args.out, args.html, args.source_root,
                    f"restrict: HTML -> {args.html}/index.html")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
