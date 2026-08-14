"""List, attribute and extract the contexts of a TCGCOV2 artifact.

A TCGCOV2 artifact records which guest address-space context (MMU PID/ASID)
executed each address.  This subcommand answers the three questions that
follow:

* what contexts are in here, and how much did each execute (`contexts FILE`);
* which context ran a given binary (`--elf`): each context's addresses are
  scored against the ELF's executable ranges, because the guest's hardware
  context IDs are not process IDs and the join has to come from somewhere --
  a binary linked at a distinctive base is identified by where its context
  executed;
* give me one context as a plain TCGCOV1 file (`--extract CTX -o FILE`), so
  the entire existing pipeline (symbolize, coverable, branches, lcov) runs
  on a single process's coverage unchanged.
"""

import argparse
import sys

from .elfinfo import elf_text_info, in_ranges
from .format import read_full, write_cov, FLAG_HAS_CTX, CTX_UNAVAILABLE


def add_arguments(parser):
    parser.add_argument("cov", help="input .cov (TCGCOV2 with context records)")
    parser.add_argument("--elf", metavar="FILE",
                        help="score each context's addresses against this "
                             "ELF's executable ranges, to identify which "
                             "context ran it")
    parser.add_argument("--extract", metavar="CTX", type=lambda v: int(v, 0),
                        help="write this context's records as a TCGCOV1 "
                             "artifact (requires -o)")
    parser.add_argument("-o", "--out", metavar="FILE",
                        help="output path for --extract")


def _ctx_name(ctx):
    return "<unavailable>" if ctx == CTX_UNAVAILABLE else f"0x{ctx:x}"


def run(args):
    if (args.extract is None) != (args.out is None):
        print("error: --extract and -o/--out go together", file=sys.stderr)
        return 2

    try:
        meta, hdr, records, edges = read_full(args.cov)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if not hdr["flags"] & FLAG_HAS_CTX:
        print(f"error: {args.cov} has no context records (not a "
              f"TCGCOV2/HAS_CTX artifact); there is nothing to list or "
              f"extract", file=sys.stderr)
        return 1

    if args.extract is not None:
        kept = [(a, c or 1) for ctx, a, c in records if ctx == args.extract]
        kept_edges = [(s, d, c) for ctx, s, d, c in edges
                      if ctx == args.extract]
        if not kept:
            known = sorted({r[0] for r in records})
            print(f"error: context {_ctx_name(args.extract)} has no records "
                  f"in {args.cov}; contexts present: "
                  f"{', '.join(_ctx_name(c) for c in known)}",
                  file=sys.stderr)
            return 1
        out_meta = dict(meta)
        out_meta["extracted_ctx"] = "0x%x" % args.extract
        write_cov(args.out, out_meta, kept, kept_edges,
                  record_type=hdr["record_type"])
        print(f"{args.cov}: context {_ctx_name(args.extract)} -> {args.out} "
              f"({len(kept)} records, {len(kept_edges)} edges)",
              file=sys.stderr)
        return 0

    ranges = None
    if args.elf:
        ranges, _dwarf = elf_text_info(args.elf)
        if ranges is None:
            print(f"error: cannot read ELF ranges from {args.elf}",
                  file=sys.stderr)
            return 1

    entries = meta.get("contexts", {})
    summary = {}
    for ctx, a, c in records:
        row = summary.setdefault(ctx, [0, 0, 0])
        row[0] += 1
        row[1] += c or 0
        if ranges is not None and in_ranges(a, ranges):
            row[2] += 1

    print(f"{args.cov}: {len(summary)} contexts, "
          f"{meta.get('ctx_switches', '?')} switches recorded")
    order = sorted(summary.items(),
                   key=lambda kv: (-kv[1][2], -kv[1][1]) if ranges is not None
                   else (-kv[1][1],))
    for ctx, (nrec, execs, hits) in order:
        line = (f"  ctx {_ctx_name(ctx)}: {nrec} records, {execs} execs, "
                f"{entries.get(str(ctx), {}).get('entries', '?')} entries")
        if ranges is not None:
            line += f", {hits}/{nrec} addrs in {args.elf}"
        print(line)
    if ranges is not None and order and order[0][1][2] > 0:
        best = order[0]
        print(f"best match for {args.elf}: ctx {_ctx_name(best[0])} "
              f"({best[1][2]}/{best[1][0]} addrs in range)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
