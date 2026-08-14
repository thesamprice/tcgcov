"""Rebase a .cov window from runtime addresses to link addresses.

For code the guest relocated at load time -- kernel modules, and eventually
Tier-3/4 userspace objects -- the artifact holds runtime addresses the ELF's
DWARF knows nothing about.  Given the runtime base (from the guest sidecar,
e.g. /sys/module/<m>/sections/.text) this selects the records inside
[base, base+size) and writes a new .cov with each address shifted by
(to - base), so the existing symbolize/coverable pipeline runs unchanged
against the object's ELF.  For an ET_REL .ko, --to defaults to 0 and
symbolize wants --section .text so addr2line treats the results as section
offsets.

Edges are kept only when BOTH endpoints fall inside the window; the count of
dropped records and edges is always printed -- silent truncation reads as
"covered everything" when it did not.
"""

import argparse
import sys

from .format import read_all, write_cov, parse_header


def add_arguments(parser):
    parser.add_argument("--cov", required=True, help="input .cov")
    parser.add_argument("--base", required=True, type=lambda v: int(v, 0),
                        help="runtime base address of the window")
    parser.add_argument("--size", required=True, type=lambda v: int(v, 0),
                        help="window size in bytes")
    parser.add_argument("--to", type=lambda v: int(v, 0), default=0,
                        help="link-time base to rebase onto (default 0)")
    parser.add_argument("--out", required=True, help="output .cov")


def run(args):
    try:
        with open(args.cov, "rb") as f:
            hdr = parse_header(f.read(), args.cov)
        meta, addrs, counts, edges = read_all(args.cov)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    records = [(a, counts.get(a, 1) if counts else 1) for a in addrs]
    lo, hi = args.base, args.base + args.size
    delta = args.to - args.base

    kept = [(a + delta, c) for a, c in records if lo <= a < hi]
    kept_edges = [(s + delta, d + delta, c) for s, d, c in edges
                  if lo <= s < hi and lo <= d < hi] if edges else []

    meta = dict(meta)
    meta["rebased_from"] = "0x%x" % args.base
    meta["rebased_window"] = "0x%x" % args.size
    meta["rebased_to"] = "0x%x" % args.to
    write_cov(args.out, meta, kept, kept_edges, record_type=hdr["record_type"])

    print(f"{args.cov}: kept {len(kept)}/{len(records)} records, "
          f"{len(kept_edges)}/{len(edges) if edges else 0} edges in "
          f"[0x{lo:x}, 0x{hi:x}) -> {args.out} (delta {delta:+#x})",
          file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
