"""Inspect an TCGCOV1 coverage artifact (header, metadata, addresses, counts,
edges)."""

import argparse
import json
import sys

from .format import (parse_header, unpack_records, unpack_edges, REC_TYPE,
                     FLAG_HAS_COUNTS, FLAG_HAS_EDGES, FLAG_EDGE_COUNTS,
                     HEADER_SIZE_V1)


def load(path):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE_V1:
        raise ValueError(f"file too small ({len(data)} bytes) to be tcgcov")

    hdr = parse_header(data, path)
    flags = hdr["flags"]
    meta_raw = data[hdr["metadata_offset"]:
                    hdr["metadata_offset"] + hdr["metadata_size"]]
    try:
        meta = json.loads(meta_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        meta = {"_parse_error": str(e), "_raw": meta_raw.decode("latin1")}

    has_counts = bool(flags & FLAG_HAS_COUNTS)
    addrs, count_map = unpack_records(data, hdr["records_offset"],
                                      hdr["records_size"], has_counts)
    counts = [count_map[a] for a in addrs] if count_map is not None else None

    edges = []
    if flags & FLAG_HAS_EDGES and hdr["edges_size"]:
        edges = unpack_edges(data, hdr["edges_offset"], hdr["edges_size"],
                             bool(flags & FLAG_EDGE_COUNTS))

    header = {
        "version": hdr["version"], "endian": hdr["endian"],
        "header_size": hdr["header_size"],
        "record_type": hdr["record_type"],
        "record_type_name": REC_TYPE.get(hdr["record_type"], "?"),
        "flags": flags, "has_counts": has_counts,
        "has_edges": bool(flags & FLAG_HAS_EDGES),
        "edge_counts": bool(flags & FLAG_EDGE_COUNTS),
        "record_count": hdr["record_count"],
        "metadata_size": hdr["metadata_size"],
        "records_size": hdr["records_size"],
        "edge_count": hdr["edge_count"], "edges_size": hdr["edges_size"],
    }
    return header, meta, addrs, counts, edges


def add_arguments(parser):
    parser.add_argument("file")
    parser.add_argument("--all", action="store_true",
                        help="print every address")
    parser.add_argument("-n", type=int, default=10,
                        help="head/tail address count (default 10)")
    parser.add_argument("--metadata-only", action="store_true",
                        help="print only the embedded metadata, as JSON")
    parser.add_argument("--key", metavar="NAME",
                        help="print just this metadata value, unquoted, for "
                             "shell use (implies --metadata-only); exits 1 if "
                             "the key is absent")


def run(args):
    try:
        header, meta, addrs, counts, edges = load(args.file)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Scripted callers read one field (the ELF path, the target name) out of a
    # .cov to drive the rest of the pipeline; keep that output bare so it can be
    # captured directly in a shell substitution.
    if args.key:
        if args.key not in meta:
            print(f"error: no metadata key '{args.key}' in {args.file}",
                  file=sys.stderr)
            return 1
        value = meta[args.key]
        print(value if isinstance(value, str) else json.dumps(value))
        return 0

    if args.metadata_only:
        print(json.dumps(meta, indent=2))
        return 0

    print("== header ==")
    for k, v in header.items():
        print(f"  {k}: {v}")

    print("== metadata ==")
    print(json.dumps(meta, indent=2))

    print("== addresses ==")
    print(f"  count: {len(addrs)}")
    if addrs:
        print(f"  min: 0x{min(addrs):x}")
        print(f"  max: 0x{max(addrs):x}")
    if counts is not None:
        print(f"  counts: present (max={max(counts) if counts else 0}, "
              f"total={sum(counts)})")
        hottest = sorted(range(len(addrs)), key=lambda i: counts[i],
                         reverse=True)[:args.n]
        print("  hottest:")
        for i in hottest:
            print(f"    0x{addrs[i]:x}  count={counts[i]}")

    if header["record_count"] != len(addrs):
        print(f"  WARNING: header record_count={header['record_count']} "
              f"!= decoded {len(addrs)}")

    def fmt(i):
        return f"  0x{addrs[i]:x}" + (f"  count={counts[i]}" if counts else "")

    idxs = range(len(addrs))
    if args.all:
        for i in idxs:
            print(fmt(i))
    elif addrs:
        n = args.n
        for i in list(idxs)[:n]:
            print(fmt(i))
        if len(addrs) > 2 * n:
            print(f"  ... ({len(addrs) - 2 * n} more) ...")
            for i in list(idxs)[-n:]:
                print(fmt(i))
        elif len(addrs) > n:
            for i in list(idxs)[n:]:
                print(fmt(i))

    if header["has_edges"]:
        print("== edges ==")
        print(f"  count: {len(edges)}")
        if header["edge_count"] != len(edges):
            print(f"  WARNING: header edge_count={header['edge_count']} "
                  f"!= decoded {len(edges)}")
        shown = edges if args.all else edges[:args.n]
        for src, dst, cnt in shown:
            suffix = f"  count={cnt}" if header["edge_counts"] else ""
            print(f"  0x{src:x} -> 0x{dst:x}{suffix}")
        if not args.all and len(edges) > args.n:
            print(f"  ... ({len(edges) - args.n} more) ...")

    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
