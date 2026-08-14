"""Inspect a TCGCOV coverage artifact (header, metadata, addresses, counts,
edges, contexts).

Artifacts embed the absolute path of the ELF they were recorded against, so
that the host tools need no separate manifest. That is convenient locally and
awkward when attaching an artifact to a bug report, because it discloses the
filesystem layout of the machine that produced it. --scrub redacts those paths
for display, and --scrub-out writes a redacted copy that is still a valid
artifact.
"""

import argparse
import json
import os
import struct
import sys

from .format import (parse_header, unpack_records, unpack_edges,
                     unpack_ctx_records, unpack_ctx_edges, REC_TYPE,
                     HEADER_FMT, MAGIC, MAGIC_V2, FLAG_HAS_COUNTS,
                     FLAG_HAS_EDGES, FLAG_EDGE_COUNTS, FLAG_HAS_CTX,
                     CTX_UNAVAILABLE)

# Metadata keys whose value is a filesystem path. Everything else in the
# metadata is a number, a boolean, or a short free-form label.
_PATH_KEYS = ("elf",)


def _looks_like_a_path(value):
    """True for a string that discloses a filesystem location.

    A bare basename ('hello.exe') does not: it is what the scrub leaves
    behind, so treating it as a path would make scrubbing non-idempotent.
    """
    return isinstance(value, str) and (os.sep in value or value.startswith("~"))


def scrub_metadata(meta):
    """Return a copy of `meta` with filesystem paths reduced to basenames.

    The basename is kept rather than dropped because it identifies which test
    the artifact belongs to, which is usually the whole reason for sharing it,
    and a basename is not a disclosure. Free-form labels (test_id, bsp) are
    scrubbed only when they look like paths -- they are user-supplied and a
    caller may have put anything in them.

    A 'scrubbed' key is added so a reader can tell that the ELF path in this
    artifact is no longer the one it was recorded against. The host tools take
    --elf explicitly, so a scrubbed artifact remains fully analysable.
    """
    out = dict(meta)
    for key, value in meta.items():
        if key in _PATH_KEYS or _looks_like_a_path(value):
            if isinstance(value, str) and value:
                out[key] = os.path.basename(value.rstrip(os.sep))
    out["scrubbed"] = True
    return out


def write_scrubbed(src_path, dst_path):
    """Write `src_path` to `dst_path` with its metadata paths redacted.

    Only the metadata section changes. Because it changes LENGTH, the record
    and edge sections move, so the header offsets are recomputed rather than
    copied. The record and edge bytes themselves are passed through verbatim --
    they are addresses and counts, and contain nothing to redact.
    """
    with open(src_path, "rb") as f:
        data = f.read()
    hdr = parse_header(data, src_path)

    meta_raw = data[hdr["metadata_offset"]:
                    hdr["metadata_offset"] + hdr["metadata_size"]]
    meta = json.loads(meta_raw.decode("utf-8"))
    new_meta = json.dumps(scrub_metadata(meta), indent=2).encode("utf-8") + b"\n"

    records = data[hdr["records_offset"]:
                   hdr["records_offset"] + hdr["records_size"]]
    edges = data[hdr["edges_offset"]:hdr["edges_offset"] + hdr["edges_size"]] \
        if hdr["edges_size"] else b""

    hsize = struct.calcsize(HEADER_FMT)
    meta_off = hsize
    rec_off = meta_off + len(new_meta)
    edge_off = rec_off + len(records) if edges else 0

    header = struct.pack(
        HEADER_FMT, MAGIC_V2 if hdr["version"] >= 2 else MAGIC,
        hdr["version"], hdr["endian"], hsize,
        hdr["record_type"], hdr["flags"], hdr["record_count"],
        meta_off, len(new_meta), rec_off, len(records),
        hdr["edge_count"], edge_off, len(edges))

    tmp = dst_path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(header + new_meta + records + edges)
    os.replace(tmp, dst_path)


def load(path):
    with open(path, "rb") as f:
        data = f.read()

    # parse_header validates size, magic, version, endianness, every section's
    # bounds and the record strides, and raises ValueError on any of them.
    hdr = parse_header(data, path)
    flags = hdr["flags"]
    meta_raw = data[hdr["metadata_offset"]:
                    hdr["metadata_offset"] + hdr["metadata_size"]]
    try:
        meta = json.loads(meta_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        meta = {"_parse_error": str(e), "_raw": meta_raw.decode("latin1")}

    has_counts = bool(flags & FLAG_HAS_COUNTS)
    has_ctx = bool(flags & FLAG_HAS_CTX)
    ctx_summary = None
    if has_ctx:
        # Aggregate for the address/count displays below, but keep a
        # per-context summary: (ctx, records, total execs, edges).
        records = unpack_ctx_records(data, hdr["records_offset"],
                                     hdr["records_size"], has_counts)
        ctx_edges = []
        if flags & FLAG_HAS_EDGES and hdr["edges_size"]:
            ctx_edges = unpack_ctx_edges(data, hdr["edges_offset"],
                                         hdr["edges_size"],
                                         bool(flags & FLAG_EDGE_COUNTS))
        summary = {}
        count_map = {} if has_counts else None
        addr_order = {}
        for c, a, cnt in records:
            row = summary.setdefault(c, [0, 0, 0])
            row[0] += 1
            row[1] += cnt or 0
            addr_order.setdefault(a, True)
            if count_map is not None:
                count_map[a] = count_map.get(a, 0) + cnt
        merged = {}
        for c, s, d, cnt in ctx_edges:
            summary.setdefault(c, [0, 0, 0])[2] += 1
            merged[(s, d)] = merged.get((s, d), 0) + cnt
        addrs = list(addr_order)
        counts = [count_map[a] for a in addrs] if count_map is not None \
            else None
        edges = [(s, d, c) for (s, d), c in sorted(merged.items())]
        ctx_summary = sorted(summary.items())
    else:
        addrs, count_map = unpack_records(data, hdr["records_offset"],
                                          hdr["records_size"], has_counts)
        counts = [count_map[a] for a in addrs] if count_map is not None \
            else None

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
        "has_ctx": has_ctx,
        "record_count": hdr["record_count"],
        "metadata_size": hdr["metadata_size"],
        "records_size": hdr["records_size"],
        "edge_count": hdr["edge_count"], "edges_size": hdr["edges_size"],
    }
    return header, meta, addrs, counts, edges, ctx_summary


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
    parser.add_argument("--scrub", action="store_true",
                        help="redact filesystem paths in the printed metadata, "
                             "reducing them to a basename; use when pasting "
                             "output into a bug report")
    parser.add_argument("--scrub-out", metavar="FILE",
                        help="write a redacted COPY of the artifact to FILE, "
                             "still a valid artifact but with the recording "
                             "machine's paths removed; analysing it needs the "
                             "ELF given explicitly with --elf")


def run(args):
    if args.scrub_out:
        try:
            write_scrubbed(args.file, args.scrub_out)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"{args.file}: scrubbed copy -> {args.scrub_out}",
              file=sys.stderr)

    try:
        header, meta, addrs, counts, edges, ctx_summary = load(args.file)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.scrub:
        meta = scrub_metadata(meta)

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

    if ctx_summary is not None:
        print("== contexts ==")
        print(f"  count: {len(ctx_summary)}")
        print("  (addresses/counts/edges below are aggregated across "
              "contexts; use `tcgcov contexts` to slice)")
        shown = ctx_summary if args.all else ctx_summary[:args.n]
        for ctx, (nrec, total, nedges) in shown:
            name = "<unavailable>" if ctx == CTX_UNAVAILABLE else f"0x{ctx:x}"
            print(f"  ctx {name}: {nrec} records, {total} execs, "
                  f"{nedges} edges")
        if not args.all and len(ctx_summary) > args.n:
            print(f"  ... ({len(ctx_summary) - args.n} more) ...")

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

    if not header["has_ctx"] and header["record_count"] != len(addrs):
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
        if not header["has_ctx"] and header["edge_count"] != len(edges):
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
