"""TCGCOV1/TCGCOV2 binary artifact format: constants and reader.

The on-disk layout (all little-endian):

    struct tcgcov_header {          # 88 bytes
        char     magic[8];          # "TCGCOV1\0" (the version field is the
                                    # format signal; a legacy "TCGCOV2\0"
                                    # magic is accepted, never written)
        uint16_t version;           # 1, or 2 when context records may appear
        uint16_t endian;            # 1 = little, 2 = big
        uint32_t header_size;
        uint32_t record_type;       # 1=TB_ADDR, 2=INSN_ADDR, 3=EDGE
        uint32_t flags;             # bit0 HAS_COUNTS, bit1 HAS_EDGES,
                                    # bit2 EDGE_COUNTS, bit3 HAS_CTX (v2)
        uint64_t record_count;
        uint64_t metadata_offset;
        uint64_t metadata_size;
        uint64_t records_offset;
        uint64_t records_size;
        uint64_t edge_count;
        uint64_t edges_offset;
        uint64_t edges_size;
    };
    <UTF-8 JSON metadata>
    <address records>               # 8-byte addr, or 16-byte {addr,count} if HAS_COUNTS
    <edge records>                  # 16-byte {src,dst}, or 24-byte {src,dst,count}
                                    # if EDGE_COUNTS; sorted by (src,dst)

TCGCOV2 adds one thing: an address-space context ID on every record. With
HAS_CTX set, every address record is prefixed with a uint64 ctx (so 16 or
24 bytes) and every edge record likewise (24 or 32 bytes); records sort by
(ctx, addr) and edges by (ctx, src, dst). Context 2**64-1 means "the
producer could not learn the context" (QEMU_PLUGIN_CTX_UNAVAILABLE). The
metadata may carry a "contexts" object mapping decimal ctx IDs to facts the
producer knew about them (currently {"entries": times-switched-into}).
HAS_CTX is only legal in a TCGCOV2 file; everything else is unchanged, and
a v2 file without HAS_CTX is byte-for-byte a v1 file with a new magic.

Edge records are what makes BRANCH coverage possible. `src` is the vaddr of the
LAST INSTRUCTION of the source translation block, not its first: on delay-slot
architectures (MicroBlaze, MIPS, SPARC) the branch is not the last instruction
of the block, so recording the last instruction is the only way the host side
can tell which block the transfer left from.

Every file whose magic is "TCGCOV1\\0" has an 88-byte header containing the edge
fields (FORMAT.md section 7): the magic changed in the same release that added
them, so a short header is a corrupt file, not an old one.
"""

import json
import struct

MAGIC = b"TCGCOV1\0"
# One writer briefly emitted a distinct magic for version-2 files
# (2026-08-14, same-day artifacts only). The version field was always the
# real signal; this magic is accepted on read and never written.
MAGIC_V2_LEGACY = b"TCGCOV2\0"
MAGIC_V2 = MAGIC_V2_LEGACY          # backwards-compatible alias
HEADER_FMT = "<8sHHIIIQQQQQQQQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)          # 88

# Address-record and edge-record strides, selected by the flags:
# keyed on (has_counts, has_ctx). records_size and edges_size must be whole
# multiples of these.
REC_STRIDE = {False: 8, True: 16}
EDGE_STRIDE = {False: 16, True: 24}

FLAG_HAS_COUNTS = 0x1
FLAG_HAS_EDGES = 0x2
FLAG_EDGE_COUNTS = 0x4
FLAG_HAS_CTX = 0x8

# The producer's "no context available" marker (QEMU_PLUGIN_CTX_UNAVAILABLE).
CTX_UNAVAILABLE = 2**64 - 1


def _rec_stride(has_counts, has_ctx):
    return REC_STRIDE[bool(has_counts)] + (8 if has_ctx else 0)


def _edge_stride(has_counts, has_ctx):
    return EDGE_STRIDE[bool(has_counts)] + (8 if has_ctx else 0)

REC_TYPE = {1: "TB_ADDR", 2: "INSN_ADDR", 3: "EDGE"}

HEADER_FIELDS = (
    "magic", "version", "endian", "header_size", "record_type", "flags",
    "record_count", "metadata_offset", "metadata_size", "records_offset",
    "records_size", "edge_count", "edges_offset", "edges_size",
)


def parse_header(data, path="<data>"):
    """Return the validated header as a dict, or raise ValueError.

    Everything the format guarantees is checked HERE, up front, because the
    only alternative is a struct.error thrown from somewhere deep in the
    unpackers -- and struct.error is not a ValueError, so it escapes the
    (OSError, ValueError) handlers every caller uses and surfaces as an
    uncaught traceback. Checked, in FORMAT.md section 7 order:

      * magic, endian (1 or 2), version (1), header_size (>= 88);
      * every (offset, size) section lies inside the file and after the header;
      * records_size / edges_size are whole multiples of their record stride.

    After this returns, the unpackers below cannot read out of bounds.
    """
    if len(data) < 8 or data[:8] not in (MAGIC, MAGIC_V2_LEGACY):
        raise ValueError(f"{path}: not a TCGCOV file (bad magic)")
    if len(data) < HEADER_SIZE:
        raise ValueError(f"{path}: truncated TCGCOV header: {len(data)} "
                         f"bytes, need {HEADER_SIZE}")

    version, endian = struct.unpack_from("<HH", data, 8)
    if endian == 2:
        raise ValueError(f"{path}: big-endian artifacts are not supported by "
                         f"this reader (endian=2); every field would have to "
                         f"be byte-swapped and the writer only emits endian=1")
    if endian != 1:
        raise ValueError(f"{path}: bad endian field {endian} "
                         f"(expected 1=little or 2=big)")
    if version not in (1, 2):
        raise ValueError(f"{path}: unsupported format version {version} "
                         f"(this reader knows versions 1 and 2)")
    if data[:8] == MAGIC_V2_LEGACY and version != 2:
        raise ValueError(f"{path}: legacy TCGCOV2 magic with version "
                         f"{version}; that writer only ever emitted "
                         f"version 2, so this header is corrupt or forged")

    hdr = dict(zip(HEADER_FIELDS, struct.unpack(HEADER_FMT,
                                                data[:HEADER_SIZE])))
    declared = hdr["header_size"]
    if declared < HEADER_SIZE:
        raise ValueError(f"{path}: header_size {declared} is smaller than the "
                         f"{HEADER_SIZE}-byte TCGCOV1 header")

    size = len(data)
    for name in ("metadata", "records", "edges"):
        off, sz = hdr[name + "_offset"], hdr[name + "_size"]
        if not sz:
            continue                       # absent section; offset is unused
        if off < declared:
            raise ValueError(f"{path}: {name}_offset {off} overlaps the "
                             f"{declared}-byte header")
        if off > size or sz > size - off:
            raise ValueError(f"{path}: {name} section [{off}, {off + sz}) "
                             f"runs past the end of the {size}-byte file")

    flags = hdr["flags"]
    has_ctx = bool(flags & FLAG_HAS_CTX)
    if has_ctx and version < 2:
        raise ValueError(f"{path}: HAS_CTX flag set in a TCGCOV1 file; "
                         f"context records exist only from TCGCOV2 on")
    stride = _rec_stride(flags & FLAG_HAS_COUNTS, has_ctx)
    if hdr["records_size"] % stride:
        raise ValueError(f"{path}: records_size {hdr['records_size']} is not "
                         f"a multiple of the {stride}-byte record stride")
    if flags & FLAG_HAS_EDGES:
        stride = _edge_stride(flags & FLAG_EDGE_COUNTS, has_ctx)
        if hdr["edges_size"] % stride:
            raise ValueError(f"{path}: edges_size {hdr['edges_size']} is not "
                             f"a multiple of the {stride}-byte edge stride")
    return hdr


def unpack_records(data, off, size, has_counts):
    """Decode the address record array -> ([addr], {addr: count} or None).

    Safe to call only on a header parse_header() has already validated: the
    bounds and stride checks there are what keep struct.unpack_from from
    raising struct.error, which no caller catches.
    """
    if has_counts:
        n = size // REC_STRIDE[True]
        flat = struct.unpack_from("<%dQ" % (2 * n), data, off) if n else ()
        return list(flat[0::2]), dict(zip(flat[0::2], flat[1::2]))
    n = size // REC_STRIDE[False]
    addrs = list(struct.unpack_from("<%dQ" % n, data, off)) if n else []
    return addrs, None


def unpack_edges(data, off, size, has_counts):
    """Decode the edge array -> [(src, dst, count)].

    Without EDGE_COUNTS the plugin only records that an edge was taken; count is
    reported as 1 so callers do not have to special-case the two modes.
    """
    n = size // EDGE_STRIDE[bool(has_counts)]
    if not n:
        return []
    words = 3 if has_counts else 2
    flat = struct.unpack_from("<%dQ" % (words * n), data, off)
    if has_counts:
        return list(zip(flat[0::3], flat[1::3], flat[2::3]))
    return [(s, d, 1) for s, d in zip(flat[0::2], flat[1::2])]


def unpack_ctx_records(data, off, size, has_counts):
    """Decode a TCGCOV2 context record array -> [(ctx, addr, count)].

    Without HAS_COUNTS the count is reported as None. Bounds are guaranteed
    by parse_header, as with unpack_records.
    """
    words = 3 if has_counts else 2
    n = size // _rec_stride(has_counts, True)
    if not n:
        return []
    flat = struct.unpack_from("<%dQ" % (words * n), data, off)
    if has_counts:
        return list(zip(flat[0::3], flat[1::3], flat[2::3]))
    return [(c, a, None) for c, a in zip(flat[0::2], flat[1::2])]


def unpack_ctx_edges(data, off, size, has_counts):
    """Decode a TCGCOV2 context edge array -> [(ctx, src, dst, count)].

    Without EDGE_COUNTS the count is reported as 1, mirroring unpack_edges.
    """
    words = 4 if has_counts else 3
    n = size // _edge_stride(has_counts, True)
    if not n:
        return []
    flat = struct.unpack_from("<%dQ" % (words * n), data, off)
    if has_counts:
        return list(zip(flat[0::4], flat[1::4], flat[2::4], flat[3::4]))
    return [(c, s, d, 1) for c, s, d in
            zip(flat[0::3], flat[1::3], flat[2::3])]


def read_full(path):
    """Return (metadata, header, records, edges) with contexts preserved.

    records is [(ctx, addr, count)] and edges [(ctx, src, dst, count)]. For a
    file without context records (TCGCOV1, or v2 without HAS_CTX) every ctx is
    None; count is None for count-less address records. This is the one reader
    that exposes the v2 context axis raw; read_all() collapses it.
    """
    with open(path, "rb") as f:
        data = f.read()
    hdr = parse_header(data, path)
    flags = hdr["flags"]
    meta_off, meta_size = hdr["metadata_offset"], hdr["metadata_size"]
    meta = json.loads(data[meta_off:meta_off + meta_size].decode("utf-8"))

    has_counts = bool(flags & FLAG_HAS_COUNTS)
    if flags & FLAG_HAS_CTX:
        records = unpack_ctx_records(data, hdr["records_offset"],
                                     hdr["records_size"], has_counts)
        edges = []
        if flags & FLAG_HAS_EDGES and hdr["edges_size"]:
            edges = unpack_ctx_edges(data, hdr["edges_offset"],
                                     hdr["edges_size"],
                                     bool(flags & FLAG_EDGE_COUNTS))
        return meta, hdr, records, edges

    addrs, counts = unpack_records(data, hdr["records_offset"],
                                   hdr["records_size"], has_counts)
    records = [(None, a, counts[a] if counts else None) for a in addrs]
    edges = []
    if flags & FLAG_HAS_EDGES and hdr["edges_size"]:
        edges = [(None, s, d, c) for s, d, c in
                 unpack_edges(data, hdr["edges_offset"], hdr["edges_size"],
                              bool(flags & FLAG_EDGE_COUNTS))]
    return meta, hdr, records, edges


def read_all(path, ctx=None):
    """Return (metadata, [addresses], counts, edges) from a TCGCOV file.

    counts is None unless the file was written in counts mode (FLAG_HAS_COUNTS).
    edges is a list of (src, dst, count) triples, empty when the artifact has no
    FLAG_HAS_EDGES section.

    For a TCGCOV2 file with context records, the context axis is collapsed so
    every existing consumer keeps working: with ctx=None counts are summed
    across all contexts (the same address executed in two processes appears
    once, with the total); with ctx=<int> only that context's records and
    edges are returned. Passing ctx on a file without context records is an
    error -- there is nothing to select on, and silently returning everything
    would misattribute coverage.
    """
    meta, hdr, records, edges = read_full(path)
    flags = hdr["flags"]
    has_ctx = bool(flags & FLAG_HAS_CTX)
    if ctx is not None and not has_ctx:
        raise ValueError(f"{path}: context {ctx:#x} requested but the file "
                         f"has no context records (not a TCGCOV2/HAS_CTX "
                         f"artifact)")

    has_counts = bool(flags & FLAG_HAS_COUNTS)
    if has_ctx and ctx is not None:
        records = [r for r in records if r[0] == ctx]
        edges = [e for e in edges if e[0] == ctx]

    counts = {} if has_counts else None
    addr_seen = {}
    for _c, a, cnt in records:
        if a not in addr_seen:
            addr_seen[a] = True
        if counts is not None:
            counts[a] = counts.get(a, 0) + cnt
    addrs = list(addr_seen)

    merged = {}
    for _c, s, d, cnt in edges:
        merged[(s, d)] = merged.get((s, d), 0) + cnt
    out_edges = [(s, d, c) for (s, d), c in sorted(merged.items())]
    return meta, addrs, counts, out_edges


def read_cov(path):
    """Return (metadata_dict, [addresses], counts) from an TCGCOV1 file.

    counts is None for plain coverage files, or a dict {addr: exec_count} when
    the file was written with counts mode (header flag FLAG_HAS_COUNTS, 16-byte
    {addr, count} records). Edge records, if any, are ignored here; use
    read_edges()/read_all() for those.
    """
    meta, addrs, counts, _edges = read_all(path)
    return meta, addrs, counts


def read_edges(path):
    """Return [(src, dst, count)] for an TCGCOV1 file (empty if no edges).

    src is the vaddr of the LAST instruction of the source translation block;
    dst is the first vaddr of the destination block.
    """
    return read_all(path)[3]


def write_cov(path, meta, records, edges=None, record_type=1, ctx=False):
    """Write a TCGCOV artifact: the inverse of read_all/read_full.

    With ctx=False (the default), a TCGCOV1 file: `records` is a list of
    (addr, count) -- counts are always written (HAS_COUNTS), matching what
    the plugin emits -- and `edges`, if given, is (src, dst, count) written
    with EDGE_COUNTS.

    With ctx=True, a TCGCOV2 file with HAS_CTX: `records` is
    (ctx, addr, count) and `edges` is (ctx, src, dst, count); both are
    sorted before writing, per the format's (ctx, addr) / (ctx, src, dst)
    ordering rule. `meta` is the metadata dict, serialized as UTF-8 JSON.
    """
    blob = json.dumps(meta, sort_keys=True).encode("utf-8")
    flags = FLAG_HAS_COUNTS
    if edges:
        flags |= FLAG_HAS_EDGES | FLAG_EDGE_COUNTS
    if ctx:
        flags |= FLAG_HAS_CTX
        records = sorted(records)
        edges = sorted(edges) if edges else edges
    magic, version = MAGIC, (2 if ctx else 1)
    rec_words, edge_words = (3, 4) if ctx else (2, 3)
    records_off = HEADER_SIZE + len(blob)
    records_size = len(records) * 8 * rec_words
    edges_off = records_off + records_size if edges else 0
    edges_size = len(edges) * 8 * edge_words if edges else 0
    hdr = struct.pack(HEADER_FMT, magic, version, 1, HEADER_SIZE, record_type,
                      flags, len(records), HEADER_SIZE, len(blob),
                      records_off, records_size,
                      len(edges) if edges else 0, edges_off, edges_size)
    with open(path, "wb") as f:
        f.write(hdr)
        f.write(blob)
        rec_fmt = "<%dQ" % rec_words
        for r in records:
            f.write(struct.pack(rec_fmt, *r))
        edge_fmt = "<%dQ" % edge_words
        for e in (edges or []):
            f.write(struct.pack(edge_fmt, *e))
