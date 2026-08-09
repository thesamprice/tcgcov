"""TCGCOV1 binary artifact format: constants and reader.

The on-disk layout (all little-endian):

    struct tcgcov_header {          # 88 bytes
        char     magic[8];          # "TCGCOV1\0"
        uint16_t version;
        uint16_t endian;            # 1 = little, 2 = big
        uint32_t header_size;
        uint32_t record_type;       # 1=TB_ADDR, 2=INSN_ADDR, 3=EDGE
        uint32_t flags;             # bit0 HAS_COUNTS, bit1 HAS_EDGES,
                                    # bit2 EDGE_COUNTS
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

Edge records are what makes BRANCH coverage possible. `src` is the vaddr of the
LAST INSTRUCTION of the source translation block, not its first: on delay-slot
architectures (MicroBlaze, MIPS, SPARC) the branch is not the last instruction
of the block, so recording the last instruction is the only way the host side
can tell which block the transfer left from.

Older artifacts used a 56-byte header with no edge fields; the reader accepts
both (the header_size field selects the layout), so existing .cov files keep
working.
"""

import json
import struct

MAGIC = b"TCGCOV1\0"
HEADER_FMT = "<8sHHIIIQQQQQQQQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)          # 88
HEADER_FMT_V1 = "<8sHHIIIQQQQQ"                    # pre-edges layout
HEADER_SIZE_V1 = struct.calcsize(HEADER_FMT_V1)    # 56

FLAG_HAS_COUNTS = 0x1
FLAG_HAS_EDGES = 0x2
FLAG_EDGE_COUNTS = 0x4

REC_TYPE = {1: "TB_ADDR", 2: "INSN_ADDR", 3: "EDGE"}

HEADER_FIELDS = (
    "magic", "version", "endian", "header_size", "record_type", "flags",
    "record_count", "metadata_offset", "metadata_size", "records_offset",
    "records_size", "edge_count", "edges_offset", "edges_size",
)


def parse_header(data, path="<data>"):
    """Return the header as a dict, accepting the 56- and 88-byte layouts.

    The short (pre-edges) layout is reported with zeroed edge fields, so callers
    can treat every artifact uniformly.
    """
    if len(data) < HEADER_SIZE_V1 or data[:8] != MAGIC:
        raise ValueError(f"{path}: not an TCGCOV1 file")
    # header_size is the uint32 at offset 12; it selects the layout.
    declared = struct.unpack_from("<I", data, 12)[0]
    if declared >= HEADER_SIZE and len(data) >= HEADER_SIZE:
        values = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    else:
        values = struct.unpack(HEADER_FMT_V1, data[:HEADER_SIZE_V1]) + (0, 0, 0)
    return dict(zip(HEADER_FIELDS, values))


def unpack_records(data, off, size, has_counts):
    """Decode the address record array -> ([addr], {addr: count} or None)."""
    if has_counts:
        n = size // 16
        flat = struct.unpack_from("<%dQ" % (2 * n), data, off) if n else ()
        return list(flat[0::2]), dict(zip(flat[0::2], flat[1::2]))
    n = size // 8
    addrs = list(struct.unpack_from("<%dQ" % n, data, off)) if n else []
    return addrs, None


def unpack_edges(data, off, size, has_counts):
    """Decode the edge array -> [(src, dst, count)].

    Without EDGE_COUNTS the plugin only records that an edge was taken; count is
    reported as 1 so callers do not have to special-case the two modes.
    """
    stride = 24 if has_counts else 16
    n = size // stride
    if not n:
        return []
    words = 3 if has_counts else 2
    flat = struct.unpack_from("<%dQ" % (words * n), data, off)
    if has_counts:
        return list(zip(flat[0::3], flat[1::3], flat[2::3]))
    return [(s, d, 1) for s, d in zip(flat[0::2], flat[1::2])]


def read_all(path):
    """Return (metadata, [addresses], counts, edges) from an TCGCOV1 file.

    counts is None unless the file was written in counts mode (FLAG_HAS_COUNTS).
    edges is a list of (src, dst, count) triples, empty when the artifact has no
    FLAG_HAS_EDGES section.
    """
    with open(path, "rb") as f:
        data = f.read()
    hdr = parse_header(data, path)
    flags = hdr["flags"]
    meta_off, meta_size = hdr["metadata_offset"], hdr["metadata_size"]
    meta = json.loads(data[meta_off:meta_off + meta_size].decode("utf-8"))

    addrs, counts = unpack_records(data, hdr["records_offset"],
                                   hdr["records_size"],
                                   bool(flags & FLAG_HAS_COUNTS))
    edges = []
    if flags & FLAG_HAS_EDGES and hdr["edges_size"]:
        edges = unpack_edges(data, hdr["edges_offset"], hdr["edges_size"],
                             bool(flags & FLAG_EDGE_COUNTS))
    return meta, addrs, counts, edges


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
