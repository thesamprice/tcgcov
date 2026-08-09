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

Every file whose magic is "TCGCOV1\\0" has an 88-byte header containing the edge
fields (FORMAT.md section 7): the magic changed in the same release that added
them, so a short header is a corrupt file, not an old one.
"""

import json
import struct

MAGIC = b"TCGCOV1\0"
HEADER_FMT = "<8sHHIIIQQQQQQQQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)          # 88

# Address-record and edge-record strides, selected by the flags. records_size
# and edges_size must be whole multiples of these.
REC_STRIDE = {False: 8, True: 16}
EDGE_STRIDE = {False: 16, True: 24}

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
    if len(data) < 8 or data[:8] != MAGIC:
        raise ValueError(f"{path}: not a TCGCOV1 file (bad magic)")
    if len(data) < HEADER_SIZE:
        raise ValueError(f"{path}: truncated TCGCOV1 header: {len(data)} "
                         f"bytes, need {HEADER_SIZE}")

    version, endian = struct.unpack_from("<HH", data, 8)
    if endian == 2:
        raise ValueError(f"{path}: big-endian artifacts are not supported by "
                         f"this reader (endian=2); every field would have to "
                         f"be byte-swapped and the writer only emits endian=1")
    if endian != 1:
        raise ValueError(f"{path}: bad endian field {endian} "
                         f"(expected 1=little or 2=big)")
    if version != 1:
        raise ValueError(f"{path}: unsupported format version {version} "
                         f"(this reader knows version 1)")

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
    stride = REC_STRIDE[bool(flags & FLAG_HAS_COUNTS)]
    if hdr["records_size"] % stride:
        raise ValueError(f"{path}: records_size {hdr['records_size']} is not "
                         f"a multiple of the {stride}-byte record stride")
    if flags & FLAG_HAS_EDGES:
        stride = EDGE_STRIDE[bool(flags & FLAG_EDGE_COUNTS)]
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
