# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal, pure-stdlib reader for the DWARF `.debug_line` line-number program.

Why this exists: the coverable-line denominator was originally built by running
the target `objdump -d`, scraping instruction addresses out of the disassembly
TEXT, and resolving them with `addr2line`. That works, but it is the most
fragile step in the tool -- a disassembly layout the parser does not recognize
yields ZERO addresses, i.e. an empty denominator, i.e. a report that reads 100%
-- and it needs a target `objdump` on PATH.

DWARF already carries the answer. `.debug_line` maps code addresses to
(file, line) for ALL code, executed or not, and is entirely
architecture-independent: no disassembler, no instruction-format knowledge, no
toolchain binary. On a MicroBlaze test ELF, `objdump` yields 111 instruction
addresses and this reader yields 36 line-table rows, and both resolve to the
same 20 coverable source lines.

Scope, deliberately narrow -- this is not a DWARF library:

  * `.debug_line` versions 2, 3, 4 and 5 (both header shapes). An unsupported
    version RAISES, naming the version. Returning nothing would reintroduce
    exactly the silent-empty-denominator failure this module exists to avoid.
  * 32- and 64-bit ELF, little- and big-endian, and the DWARF 64-bit format
    (the 0xffffffff initial-length escape).
  * zlib-compressed debug sections (SHF_COMPRESSED and legacy `.zdebug_*`).
  * `.debug_info` is read only far enough to pull each compilation unit's
    DW_AT_comp_dir (needed to make relative file names absolute the way
    `addr2line` does) and DW_AT_str_offsets_base. That parse is best-effort:
    if it fails, the line table is still read.
  * `.symtab` is read for function names, since the line table has none.

Everything raises `DwarfError`, which is a `RuntimeError`, so callers that
already catch `(OSError, RuntimeError)` around the objdump path need no change.
"""

import os
import struct
import zlib
from bisect import bisect_right
from collections import namedtuple

__all__ = ["DwarfError", "LineRow", "ElfInfo", "FunctionIndex",
           "SUPPORTED_VERSIONS", "read_elf", "parse_line_section",
           "iter_line_rows", "iter_line_rows_by_section",
           "iter_coverable_lines", "iter_inline_call_sites"]


class DwarfError(RuntimeError):
    """Malformed, truncated or unsupported ELF/DWARF input.

    Derived from RuntimeError on purpose: the coverable producer already
    handles (OSError, RuntimeError) from the objdump path, so the DWARF path
    slots into the same error handling.
    """


# One row emitted by the line-number program. `file` is the resolved absolute
# (or comp_dir-relative, if comp_dir is unknown) source path, or None when the
# row's file index is not in the unit's file table.
# `section` is the ELF section index the row's sequence belongs to, known
# only for a relocatable object (from the relocation on its set_address);
# None otherwise.
LineRow = namedtuple("LineRow", "address file line end_sequence is_stmt "
                                "section", defaults=(None,))

# Line-table versions this module implements. DWARF 5 changed the header
# shape; 2/3/4 differ only in small ways (max_ops_per_insn appeared in 4).
SUPPORTED_VERSIONS = (2, 3, 4, 5)

# Sections we read. Anything absent is simply empty.
_WANTED_SECTIONS = (
    ".debug_line", ".debug_line_str", ".debug_str", ".debug_str_offsets",
    ".debug_info", ".debug_abbrev", ".symtab", ".strtab",
    ".debug_rnglists", ".debug_ranges", ".debug_addr",
)

_SHF_COMPRESSED = 0x800
_SHT_NOBITS = 8
_SHN_XINDEX = 0xFFFF

# DW_LNE_*
_LNE_END_SEQUENCE = 0x01
_LNE_SET_ADDRESS = 0x02
_LNE_DEFINE_FILE = 0x03
_LNE_SET_DISCRIMINATOR = 0x04

# DW_LNCT_* (DWARF 5 directory/file entry content types)
_LNCT_PATH = 0x01
_LNCT_DIRECTORY_INDEX = 0x02

# DW_AT_*
_AT_NAME = 0x03
_AT_STMT_LIST = 0x10
_AT_COMP_DIR = 0x1B
_AT_STR_OFFSETS_BASE = 0x72

# DW_TAG_compile_unit / DW_TAG_skeleton_unit carry comp_dir; other root DIEs
# (type units) do not have a stmt_list we care about anyway.
_TAG_COMPILE_UNIT = 0x11
_TAG_SKELETON_UNIT = 0x4A


def _decode(raw):
    """Bytes -> str the way the rest of tcgcov decodes tool output.

    Source paths are arbitrary bytes; surrogateescape keeps a non-UTF-8 byte
    from aborting the whole run.
    """
    return raw.decode("utf-8", "surrogateescape")


class _Reader:
    """Cursor over a bytes buffer with the DWARF primitive types."""

    def __init__(self, data, little=True, pos=0, what="data"):
        self.data = data
        self.little = little
        self.pos = pos
        self.what = what

    @property
    def prefix(self):
        return "<" if self.little else ">"

    def _need(self, size):
        end = self.pos + size
        if end > len(self.data) or size < 0:
            raise DwarfError("%s: truncated at offset 0x%x (wanted %d bytes, "
                             "%d left)" % (self.what, self.pos, size,
                                           len(self.data) - self.pos))
        return end

    def _fixed(self, fmt, size):
        end = self._need(size)
        value = struct.unpack_from(self.prefix + fmt, self.data, self.pos)[0]
        self.pos = end
        return value

    def u8(self):
        return self._fixed("B", 1)

    def s8(self):
        return self._fixed("b", 1)

    def u16(self):
        return self._fixed("H", 2)

    def u32(self):
        return self._fixed("I", 4)

    def u64(self):
        return self._fixed("Q", 8)

    def uint(self, size):
        """Unsigned integer of an arbitrary byte width (1..8)."""
        end = self._need(size)
        raw = self.data[self.pos:end]
        self.pos = end
        return int.from_bytes(raw, "little" if self.little else "big")

    def take(self, size):
        end = self._need(size)
        raw = self.data[self.pos:end]
        self.pos = end
        return raw

    def skip(self, size):
        self.pos = self._need(size)

    def uleb(self):
        result = 0
        shift = 0
        while True:
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7
            if shift > 128:
                raise DwarfError("%s: runaway ULEB128 at offset 0x%x"
                                 % (self.what, self.pos))

    def sleb(self):
        result = 0
        shift = 0
        while True:
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if byte & 0x40:
                    result -= 1 << shift
                return result
            if shift > 128:
                raise DwarfError("%s: runaway SLEB128 at offset 0x%x"
                                 % (self.what, self.pos))

    def cstr(self):
        end = self.data.find(b"\0", self.pos)
        if end == -1:
            raise DwarfError("%s: unterminated string at offset 0x%x"
                             % (self.what, self.pos))
        raw = self.data[self.pos:end]
        self.pos = end + 1
        return _decode(raw)


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------

# relocatable: ET_REL (a .o / .ko), whose debug sections have been relocated
#   in `sections` by read_elf -- every code section starts at 0 there.
# section_names: name per section index. section_addrs: (sh_addr, sh_size)
#   per index. line_sections: .debug_line offset -> the section index an
#   address operand there was relocated against (set_address -> section).
# machine: e_machine.
# reloc_targets: for each relocated debug section, {offset: section index}
#   of its absolute relocations against allocated sections (line_sections is
#   the .debug_line one). exec_ranges: [(start, end)] of the executable
#   sections of a linked image -- where real code is; code the linker
#   discarded keeps debug info relocated to (near) 0, outside all of them.
ElfInfo = namedtuple("ElfInfo", "path sections little is64 relocatable "
                                "section_names section_addrs line_sections "
                                "machine reloc_targets exec_ranges",
                     defaults=(False, (), (), None, 0, None, ()))


def _string_at(table, offset):
    if offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    return _decode(table[offset:end if end != -1 else len(table)])


def _decompress(name, raw, little, is64):
    """Transparently inflate a compressed debug section.

    Two spellings exist: SHF_COMPRESSED with an Elf(32|64)_Chdr, and the older
    GNU `.zdebug_*` convention ("ZLIB" + 8-byte big-endian size).
    """
    if raw[:4] == b"ZLIB" and len(raw) >= 12:
        return zlib.decompress(raw[12:])
    hdr = 24 if is64 else 12
    if len(raw) < hdr:
        raise DwarfError("%s: compressed section header truncated" % name)
    prefix = "<" if little else ">"
    ch_type = struct.unpack_from(prefix + "I", raw, 0)[0]
    if ch_type != 1:                        # 1 == ELFCOMPRESS_ZLIB
        raise DwarfError("%s: unsupported debug-section compression type %d "
                         "(only zlib is supported)" % (name, ch_type))
    return zlib.decompress(raw[hdr:])


def read_elf(path, wanted=_WANTED_SECTIONS):
    """Read an ELF's section headers; return an ElfInfo with `wanted` sections.

    Handles ELF32/ELF64 and both endiannesses -- the whole point of this tool
    is cross-target work, so neither may be assumed. Sections absent from the
    file are simply absent from the dict.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise DwarfError("%s: not an ELF file" % path)

    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise DwarfError("%s: unknown ELF class %d" % (path, ei_class))
    if ei_data not in (1, 2):
        raise DwarfError("%s: unknown ELF data encoding %d" % (path, ei_data))
    is64 = ei_class == 2
    little = ei_data == 1
    prefix = "<" if little else ">"

    e_type, e_machine = struct.unpack_from(prefix + "HH", data, 16)
    if is64:
        e_shoff = struct.unpack_from(prefix + "Q", data, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            prefix + "HHH", data, 0x3A)
    else:
        e_shoff = struct.unpack_from(prefix + "I", data, 0x20)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            prefix + "HHH", data, 0x2E)

    if not e_shoff or not e_shentsize:
        raise DwarfError("%s: no section headers (stripped or a core file?)"
                         % path)

    def shdr(index):
        off = e_shoff + index * e_shentsize
        if off + e_shentsize > len(data):
            raise DwarfError("%s: section header %d out of range"
                             % (path, index))
        if is64:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info) = struct.unpack_from(prefix + "IIQQQQII",
                                                    data, off)
        else:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, sh_info) = struct.unpack_from(prefix + "IIIIIIII",
                                                    data, off)
        return (sh_name, sh_type, sh_flags, sh_offset, sh_size, sh_addr,
                sh_link, sh_info)

    # e_shnum == 0 / e_shstrndx == SHN_XINDEX push the real values into
    # section 0. Rare, but produced by linkers on very large images.
    first = shdr(0)
    if e_shnum == 0:
        e_shnum = first[4]
    if e_shstrndx == _SHN_XINDEX:
        # sh_link of section 0; it sits after sh_size in both classes.
        off = e_shoff + (0x28 if is64 else 0x18)
        e_shstrndx = struct.unpack_from(prefix + "I", data, off)[0]
    if e_shstrndx >= e_shnum:
        raise DwarfError("%s: bad section-name string table index" % path)

    str_off, str_size = shdr(e_shstrndx)[3:5]
    shstrtab = data[str_off:str_off + str_size]

    wanted = set(wanted)
    # ".zdebug_x" is the legacy compressed spelling of ".debug_x".
    zwanted = {".z" + n[1:]: n for n in wanted if n.startswith(".debug")}
    sections = {}
    headers = [shdr(i) for i in range(e_shnum)]
    names = [_string_at(shstrtab, h[0]) for h in headers]
    index_of = {}
    for i in range(e_shnum):
        sh_name, sh_type, sh_flags, sh_offset, sh_size = headers[i][:5]
        name = names[i]
        key = name if name in wanted else zwanted.get(name)
        if key is None or sh_type == _SHT_NOBITS:
            continue
        index_of[key] = i
        raw = data[sh_offset:sh_offset + sh_size]
        if sh_flags & _SHF_COMPRESSED or name.startswith(".zdebug"):
            try:
                raw = _decompress(name, raw, little, is64)
            except zlib.error as e:
                raise DwarfError("%s: %s: decompression failed (%s)"
                                 % (path, name, e))
        sections[key] = raw

    targets = {}
    relocatable = e_type == _ET_REL
    if relocatable:
        targets = _relocate_debug(path, data, headers, names, index_of,
                                  sections, little, is64, e_machine)
    exec_ranges = tuple(sorted(
        (h[5], h[5] + h[4]) for h in headers
        if h[2] & _SHF_EXECINSTR_FLAG and h[4] and not relocatable))
    return ElfInfo(path, sections, little, is64, relocatable, tuple(names),
                   tuple((h[5], h[4]) for h in headers),
                   targets.get(".debug_line"), e_machine, targets,
                   exec_ranges)


# --------------------------------------------------------------------------
# Relocations (relocatable objects only)
# --------------------------------------------------------------------------
#
# A .o's debug sections are incomplete until relocated: addresses in the line
# table (DW_LNE_set_address) and string offsets (DW_FORM_strp/line_strp) are
# zero in place, and on RISC-V every address advance inside a sequence is an
# ADD/SUB relocation pair because of linker relaxation. Section symbols and
# local labels in a .o are section-relative, so applying S + A yields offsets
# into the target section -- exactly the 0-based addresses `addr2line -j`
# works in. Only the types debug sections use are implemented; any other is
# an error, never a guess.

_ET_REL = 1
_SHT_RELA, _SHT_REL = 4, 9
_SHF_ALLOC_FLAG = 0x2
_RELOCATED = (".debug_line", ".debug_info", ".debug_str_offsets",
              ".debug_rnglists", ".debug_ranges", ".debug_addr")
_SHF_EXECINSTR_FLAG = 0x4

_ABS, _ADD, _SUB, _SET, _SET6, _SUB6, _SET_ULEB, _SUB_ULEB = range(8)
# e_machine -> {r_type: (operation, width)}; width in bytes.
_RELOC_OPS = {
    243: {                                        # RISC-V
        0: None, 1: (_ABS, 4), 2: (_ABS, 8),
        33: (_ADD, 1), 34: (_ADD, 2), 35: (_ADD, 4), 36: (_ADD, 8),
        37: (_SUB, 1), 38: (_SUB, 2), 39: (_SUB, 4), 40: (_SUB, 8),
        43: None, 51: None,                       # ALIGN, RELAX markers
        52: (_SUB6, 1), 53: (_SET6, 1), 54: (_SET, 1), 55: (_SET, 2),
        56: (_SET, 4), 60: (_SET_ULEB, 0), 61: (_SUB_ULEB, 0),
    },
    # MicroBlaze: 9/33 are 64_NONE/32_NONE, relaxation markers that write
    # nothing.
    189: {0: None, 1: (_ABS, 4), 9: None, 33: None},
    0xBAAB: {0: None, 1: (_ABS, 4), 9: None, 33: None},
    62: {0: None, 1: (_ABS, 8), 10: (_ABS, 4), 11: (_ABS, 4)},  # x86-64
    183: {0: None, 257: (_ABS, 8), 258: (_ABS, 4), 259: (_ABS, 2)},  # AArch64
    40: {0: None, 2: (_ABS, 4)},                  # ARM (REL)
    3: {0: None, 1: (_ABS, 4)},                   # i386 (REL)
}


def _uleb_len(buf, off):
    n = 1
    while off + n - 1 < len(buf) and buf[off + n - 1] & 0x80:
        n += 1
    return n


def _read_uleb(buf, off, n):
    v = 0
    for i in range(n):
        v |= (buf[off + i] & 0x7F) << (7 * i)
    return v


def _write_uleb_fixed(buf, off, n, value):
    """Encode `value` in exactly n bytes (padding with continuation bits)."""
    for i in range(n):
        byte = value & 0x7F
        value >>= 7
        if i < n - 1:
            byte |= 0x80
        buf[off + i] = byte


def _relocate_debug(path, data, headers, names, index_of, sections, little,
                    is64, machine):
    """Apply the relocations of the debug sections in `sections`, in place.

    Returns {debug section: {offset: section index}} for the absolute
    relocations whose symbol lives in an allocated section: the sections
    the line table's set_address operands, and the address attributes and
    range lists, point into.
    """
    prefix = "<" if little else ">"
    symtab_cache = {}

    def symbols(link):
        if link not in symtab_cache:
            off, size = headers[link][3], headers[link][4]
            ent = 24 if is64 else 16
            out = []
            for o in range(off, off + size - ent + 1, ent):
                if is64:
                    _n, _i, _o, shndx, value, _s = struct.unpack_from(
                        prefix + "IBBHQQ", data, o)
                else:
                    _n, value, _s, _i, _o, shndx = struct.unpack_from(
                        prefix + "IIIBBH", data, o)
                out.append((value, shndx))
            symtab_cache[link] = out
        return symtab_cache[link]

    ops = _RELOC_OPS.get(machine)
    targets = {}
    for key in _RELOCATED:
        target = index_of.get(key)
        if target is None:
            continue
        relocs = [h for h in headers
                  if h[1] in (_SHT_RELA, _SHT_REL) and h[7] == target]
        if not relocs:
            continue
        if ops is None:
            raise DwarfError("%s: relocatable object for ELF machine %d, "
                             "whose relocations this reader does not know"
                             % (path, machine))
        buf = bytearray(sections[key])
        where = targets.setdefault(key, {})
        for rh in relocs:
            rela = rh[1] == _SHT_RELA
            ent = (24 if is64 else 12) if rela else (16 if is64 else 8)
            syms = symbols(rh[6])
            for o in range(rh[3], rh[3] + rh[4] - ent + 1, ent):
                if is64:
                    r_off, r_info = struct.unpack_from(prefix + "QQ", data, o)
                    r_sym, r_type = r_info >> 32, r_info & 0xFFFFFFFF
                    addend = (struct.unpack_from(prefix + "q", data, o + 16)[0]
                              if rela else None)
                else:
                    r_off, r_info = struct.unpack_from(prefix + "II", data, o)
                    r_sym, r_type = r_info >> 8, r_info & 0xFF
                    addend = (struct.unpack_from(prefix + "i", data, o + 8)[0]
                              if rela else None)
                if r_type not in ops:
                    raise DwarfError(
                        "%s: %s: relocation type %d for ELF machine %d is not "
                        "supported" % (path, key, r_type, machine))
                op = ops[r_type]
                if op is None:
                    continue
                kind, width = op
                value, shndx = syms[r_sym] if r_sym < len(syms) else (0, 0)
                fmt = prefix + {1: "B", 2: "H", 4: "I", 8: "Q"}.get(width, "")
                if kind in (_SET_ULEB, _SUB_ULEB):
                    n = _uleb_len(buf, r_off)
                    cur = _read_uleb(buf, r_off, n)
                    a = addend or 0
                    new = value + a if kind == _SET_ULEB else cur - value - a
                    _write_uleb_fixed(buf, r_off, n, new & ((1 << (7 * n)) - 1))
                    continue
                if r_off + width > len(buf):
                    raise DwarfError("%s: %s: relocation at 0x%x past the "
                                     "section" % (path, key, r_off))
                cur = struct.unpack_from(fmt, buf, r_off)[0]
                a = cur if addend is None else addend
                mask = (1 << (8 * width)) - 1
                if kind == _ABS or kind == _SET:
                    new = value + a
                elif kind == _ADD:
                    new = cur + value + a
                elif kind == _SUB:
                    new = cur - value - a
                elif kind == _SET6:
                    new = (cur & 0xC0) | ((value + a) & 0x3F)
                else:                                   # _SUB6
                    new = (cur & 0xC0) | ((cur - value - a) & 0x3F)
                struct.pack_into(fmt, buf, r_off, new & mask)
                if kind == _ABS and 0 < shndx < len(headers) and \
                        headers[shndx][2] & _SHF_ALLOC_FLAG:
                    where[r_off] = shndx
        sections[key] = bytes(buf)
    return targets


# --------------------------------------------------------------------------
# Function names (the line table has none)
# --------------------------------------------------------------------------

class FunctionIndex:
    """Address -> function name, from `.symtab` STT_FUNC symbols.

    The line table carries no function name, but the coverable records have a
    `function` field (LCOV `FN:` records come from it). Symbol names match what
    `addr2line` reports for non-inlined code in C; for C++ they are mangled,
    where `addr2line -C` demangles -- a cosmetic difference confined to FN
    records, never to the line denominator.
    """

    def __init__(self, elf):
        symtab = elf.sections.get(".symtab", b"")
        strtab = elf.sections.get(".strtab", b"")
        entsize = 24 if elf.is64 else 16
        prefix = "<" if elf.little else ">"
        funcs = []
        for off in range(0, len(symtab) - entsize + 1, entsize):
            if elf.is64:
                st_name, st_info, _other, shndx, st_value, st_size = \
                    struct.unpack_from(prefix + "IBBHQQ", symtab, off)
            else:
                st_name, st_value, st_size, st_info, _other, shndx = \
                    struct.unpack_from(prefix + "IIIBBH", symtab, off)
            if st_info & 0xF != 2:          # STT_FUNC
                continue
            name = _string_at(strtab, st_name)
            if name:
                funcs.append((st_value, st_size, name, shndx))
        # In a relocatable object every section's symbols start at 0, so a
        # function is looked up within its own section.
        self._relocatable = getattr(elf, "relocatable", False)
        self._by_section = {}
        for f in funcs:
            key = f[3] if self._relocatable else None
            self._by_section.setdefault(key, []).append(f[:3])
        for lst in self._by_section.values():
            lst.sort(key=lambda f: (f[0], -f[1]))
        self._funcs = self._by_section.get(None, [])
        self._starts = [f[0] for f in self._funcs]

    def at(self, address, section=None):
        """Return the function containing `address` (in `section`, for a
        relocatable object), or "" if none does."""
        if self._relocatable:
            funcs = self._by_section.get(section, [])
            return self._lookup(funcs, [f[0] for f in funcs], address)
        return self._lookup(self._funcs, self._starts, address)

    @staticmethod
    def _lookup(funcs, starts, address):
        """Return the function containing `address`, or "" if none does.

        Only symbols starting at the same address are considered as
        alternatives (aliases, and the zero-sized assembly labels binutils
        emits alongside a sized symbol); a symbol that does not span the
        address is not stretched to reach it.
        """
        i = bisect_right(starts, address) - 1
        if i < 0:
            return ""
        start = starts[i]
        while i >= 0 and starts[i] == start:
            _s, size, name = funcs[i]
            if (size and address < start + size) or \
                    (not size and address == start):
                return name
            i -= 1
        return ""


# --------------------------------------------------------------------------
# DWARF forms (shared by the .debug_info scan and the DWARF 5 file tables)
# --------------------------------------------------------------------------

# Marker for a string that can only be resolved once the unit's
# DW_AT_str_offsets_base is known.
_Strx = namedtuple("_Strx", "index")

# form -> fixed byte size, for the forms whose size does not depend on
# anything the reader has to interpret.
_FORM_FIXED = {
    0x05: 2, 0x06: 4, 0x07: 8,          # data2, data4, data8
    0x0B: 1, 0x0C: 1,                   # data1, flag
    0x11: 1, 0x12: 2, 0x13: 4, 0x14: 8,  # ref1, ref2, ref4, ref8
    0x19: 0,                            # flag_present
    0x1C: 4,                            # ref_sup4
    0x1E: 16,                           # data16 (MD5)
    0x20: 8,                            # ref_sig8
    0x21: 0,                            # implicit_const
    0x24: 8,                            # ref_sup8
    0x25: 1, 0x26: 2, 0x27: 3, 0x28: 4,  # strx1..strx4
    0x29: 1, 0x2A: 2, 0x2B: 3, 0x2C: 4,  # addrx1..addrx4
}
_FORM_ULEB = (0x0F, 0x15, 0x1A, 0x1B, 0x22, 0x23)  # udata, ref_udata, strx,
#                                                    addrx, loclistx, rnglistx
_FORM_BLOCK_LEN = {0x03: 2, 0x04: 4, 0x0A: 1}       # block2, block4, block1
_STRX_FORMS = (0x1A, 0x25, 0x26, 0x27, 0x28)


def _read_form(r, form, offset_size, addr_size, strings, implicit_const=None):
    """Read one attribute value; return a str/int/bytes, a _Strx, or None.

    `strings` is (debug_str, debug_line_str). Unhandled-but-well-formed forms
    are consumed and returned as None -- the caller only cares about a handful
    of attributes, but must still be able to walk past the rest.
    """
    debug_str, line_str = strings
    if form == 0x16:                        # DW_FORM_indirect
        return _read_form(r, r.uleb(), offset_size, addr_size, strings)
    if form == 0x21:                        # DW_FORM_implicit_const
        return implicit_const
    if form == 0x08:                        # DW_FORM_string
        return r.cstr()
    if form == 0x0E:                        # DW_FORM_strp
        return _string_at(debug_str, r.uint(offset_size))
    if form == 0x1F:                        # DW_FORM_line_strp
        return _string_at(line_str, r.uint(offset_size))
    if form == 0x1D:                        # DW_FORM_strp_sup (supplementary
        r.skip(offset_size)                 # object file: not available)
        return None
    if form in _STRX_FORMS:
        return _Strx(r.uleb() if form == 0x1A else r.uint(_FORM_FIXED[form]))
    if form == 0x01:                        # DW_FORM_addr
        return r.uint(addr_size)
    if form in (0x10, 0x17):                # ref_addr, sec_offset
        return r.uint(offset_size)
    if form == 0x0D:                        # DW_FORM_sdata
        return r.sleb()
    if form in _FORM_ULEB:
        return r.uleb()
    if form in _FORM_BLOCK_LEN:
        return r.take(r.uint(_FORM_BLOCK_LEN[form]))
    if form in (0x09, 0x18):                # block, exprloc
        return r.take(r.uleb())
    size = _FORM_FIXED.get(form)
    if size is None:
        raise DwarfError("unhandled DWARF form 0x%x at offset 0x%x"
                         % (form, r.pos))
    return r.uint(size) if size else None


def _resolve_strx(value, str_offsets, base, offset_size, little):
    """Resolve DW_FORM_strx* against `.debug_str_offsets`."""
    if not str_offsets:
        raise DwarfError("DW_FORM_strx used but .debug_str_offsets is missing")
    off = base + value.index * offset_size
    if off + offset_size > len(str_offsets):
        raise DwarfError("DW_FORM_strx index %d out of range in "
                         ".debug_str_offsets" % value.index)
    return int.from_bytes(str_offsets[off:off + offset_size],
                          "little" if little else "big")


# --------------------------------------------------------------------------
# .debug_info: comp_dir and str_offsets_base per line-table unit
# --------------------------------------------------------------------------

def _parse_abbrev(data, offset, little):
    """Parse one abbreviation table -> {code: (tag, [(attr, form, const)])}."""
    r = _Reader(data, little, offset, ".debug_abbrev")
    table = {}
    while True:
        code = r.uleb()
        if code == 0:
            return table
        tag = r.uleb()
        r.u8()                              # DW_CHILDREN_*
        attrs = []
        while True:
            attr = r.uleb()
            form = r.uleb()
            const = r.sleb() if form == 0x21 else None
            if attr == 0 and form == 0:
                break
            attrs.append((attr, form, const))
        table[code] = (tag, attrs)


def _unit_metadata(elf):
    """Map a `.debug_line` unit offset -> {"comp_dir":…, "str_offsets_base":…}.

    Best effort by design: DWARF 5 file tables already carry comp_dir as
    directory 0, so this only really matters for versions 2-4, and a
    `.debug_info` we cannot parse must never stop the line table being read.
    """
    info = elf.sections.get(".debug_info", b"")
    abbrev_data = elf.sections.get(".debug_abbrev", b"")
    if not info or not abbrev_data:
        return {}
    debug_str = elf.sections.get(".debug_str", b"")
    line_str = elf.sections.get(".debug_line_str", b"")
    str_offsets = elf.sections.get(".debug_str_offsets", b"")
    strings = (debug_str, line_str)

    out = {}
    abbrev_cache = {}
    r = _Reader(info, elf.little, 0, ".debug_info")
    while r.pos + 11 <= len(info):
        length = r.u32()
        offset_size = 4
        if length == 0xFFFFFFFF:
            offset_size = 8
            length = r.u64()
        elif length >= 0xFFFFFFF0 or length == 0:
            break                           # reserved value or padding
        unit_end = r.pos + length
        if unit_end > len(info):
            break
        try:
            version = r.u16()
            if version >= 5:
                unit_type = r.u8()
                addr_size = r.u8()
                abbrev_off = r.uint(offset_size)
                if unit_type in (2, 6):     # DW_UT_type / DW_UT_split_type
                    r.skip(8 + offset_size)
                elif unit_type in (4, 5):   # DW_UT_skeleton / split_compile
                    r.skip(8)
            else:
                abbrev_off = r.uint(offset_size)
                addr_size = r.u8()
            if abbrev_off not in abbrev_cache:
                abbrev_cache[abbrev_off] = _parse_abbrev(
                    abbrev_data, abbrev_off, elf.little)
            abbrevs = abbrev_cache[abbrev_off]
            code = r.uleb()
            if code:
                tag, attrs = abbrevs.get(code, (None, None))
                if attrs is not None:
                    values = []
                    for attr, form, const in attrs:
                        values.append((attr, _read_form(
                            r, form, offset_size, addr_size, strings, const)))
                    if tag in (_TAG_COMPILE_UNIT, _TAG_SKELETON_UNIT):
                        _record_unit(out, values, str_offsets, offset_size,
                                     elf.little, debug_str)
        except (DwarfError, struct.error, KeyError):
            pass                            # one bad CU must not lose the rest
        r.pos = unit_end
    return out


def _record_unit(out, values, str_offsets, offset_size, little, debug_str):
    """Turn one compile-unit DIE's attributes into a line-unit metadata entry.

    Two passes: DW_AT_str_offsets_base may appear after DW_AT_comp_dir in the
    DIE, and a strx-form comp_dir cannot be resolved without it. When absent it
    defaults to the standard `.debug_str_offsets` header size.
    """
    by_attr = dict(values)
    stmt_list = by_attr.get(_AT_STMT_LIST)
    if not isinstance(stmt_list, int):
        return
    base = by_attr.get(_AT_STR_OFFSETS_BASE)
    if not isinstance(base, int):
        base = 8 if offset_size == 4 else 16
    comp_dir = by_attr.get(_AT_COMP_DIR)
    if isinstance(comp_dir, _Strx):
        try:
            comp_dir = _string_at(debug_str, _resolve_strx(
                comp_dir, str_offsets, base, offset_size, little))
        except DwarfError:
            comp_dir = None
    if not isinstance(comp_dir, str):
        comp_dir = None
    out[stmt_list] = {"comp_dir": comp_dir, "str_offsets_base": base}


# --------------------------------------------------------------------------
# .debug_line
# --------------------------------------------------------------------------

class _LineHeader:
    """The decoded prologue of one line-number program unit."""

    __slots__ = ("offset", "version", "offset_size", "unit_end",
                 "program_start", "min_inst", "max_ops", "default_is_stmt",
                 "line_base", "line_range", "opcode_base", "std_lens",
                 "dirs", "files", "comp_dir")


def _parse_v4_tables(r):
    """DWARF 2-4: NUL-terminated name lists, each ended by an empty name."""
    dirs = []
    while True:
        name = r.cstr()
        if not name:
            break
        dirs.append(name)
    files = []
    while True:
        name = r.cstr()
        if not name:
            break
        dir_index = r.uleb()
        r.uleb()                            # mtime
        r.uleb()                            # length
        files.append((name, dir_index))
    return dirs, files


def _parse_v5_table(r, offset_size, addr_size, strings, str_offsets, base,
                    little):
    """DWARF 5: a content-type/form descriptor list, then that many entries."""
    fmt_count = r.u8()
    formats = [(r.uleb(), r.uleb()) for _ in range(fmt_count)]
    count = r.uleb()
    entries = []
    for _ in range(count):
        name = None
        dir_index = 0
        for content_type, form in formats:
            value = _read_form(r, form, offset_size, addr_size, strings)
            if content_type == _LNCT_PATH:
                if isinstance(value, _Strx):
                    value = _string_at(strings[0], _resolve_strx(
                        value, str_offsets, base, offset_size, little))
                name = value
            elif content_type == _LNCT_DIRECTORY_INDEX:
                dir_index = value if isinstance(value, int) else 0
        entries.append((name if isinstance(name, str) else "", dir_index))
    return entries


def _parse_header(r, unit_offset, elf_little, sections, metadata):
    """Parse one unit prologue; leaves `r` positioned at the program."""
    h = _LineHeader()
    h.offset = unit_offset
    length = r.u32()
    h.offset_size = 4
    if length == 0xFFFFFFFF:
        h.offset_size = 8
        length = r.u64()
    elif length >= 0xFFFFFFF0:
        raise DwarfError(".debug_line+0x%x: reserved initial length 0x%x"
                         % (unit_offset, length))
    h.unit_end = r.pos + length
    if h.unit_end > len(r.data):
        raise DwarfError(".debug_line+0x%x: unit length %d runs past the "
                         "section (%d bytes)"
                         % (unit_offset, length, len(r.data)))

    h.version = r.u16()
    if h.version not in SUPPORTED_VERSIONS:
        raise DwarfError(
            ".debug_line+0x%x: unsupported DWARF line-table version %d "
            "(this reader implements %s). Refusing to guess: an empty "
            "coverable inventory would make every report read 100%%."
            % (unit_offset, h.version,
               ", ".join(str(v) for v in SUPPORTED_VERSIONS)))

    addr_size = 8 if h.offset_size == 8 else 4
    if h.version >= 5:
        addr_size = r.u8()
        r.u8()                              # segment_selector_size
    header_length = r.uint(h.offset_size)
    h.program_start = r.pos + header_length

    h.min_inst = r.u8() or 1
    h.max_ops = (r.u8() or 1) if h.version >= 4 else 1
    h.default_is_stmt = bool(r.u8())
    h.line_base = r.s8()
    h.line_range = r.u8()
    if h.line_range == 0:
        raise DwarfError(".debug_line+0x%x: line_range is 0" % unit_offset)
    h.opcode_base = r.u8()
    h.std_lens = [r.u8() for _ in range(max(h.opcode_base - 1, 0))]

    meta = metadata.get(unit_offset, {})
    h.comp_dir = meta.get("comp_dir")
    base = meta.get("str_offsets_base", 8 if h.offset_size == 4 else 16)
    strings = (sections.get(".debug_str", b""),
               sections.get(".debug_line_str", b""))
    str_offsets = sections.get(".debug_str_offsets", b"")

    if h.version >= 5:
        dirs = _parse_v5_table(r, h.offset_size, addr_size, strings,
                               str_offsets, base, elf_little)
        files = _parse_v5_table(r, h.offset_size, addr_size, strings,
                                str_offsets, base, elf_little)
        h.dirs = [name for name, _ in dirs]
        h.files = files
        # In DWARF 5 directory 0 IS the compilation directory, so a unit needs
        # no help from .debug_info to make its relative names absolute.
        if not h.comp_dir and h.dirs:
            h.comp_dir = h.dirs[0]
    else:
        h.dirs, h.files = _parse_v4_tables(r)
    return h


def _resolve_file(h, index, cache):
    """File-table index -> path, joined the way `addr2line` (bfd) joins it.

    bfd's concat_filename: an absolute file name is used as-is; otherwise the
    directory is prepended, and comp_dir is prepended to THAT unless the
    directory is itself absolute. DWARF 5 indexes both tables from 0 (index 0
    being the primary source file and directory 0 the comp_dir); DWARF 2-4
    index files from 1 and directories from 1, with file index 0 meaning "the
    unit's primary source file", which is not in the table at all.
    """
    if index in cache:
        return cache[index]

    entry = None
    if h.version >= 5:
        if 0 <= index < len(h.files):
            name, dir_index = h.files[index]
            directory = h.dirs[dir_index] if 0 <= dir_index < len(h.dirs) \
                else None
            entry = (name, directory)
    else:
        if 1 <= index <= len(h.files):
            name, dir_index = h.files[index - 1]
            directory = h.dirs[dir_index - 1] if 1 <= dir_index <= len(h.dirs) \
                else None
            entry = (name, directory)

    path = None
    if entry and entry[0]:
        name, directory = entry
        if os.path.isabs(name):
            path = name
        elif directory:
            path = directory if os.path.isabs(directory) or not h.comp_dir \
                else os.path.join(h.comp_dir, directory)
            path = os.path.join(path, name)
        elif h.comp_dir:
            path = os.path.join(h.comp_dir, name)
        else:
            path = name
        path = os.path.normpath(path)

    cache[index] = path
    return path


def _run_program(r, h, line_sections=None):
    """Execute one unit's line-number program, yielding every row it emits.

    line_sections (relocatable objects) maps a set_address operand's offset
    to the section it addresses; rows carry it until the sequence ends.
    """
    file_cache = {}
    line_sections = line_sections or {}
    section = None
    address = 0
    op_index = 0
    file_index = 1
    line = 1
    is_stmt = h.default_is_stmt

    def advance(operation_advance):
        nonlocal address, op_index
        if h.max_ops <= 1:
            address += h.min_inst * operation_advance
        else:
            total = op_index + operation_advance
            address += h.min_inst * (total // h.max_ops)
            op_index = total % h.max_ops

    def reset():
        nonlocal address, op_index, file_index, line, is_stmt, section
        section = None
        address = 0
        op_index = 0
        file_index = 1
        line = 1
        is_stmt = h.default_is_stmt

    while r.pos < h.unit_end:
        opcode = r.u8()

        if opcode >= h.opcode_base:          # special opcode
            adjusted = opcode - h.opcode_base
            advance(adjusted // h.line_range)
            line += h.line_base + (adjusted % h.line_range)
            yield LineRow(address, _resolve_file(h, file_index, file_cache),
                          line, False, is_stmt, section)
            continue

        if opcode == 0:                      # extended opcode
            length = r.uleb()
            end = r.pos + length
            if length == 0:
                continue
            sub = r.u8()
            if sub == _LNE_END_SEQUENCE:
                yield LineRow(address,
                              _resolve_file(h, file_index, file_cache),
                              line, True, is_stmt, section)
                reset()
            elif sub == _LNE_SET_ADDRESS:
                # The operand width comes from the operation's own length, so
                # 4- and 8-byte targets both work without being told which.
                section = line_sections.get(r.pos, section)
                address = r.uint(max(length - 1, 0))
                op_index = 0
            elif sub == _LNE_DEFINE_FILE:    # DWARF <= 4 only
                name = r.cstr()
                dir_index = r.uleb()
                r.uleb()
                r.uleb()
                h.files.append((name, dir_index))
                file_cache.clear()
            elif sub == _LNE_SET_DISCRIMINATOR:
                r.uleb()
            r.pos = end                      # vendor extensions included
            continue

        # Standard opcodes.
        if opcode == 1:                      # DW_LNS_copy
            yield LineRow(address, _resolve_file(h, file_index, file_cache),
                          line, False, is_stmt, section)
        elif opcode == 2:                    # DW_LNS_advance_pc
            advance(r.uleb())
        elif opcode == 3:                    # DW_LNS_advance_line
            line += r.sleb()
        elif opcode == 4:                    # DW_LNS_set_file
            file_index = r.uleb()
        elif opcode == 5:                    # DW_LNS_set_column
            r.uleb()
        elif opcode == 6:                    # DW_LNS_negate_stmt
            is_stmt = not is_stmt
        elif opcode == 7:                    # DW_LNS_set_basic_block
            pass
        elif opcode == 8:                    # DW_LNS_const_add_pc
            advance((255 - h.opcode_base) // h.line_range)
        elif opcode == 9:                    # DW_LNS_fixed_advance_pc
            address += r.u16()
            op_index = 0
        elif opcode in (10, 11):             # set_prologue_end/epilogue_begin
            pass
        elif opcode == 12:                   # DW_LNS_set_isa
            r.uleb()
        else:
            # A vendor standard opcode we do not know: the header told us how
            # many ULEB operands it takes, which is exactly why that table
            # exists.
            for _ in range(h.std_lens[opcode - 1] if
                           opcode - 1 < len(h.std_lens) else 0):
                r.uleb()


def parse_line_section(data, little=True, sections=None, metadata=None,
                       line_sections=None):
    """Yield every LineRow in a `.debug_line` section, end_sequence included.

    `sections` supplies the string sections a DWARF 5 file table may reference
    (`.debug_line_str`, `.debug_str`, `.debug_str_offsets`); `metadata` maps a
    unit offset to its comp_dir/str_offsets_base (see `_unit_metadata`). Both
    default to empty, which is enough for a self-contained v2-4 table.
    """
    sections = sections or {}
    metadata = metadata or {}
    r = _Reader(data, little, 0, ".debug_line")
    while r.pos + 4 <= len(data):
        unit_offset = r.pos
        # Some linkers pad the section with zeros; a zero length is not a unit.
        if data[unit_offset:unit_offset + 4] == b"\0\0\0\0":
            break
        h = _parse_header(r, unit_offset, little, sections, metadata)
        r.pos = h.program_start
        for row in _run_program(r, h, line_sections):
            yield row
        r.pos = h.unit_end


def iter_line_rows(elf, section=None):
    """Yield (address, file, line) for every real code row; see below."""
    for address, path, line, _sec in iter_line_rows_by_section(elf, section):
        yield address, path, line


def section_base(elf, section):
    """Address a row's 0-based --section offset is relative to.

    0 for a relocatable object (its symbols are section-relative too);
    the section's sh_addr in a linked image, where symbols are absolute.
    """
    if section is None or elf.relocatable:
        return 0
    return elf.section_addrs[elf.section_names.index(section)][0]


# --------------------------------------------------------------------------
# Coverable lines: what `addr2line -i` would report for every instruction
# --------------------------------------------------------------------------
#
# The objdump denominator resolves each instruction through `addr2line -i`,
# which reports, per address, the LAST line-table row at that address, plus
# for inlined code the call site of every inlined frame. Counting every row
# instead (several rows share an address at -O2: declarations, views) gave
# 37% more lines than objdump on a riscv RTEMS image while missing the call
# sites (issue #23). iter_coverable_lines reproduces addr2line's view from
# the DWARF alone: last row per address, plus DW_AT_call_file/call_line of
# every DW_TAG_inlined_subroutine whose code survived linking.

_TAG_INLINED_SUBROUTINE = 0x1D
_AT_LOW_PC, _AT_HIGH_PC, _AT_RANGES = 0x11, 0x12, 0x55
_AT_CALL_FILE, _AT_CALL_LINE = 0x58, 0x59
_AT_ADDR_BASE, _AT_RNGLISTS_BASE = 0x73, 0x74
_FORM_ADDR, _FORM_ADDRX = 0x01, (0x1B, 0x29, 0x2A, 0x2B, 0x2C)
_FORM_RNGLISTX = 0x23


class _AddrSpace:
    """Resolve addresses (and, in a .o, their section) for one unit."""

    def __init__(self, elf, addr_size, offset_size):
        self.elf = elf
        self.asz = addr_size
        self.osz = offset_size
        self.addr_base = 8 if offset_size == 4 else 16
        self.rnglists_base = 12 if offset_size == 4 else 20
        self.targets = elf.reloc_targets or {}

    def sec(self, name, offset):
        return self.targets.get(name, {}).get(offset)

    def addrx(self, index):
        data = self.elf.sections.get(".debug_addr", b"")
        off = self.addr_base + index * self.asz
        r = _Reader(data, self.elf.little, off, ".debug_addr")
        return r.uint(self.asz), self.sec(".debug_addr", off)

    def ranges(self, value, form, version, base):
        """[(start, end, section)] of a DW_AT_ranges value."""
        if version >= 5:
            data = self.elf.sections.get(".debug_rnglists", b"")
            if form == _FORM_RNGLISTX:
                r = _Reader(data, self.elf.little,
                            self.rnglists_base + value * self.osz,
                            ".debug_rnglists")
                off = self.rnglists_base + r.uint(self.osz)
            else:
                off = value
            return self._rnglist(data, off, base)
        return self._ranges_v4(self.elf.sections.get(".debug_ranges", b""),
                               value, base)

    def _rnglist(self, data, off, base):
        out = []
        r = _Reader(data, self.elf.little, off, ".debug_rnglists")
        b_addr, b_sec = base
        while True:
            kind = r.u8()
            if kind == 0:                                 # end_of_list
                return out
            if kind == 1:                                 # base_addressx
                b_addr, b_sec = self.addrx(r.uleb())
            elif kind == 2:                               # startx_endx
                (a, sa), (b, _sb) = self.addrx(r.uleb()), self.addrx(r.uleb())
                out.append((a, b, sa))
            elif kind == 3:                               # startx_length
                a, sa = self.addrx(r.uleb())
                out.append((a, a + r.uleb(), sa))
            elif kind == 4:                               # offset_pair
                start, end = r.uleb(), r.uleb()
                out.append((b_addr + start, b_addr + end, b_sec))
            elif kind == 5:                               # base_address
                pos = r.pos
                b_addr = r.uint(self.asz)
                b_sec = self.sec(".debug_rnglists", pos)
            elif kind in (6, 7):                          # start_end/_length
                pos = r.pos
                a = r.uint(self.asz)
                b = r.uint(self.asz) if kind == 6 else a + r.uleb()
                out.append((a, b, self.sec(".debug_rnglists", pos)))
            else:
                raise DwarfError("unknown DW_RLE kind %d" % kind)

    def _ranges_v4(self, data, off, base):
        out = []
        r = _Reader(data, self.elf.little, off, ".debug_ranges")
        b_addr, b_sec = base
        top = (1 << (8 * self.asz)) - 1
        while True:
            pos = r.pos
            start, end = r.uint(self.asz), r.uint(self.asz)
            if start == 0 and end == 0 and \
                    self.sec(".debug_ranges", pos) is None:
                return out
            if start == top:                              # base selection
                b_addr, b_sec = end, self.sec(".debug_ranges",
                                              pos + self.asz)
                continue
            sec = self.sec(".debug_ranges", pos)
            if sec is not None:                           # relocated pair
                out.append((start, end, sec))
            else:
                out.append((b_addr + start, b_addr + end, b_sec))


def iter_inline_call_sites(elf):
    """Yield (start, end, file, line, section) per inlined code range.

    One entry per address range of every DW_TAG_inlined_subroutine: its
    DW_AT_call_file/DW_AT_call_line is the caller's line that addr2line -i
    reports for any address in the range. `section` is known only in a
    relocatable object. Best effort per unit, like _unit_metadata: a unit
    that cannot be walked contributes nothing rather than stopping the rest.
    """
    info = elf.sections.get(".debug_info", b"")
    abbrev_data = elf.sections.get(".debug_abbrev", b"")
    line = elf.sections.get(".debug_line", b"")
    if not info or not abbrev_data or not line:
        return
    strings = (elf.sections.get(".debug_str", b""),
               elf.sections.get(".debug_line_str", b""))
    metadata = _unit_metadata(elf)
    abbrev_cache = {}
    r = _Reader(info, elf.little, 0, ".debug_info")
    while r.pos + 11 <= len(info):
        length = r.u32()
        offset_size = 4
        if length == 0xFFFFFFFF:
            offset_size = 8
            length = r.u64()
        elif length >= 0xFFFFFFF0 or length == 0:
            return
        unit_end = r.pos + length
        if unit_end > len(info):
            return
        out = []
        try:
            version = r.u16()
            if version >= 5:
                unit_type = r.u8()
                addr_size = r.u8()
                abbrev_off = r.uint(offset_size)
                if unit_type in (2, 6):
                    r.skip(8 + offset_size)
                elif unit_type in (4, 5):
                    r.skip(8)
            else:
                abbrev_off = r.uint(offset_size)
                addr_size = r.u8()
            if abbrev_off not in abbrev_cache:
                abbrev_cache[abbrev_off] = _parse_abbrev(
                    abbrev_data, abbrev_off, elf.little)
            abbrevs = abbrev_cache[abbrev_off]
            space = _AddrSpace(elf, addr_size, offset_size)
            header, file_cache, base = None, {}, (0, None)
            while r.pos < unit_end:
                code = r.uleb()
                if not code:
                    continue
                tag, attrs = abbrevs[code]
                vals = {}
                for attr, form, const in attrs:
                    pos = r.pos
                    vals[attr] = (form, pos, _read_form(
                        r, form, offset_size, addr_size, strings, const))
                if header is None and tag in (_TAG_COMPILE_UNIT,
                                              _TAG_SKELETON_UNIT):
                    for attr, target in ((_AT_ADDR_BASE, "addr_base"),
                                         (_AT_RNGLISTS_BASE,
                                          "rnglists_base")):
                        if isinstance(vals.get(attr, (0, 0, None))[2], int):
                            setattr(space, target, vals[attr][2])
                    base = _pc_value(space, vals.get(_AT_LOW_PC))
                    stmt = vals.get(_AT_STMT_LIST, (0, 0, None))[2]
                    if isinstance(stmt, int):
                        lr = _Reader(line, elf.little, stmt, ".debug_line")
                        header = _parse_header(lr, stmt, elf.little,
                                               elf.sections, metadata)
                    continue
                if tag != _TAG_INLINED_SUBROUTINE or header is None:
                    continue
                call_file = vals.get(_AT_CALL_FILE, (0, 0, None))[2]
                call_line = vals.get(_AT_CALL_LINE, (0, 0, None))[2]
                if not isinstance(call_file, int) or not call_line:
                    continue
                path = _resolve_file(header, call_file, file_cache)
                if path is None:
                    continue
                for start, end, sec in _die_ranges(space, vals, version,
                                                   base):
                    if end > start:
                        out.append((start, end, path, call_line, sec))
        except (DwarfError, struct.error, KeyError):
            out = []                        # one bad unit must not lose the rest
        r.pos = unit_end
        for item in out:
            yield item


def _pc_value(space, val):
    """(address, section) of a low_pc-style attribute value, or (0, None)."""
    if val is None:
        return 0, None
    form, pos, value = val
    if not isinstance(value, int):
        return 0, None
    if form in _FORM_ADDRX:
        return space.addrx(value)
    return value, space.sec(".debug_info", pos)


def _die_ranges(space, vals, version, base):
    if _AT_RANGES in vals:
        form, _pos, value = vals[_AT_RANGES]
        if isinstance(value, int):
            return space.ranges(value, form, version, base)
        return []
    if _AT_LOW_PC not in vals or _AT_HIGH_PC not in vals:
        return []
    low, sec = _pc_value(space, vals[_AT_LOW_PC])
    form, _pos, high = vals[_AT_HIGH_PC]
    if not isinstance(high, int):
        return []
    if form == _FORM_ADDR or form in _FORM_ADDRX:
        high = _pc_value(space, vals[_AT_HIGH_PC])[0]
    else:
        high = low + high                   # DWARF 4+: an offset from low
    return [(low, high, sec)]


def iter_coverable_lines(elf, section=None):
    """Yield (address, file, line, section): addr2line -i's view of the code.

    Per address the last line-table row (what addr2line reports), plus the
    call site of every inlined range -- the line set the objdump denominator
    gets by resolving each instruction with `addr2line -i`. In a linked image
    only addresses inside an executable section count: code the linker
    discarded keeps its debug info, relocated to (near) 0. With `section`,
    only that section's lines, as 0-based offsets into it.
    """
    if not isinstance(elf, ElfInfo):
        elf = read_elf(elf)
    want, base, end = _section_window(elf, section)

    def live(address, sec):
        if elf.relocatable:
            return sec is not None and (want is None or sec == want)
        if want is not None:
            return base <= address < end
        if not elf.exec_ranges:             # no section table to go by:
            return address != 0             # the address-0 rule alone
        return any(lo <= address < hi for lo, hi in elf.exec_ranges)

    last = {}
    data = elf.sections.get(".debug_line", b"")
    if not data:
        raise DwarfError("%s: no .debug_line section (build with -g?)"
                         % elf.path)
    for row in parse_line_section(data, elf.little, elf.sections,
                                  _unit_metadata(elf), elf.line_sections):
        if row.end_sequence or not row.line or row.file is None:
            continue
        if not live(row.address, row.section):
            continue
        key = (row.section, row.address)
        last.pop(key, None)                 # keep the LAST row, in order
        last[key] = (row.file, row.line)
    for (sec, address), (path, line) in last.items():
        yield address - base, path, line, sec
    for start, stop, path, line, sec in iter_inline_call_sites(elf):
        if live(start, sec):
            yield start - base, path, line, sec


def _section_window(elf, section):
    """(index, base, end) for a --section filter; (None, 0, None) without."""
    if section is None:
        return None, 0, None
    if section not in elf.section_names:
        raise DwarfError("%s: no section %s" % (elf.path, section))
    if elf.section_names.count(section) > 1:
        raise DwarfError("%s: several sections are named %s"
                         % (elf.path, section))
    want = elf.section_names.index(section)
    if elf.relocatable:
        return want, 0, None
    start, size = elf.section_addrs[want]
    return want, start, start + size


def iter_line_rows_by_section(elf, section=None):
    """Yield (address, file, line, section) for every real code row in an ELF.

    With `section`, only that section's rows, its addresses 0-based offsets
    into it -- the space `addr2line -j SECTION` works in. In a relocatable
    object each row's section comes from its sequence's relocated
    set_address; in a linked image, from the section's address range. The
    fourth field is the row's section index (relocatable objects; else None).

    `elf` is a path or an ElfInfo. Rows are filtered exactly the way the
    coverable denominator needs them:

      * `end_sequence` rows are dropped -- they mark the byte AFTER the last
        instruction of a sequence, so their address belongs to no instruction.
      * address 0 rows are dropped -- that is what a garbage-collected or
        unallocated section relocates to, not real code. Not in a
        relocatable object, where every section's first instruction is at 0.
      * LINE 0 rows are dropped. DWARF line 0 means "compiler-generated code
        belonging to no source line", and `addr2line` renders it as `file:?`,
        which the covered side already discards (its line regex needs a
        digit). Keeping them here would put lines the covered side can never
        report into the denominator -- 360 of them in one real picolibc image
        -- and LCOV has no line 0 to render them on either.
      * rows whose file index is not in the unit's file table are dropped.
    """
    if not isinstance(elf, ElfInfo):
        elf = read_elf(elf)
    data = elf.sections.get(".debug_line", b"")
    if not data:
        raise DwarfError("%s: no .debug_line section (build with -g?)"
                         % elf.path)
    metadata = _unit_metadata(elf)
    want, base, end = None, 0, None
    if section is not None:
        if section not in elf.section_names:
            raise DwarfError("%s: no section %s" % (elf.path, section))
        if elf.section_names.count(section) > 1:
            raise DwarfError("%s: several sections are named %s"
                             % (elf.path, section))
        want = elf.section_names.index(section)
        if not elf.relocatable:
            base, size = elf.section_addrs[want]
            end = base + size
    for row in parse_line_section(data, elf.little, elf.sections, metadata,
                                  elf.line_sections):
        if row.end_sequence or not row.line or row.file is None:
            continue
        if not row.address and not elf.relocatable:
            continue
        if want is not None:
            if elf.relocatable:
                if row.section != want:
                    continue
            elif not base <= row.address < end:
                continue
        yield row.address - base, row.file, row.line, row.section
