# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for the pure-stdlib DWARF `.debug_line` reader (tcgcov.dwarfline) and
the coverable denominator that is built from it (tcgcov.coverable).

Everything here is hermetic: the ELFs and line-number programs are built byte
by byte below, so the tests need no cross toolchain and cannot drift with one.
That matters because this reader's whole job is to be the fallback when the
toolchain-dependent path (objdump + addr2line) is unavailable or unparsable.

The reader was additionally cross-checked against
`readelf --debug-dump=decodedline` on real linked ELFs -- MicroBlaze (DWARF 5),
x86-64, RISC-V 64 and big-endian AArch64, at -gdwarf-2/3/4/5, plus 64-bit DWARF
and zlib-compressed debug sections -- and agreed row for row on every one.
"""

import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tcgcov import coverable, dwarfline  # noqa: E402
from tcgcov.dwarfline import DwarfError  # noqa: E402
from tcgcov.paths import PathOptions  # noqa: E402


# --------------------------------------------------------------------------
# Fixture builders: LEB128, line-number programs, ELF containers
# --------------------------------------------------------------------------

def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def sleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        done = (value == 0 and not byte & 0x40) or \
               (value == -1 and byte & 0x40)
        out.append(byte if done else byte | 0x80)
        if done:
            return bytes(out)


def pack(little, fmt, *args):
    return struct.pack(("<" if little else ">") + fmt, *args)


# Standard opcode operand counts for opcode_base 13 (DWARF 2-5 as emitted by
# every real producer).
STD_LENS = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]
LINE_BASE = -5
LINE_RANGE = 14
OPCODE_BASE = 13


class Program:
    """Byte-level builder for a line-number program."""

    def __init__(self, little=True):
        self.little = little
        self.buf = bytearray()

    def set_address(self, addr, size=4):
        self.buf += b"\x00" + uleb(1 + size) + b"\x02"
        self.buf += addr.to_bytes(size, "little" if self.little else "big")
        return self

    def copy(self):
        self.buf += b"\x01"
        return self

    def advance_pc(self, n):
        self.buf += b"\x02" + uleb(n)
        return self

    def advance_line(self, n):
        self.buf += b"\x03" + sleb(n)
        return self

    def set_file(self, n):
        self.buf += b"\x04" + uleb(n)
        return self

    def set_column(self, n):
        self.buf += b"\x05" + uleb(n)
        return self

    def negate_stmt(self):
        self.buf += b"\x06"
        return self

    def const_add_pc(self):
        self.buf += b"\x08"
        return self

    def fixed_advance_pc(self, n):
        self.buf += b"\x09" + pack(self.little, "H", n)
        return self

    def set_discriminator(self, n):
        payload = b"\x04" + uleb(n)
        self.buf += b"\x00" + uleb(len(payload)) + payload
        return self

    def special(self, addr_advance, line_advance):
        opcode = (line_advance - LINE_BASE) + LINE_RANGE * addr_advance \
            + OPCODE_BASE
        assert OPCODE_BASE <= opcode <= 255, opcode
        self.buf += bytes([opcode])
        return self

    def end_sequence(self):
        self.buf += b"\x00\x01\x01"
        return self

    @property
    def bytes(self):
        return bytes(self.buf)


CONST_ADD_PC_ADVANCE = (255 - OPCODE_BASE) // LINE_RANGE   # == 17


def line_unit_v4(program, version=4, little=True, dirs=(), files=(("a.c", 0),),
                 min_inst=1, dwarf64=False):
    """A complete DWARF 2/3/4 `.debug_line` unit."""
    body = bytearray()
    body += bytes([min_inst])
    if version >= 4:
        body += b"\x01"                     # maximum_operations_per_instruction
    body += b"\x01"                         # default_is_stmt
    body += struct.pack("b", LINE_BASE)
    body += bytes([LINE_RANGE, OPCODE_BASE])
    body += bytes(STD_LENS)
    for d in dirs:
        body += d.encode() + b"\0"
    body += b"\0"
    for name, dir_index in files:
        body += name.encode() + b"\0" + uleb(dir_index) + uleb(0) + uleb(0)
    body += b"\0"

    offset_size = 8 if dwarf64 else 4
    header_length = pack(little, "Q" if dwarf64 else "I", len(body))
    unit = pack(little, "H", version) + header_length + bytes(body) + program
    if dwarf64:
        return b"\xff\xff\xff\xff" + pack(little, "Q", len(unit)) + unit
    return pack(little, "I", len(unit)) + unit


DW_FORM_string = 0x08
DW_FORM_udata = 0x0F
DW_FORM_data16 = 0x1E
DW_LNCT_path = 0x01
DW_LNCT_directory_index = 0x02
DW_LNCT_MD5 = 0x05


def line_unit_v5(program, little=True, dirs=("/src",), files=(("a.c", 0),),
                 address_size=4, md5=False, min_inst=1, initial_file=0):
    """A complete DWARF 5 `.debug_line` unit.

    The v5 prologue is a different shape from v2-4: the directory and file
    tables are described by content-type/form descriptor lists instead of
    being NUL-terminated name lists, and both are indexed from 0.

    The state machine's `file` register still starts at 1 in DWARF 5, so a
    real v5 producer emits an explicit DW_LNS_set_file to reach entry 0.
    `initial_file` prepends that opcode (pass None to leave the register at
    its default and test that default).
    """
    if initial_file is not None:
        program = b"\x04" + uleb(initial_file) + program
    body = bytearray()
    body += bytes([min_inst, 1, 1])         # min_inst, max_ops, default_is_stmt
    body += struct.pack("b", LINE_BASE)
    body += bytes([LINE_RANGE, OPCODE_BASE])
    body += bytes(STD_LENS)

    body += b"\x01" + uleb(DW_LNCT_path) + uleb(DW_FORM_string)
    body += uleb(len(dirs))
    for d in dirs:
        body += d.encode() + b"\0"

    formats = [(DW_LNCT_path, DW_FORM_string),
               (DW_LNCT_directory_index, DW_FORM_udata)]
    if md5:
        formats.append((DW_LNCT_MD5, DW_FORM_data16))
    body += bytes([len(formats)])
    for content, form in formats:
        body += uleb(content) + uleb(form)
    body += uleb(len(files))
    for name, dir_index in files:
        body += name.encode() + b"\0" + uleb(dir_index)
        if md5:
            body += bytes(16)

    unit = (pack(little, "H", 5) + bytes([address_size, 0])
            + pack(little, "I", len(body)) + bytes(body) + program)
    return pack(little, "I", len(unit)) + unit


def build_elf(sections, little=True, is64=False):
    """Assemble a minimal ELF carrying `sections` ({name: bytes}, ordered)."""
    names = list(sections)
    shstrtab = bytearray(b"\0")
    name_off = {}
    for n in names + [".shstrtab"]:
        name_off[n] = len(shstrtab)
        shstrtab += n.encode() + b"\0"
    all_sections = list(sections.items()) + [(".shstrtab", bytes(shstrtab))]

    ehsize = 64 if is64 else 52
    shentsize = 64 if is64 else 40
    offset = ehsize
    placed = []
    for name, data in all_sections:
        placed.append((name, data, offset))
        offset += len(data)
    shoff = offset

    out = bytearray()
    ident = (b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1])
             + bytes(9))
    shnum = len(all_sections) + 1           # + the SHT_NULL section 0
    shstrndx = shnum - 1
    if is64:
        out += pack(little, "16sHHIQQQIHHHHHH", ident, 2, 0x3E, 1, 0, 0,
                    shoff, 0, ehsize, 0, 0, shentsize, shnum, shstrndx)
    else:
        out += pack(little, "16sHHIIIIIHHHHHH", ident, 2, 0xBD, 1, 0, 0,
                    shoff, 0, ehsize, 0, 0, shentsize, shnum, shstrndx)
    for _name, data, _off in placed:
        out += data

    def shdr(name_index, sh_type, off, size, link=0, entsize=0):
        if is64:
            return pack(little, "IIQQQQIIQQ", name_index, sh_type, 0, 0, off,
                        size, link, 0, 1, entsize)
        return pack(little, "IIIIIIIIII", name_index, sh_type, 0, 0, off, size,
                    link, 0, 1, entsize)

    out += shdr(0, 0, 0, 0)                 # SHT_NULL
    strtab_index = {n: i + 1 for i, (n, _d, _o) in enumerate(placed)}
    for name, data, off in placed:
        sh_type = 3 if name in (".shstrtab", ".strtab") else 1
        link = entsize = 0
        if name == ".symtab":
            sh_type = 2
            link = strtab_index.get(".strtab", 0)
            entsize = 24 if is64 else 16
        out += shdr(name_off[name], sh_type, off, len(data), link, entsize)
    return bytes(out)


def build_symtab(funcs, little=True, is64=False):
    """({name: (address, size)}) -> (.symtab bytes, .strtab bytes)."""
    strtab = bytearray(b"\0")
    symtab = bytearray(bytes(24 if is64 else 16))   # the null symbol
    for name, (addr, size) in funcs.items():
        off = len(strtab)
        strtab += name.encode() + b"\0"
        if is64:
            symtab += pack(little, "IBBHQQ", off, 0x12, 0, 1, addr, size)
        else:
            symtab += pack(little, "IIIBBH", off, addr, size, 0x12, 0, 1)
    return bytes(symtab), bytes(strtab)


def rows_of(section, little=True, sections=None, metadata=None):
    return list(dwarfline.parse_line_section(section, little, sections,
                                             metadata))


# --------------------------------------------------------------------------
# The line-number program state machine
# --------------------------------------------------------------------------

class TestLineProgramV4(unittest.TestCase):
    """DWARF 4 header shape and the standard/special/extended opcodes."""

    def program(self, little=True):
        p = Program(little)
        p.set_address(0x1000).copy()                # 0x1000 line 1
        p.advance_line(9).advance_pc(4).copy()      # 0x1004 line 10
        p.special(2, 1)                             # 0x1006 line 11
        p.const_add_pc().copy()                     # 0x1017 line 11
        p.advance_line(-5).fixed_advance_pc(0x10).copy()   # 0x1027 line 6
        p.advance_pc(4).end_sequence()              # 0x102b end_sequence
        return p.bytes

    def test_little_endian(self):
        section = line_unit_v4(self.program(True), little=True)
        rows = rows_of(section, little=True)
        self.assertEqual(
            [(r.address, r.line, r.end_sequence) for r in rows],
            [(0x1000, 1, False), (0x1004, 10, False), (0x1006, 11, False),
             (0x1017, 11, False), (0x1027, 6, False), (0x102B, 6, True)])

    def test_big_endian_gives_the_same_rows(self):
        # Cross-target work means neither endianness may be assumed; the same
        # logical program must decode identically from big-endian bytes.
        le = rows_of(line_unit_v4(self.program(True), little=True), True)
        be = rows_of(line_unit_v4(self.program(False), little=False), False)
        self.assertEqual(le, be)

    def test_dwarf2_and_3_have_no_max_ops_byte(self):
        for version in (2, 3):
            section = line_unit_v4(self.program(), version=version)
            rows = rows_of(section)
            self.assertEqual([(r.address, r.line) for r in rows[:3]],
                             [(0x1000, 1), (0x1004, 10), (0x1006, 11)],
                             "version %d" % version)

    def test_minimum_instruction_length_scales_advances(self):
        p = Program()
        p.set_address(0x100).copy().advance_pc(3).copy()
        rows = rows_of(line_unit_v4(p.bytes, min_inst=4))
        self.assertEqual([r.address for r in rows], [0x100, 0x10C])

    def test_set_file_selects_from_the_file_table(self):
        p = Program()
        p.set_address(0x10).copy().set_file(2).copy().end_sequence()
        section = line_unit_v4(p.bytes, dirs=("/inc",),
                               files=(("a.c", 0), ("b.h", 1)))
        rows = rows_of(section)
        self.assertEqual(rows[0].file, "a.c")
        self.assertEqual(rows[1].file, "/inc/b.h")

    def test_file_index_zero_is_not_in_the_v4_table(self):
        # In DWARF <= 4 file numbering starts at 1 and 0 means "the unit's
        # primary source file", which the table does not contain.
        p = Program()
        p.set_address(0x10).set_file(0).copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertIsNone(rows[0].file)

    def test_unknown_extended_opcode_is_skipped_by_its_length(self):
        p = Program()
        p.set_address(0x40).copy()
        # A vendor extended opcode (0x80) with a four-byte payload.
        p.buf += b"\x00" + uleb(5) + b"\x80\xde\xad\xbe\xef"
        p.copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertEqual([r.address for r in rows], [0x40, 0x40, 0x40])

    def test_set_discriminator_does_not_disturb_the_row(self):
        p = Program()
        p.set_address(0x40).set_discriminator(3).copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertEqual((rows[0].address, rows[0].line), (0x40, 1))

    def test_negate_stmt_is_reported(self):
        p = Program()
        p.set_address(0x40).copy().negate_stmt().copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertEqual([r.is_stmt for r in rows[:2]], [True, False])

    def test_end_sequence_resets_the_state(self):
        p = Program()
        p.set_address(0x10).advance_line(4).copy().end_sequence()
        p.set_address(0x2000).copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertEqual([(r.address, r.line) for r in rows],
                         [(0x10, 5), (0x10, 5), (0x2000, 1), (0x2000, 1)])

    def test_eight_byte_set_address(self):
        p = Program()
        p.set_address(0x7FFFFFFF1000, size=8).copy().end_sequence()
        rows = rows_of(line_unit_v4(p.bytes))
        self.assertEqual(rows[0].address, 0x7FFFFFFF1000)

    def test_two_units_in_one_section(self):
        a = line_unit_v4(Program().set_address(0x10).copy()
                         .end_sequence().bytes, files=(("a.c", 0),))
        b = line_unit_v4(Program().set_address(0x20).copy()
                         .end_sequence().bytes, files=(("b.c", 0),))
        rows = [r for r in rows_of(a + b) if not r.end_sequence]
        self.assertEqual([(r.address, r.file) for r in rows],
                         [(0x10, "a.c"), (0x20, "b.c")])

    def test_dwarf64_initial_length_escape(self):
        section = line_unit_v4(self.program(), dwarf64=True)
        rows = rows_of(section)
        self.assertEqual([(r.address, r.line) for r in rows[:2]],
                         [(0x1000, 1), (0x1004, 10)])


class TestLineProgramV5(unittest.TestCase):
    """DWARF 5's differently shaped prologue must decode to the same rows."""

    def test_v5_directory_and_file_tables(self):
        p = Program()
        p.set_address(0x2000).advance_line(41).copy()
        p.set_file(1).advance_line(1).advance_pc(8).copy()
        p.end_sequence()
        section = line_unit_v5(p.bytes, dirs=("/src", "/src/inc"),
                               files=(("a.c", 0), ("b.h", 1)))
        rows = [r for r in rows_of(section) if not r.end_sequence]
        self.assertEqual([(r.address, r.file, r.line) for r in rows],
                         [(0x2000, "/src/a.c", 42),
                          (0x2008, "/src/inc/b.h", 43)])

    def test_v5_file_index_zero_is_a_real_entry(self):
        # The v5 change that most often breaks a reader written for v4: both
        # tables are indexed from 0, and entry 0 is the primary source file
        # (in v4, index 0 is not in the table at all). The `file` register
        # still starts at 1, so entry 0 is only reached by an explicit
        # DW_LNS_set_file -- which is exactly what clang emits.
        files = (("main.c", 0), ("other.c", 0))
        p = Program().set_address(0x10).copy().end_sequence()
        default = line_unit_v5(p.bytes, files=files, initial_file=None)
        self.assertEqual(rows_of(default)[0].file, "/src/other.c")
        explicit = line_unit_v5(p.bytes, files=files, initial_file=0)
        self.assertEqual(rows_of(explicit)[0].file, "/src/main.c")

    def test_v5_directory_zero_is_the_compilation_directory(self):
        p = Program().set_address(0x10).copy().end_sequence()
        section = line_unit_v5(p.bytes, dirs=("/build/root", "rel/dir"),
                               files=(("a.c", 1),))
        self.assertEqual(rows_of(section)[0].file, "/build/root/rel/dir/a.c")

    def test_v5_absolute_file_name_is_used_as_is(self):
        # What GCC/Clang actually emit for an absolute -c argument, and what
        # addr2line reports: comp_dir is NOT prepended to an absolute name.
        p = Program().set_address(0x10).copy().end_sequence()
        section = line_unit_v5(p.bytes, dirs=("/build/root",),
                               files=(("/elsewhere/a.c", 0),))
        self.assertEqual(rows_of(section)[0].file, "/elsewhere/a.c")

    def test_v5_md5_column_is_skipped(self):
        p = Program().set_address(0x10).copy().end_sequence()
        section = line_unit_v5(p.bytes, md5=True)
        self.assertEqual(rows_of(section)[0].file, "/src/a.c")

    def test_v5_big_endian(self):
        p = Program(little=False).set_address(0x2000).copy().end_sequence()
        section = line_unit_v5(p.bytes, little=False)
        rows = rows_of(section, little=False)
        self.assertEqual((rows[0].address, rows[0].file), (0x2000, "/src/a.c"))

    def test_v5_eight_byte_address_size(self):
        p = Program().set_address(0xFFFF000010, size=8).copy().end_sequence()
        section = line_unit_v5(p.bytes, address_size=8)
        self.assertEqual(rows_of(section)[0].address, 0xFFFF000010)


class TestUnsupportedVersion(unittest.TestCase):
    """An unknown version must SAY SO, not quietly produce nothing.

    A silent empty result is the exact failure this module exists to prevent:
    an empty coverable inventory makes every downstream report read 100%.
    """

    def _section(self, version):
        section = bytearray(line_unit_v4(
            Program().set_address(0x10).copy().end_sequence().bytes))
        section[4:6] = struct.pack("<H", version)
        return bytes(section)

    def test_future_version_raises_naming_the_version(self):
        for version in (6, 7, 0x1234):
            with self.assertRaises(DwarfError) as cm:
                rows_of(self._section(version))
            message = str(cm.exception)
            self.assertIn(str(version), message)
            self.assertIn("unsupported", message.lower())
            self.assertIn("2, 3, 4, 5", message)

    def test_version_one_raises_too(self):
        with self.assertRaises(DwarfError):
            rows_of(self._section(1))

    def test_dwarf_error_is_a_runtime_error(self):
        # coverable.run already catches (OSError, RuntimeError) around the
        # objdump path; the DWARF path must land in the same net.
        self.assertTrue(issubclass(DwarfError, RuntimeError))

    def test_truncated_unit_raises(self):
        section = line_unit_v4(
            Program().set_address(0x10).copy().end_sequence().bytes)
        with self.assertRaises(DwarfError):
            rows_of(section[:len(section) - 6])


# --------------------------------------------------------------------------
# The ELF container
# --------------------------------------------------------------------------

def write_elf(tmpdir, name, sections, little=True, is64=False):
    path = os.path.join(tmpdir, name)
    with open(path, "wb") as f:
        f.write(build_elf(sections, little, is64))
    return path


class TestElfContainer(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _unit(self, little=True, addr=0x8000):
        p = Program(little)
        p.set_address(addr).advance_line(6).copy()
        p.advance_pc(4).special(0, 1)
        p.advance_pc(4).end_sequence()
        return line_unit_v5(p.bytes, little=little, dirs=("/src",),
                            files=(("a.c", 0),))

    def test_all_four_elf_shapes(self):
        for is64 in (False, True):
            for little in (True, False):
                path = write_elf(
                    self.tmp, "t-%d-%d.elf" % (is64, little),
                    {".debug_line": self._unit(little)}, little, is64)
                elf = dwarfline.read_elf(path)
                self.assertEqual((elf.is64, elf.little), (is64, little))
                self.assertEqual(
                    list(dwarfline.iter_line_rows(path)),
                    [(0x8000, "/src/a.c", 7), (0x8004, "/src/a.c", 8)],
                    "is64=%s little=%s" % (is64, little))

    def test_end_sequence_rows_are_excluded(self):
        # The end_sequence address is one past the last instruction of the
        # sequence, so counting it would add a line no instruction occupies.
        path = write_elf(self.tmp, "es.elf", {".debug_line": self._unit()})
        raw = rows_of(self._unit())
        self.assertTrue(any(r.end_sequence for r in raw))
        self.assertEqual(len(list(dwarfline.iter_line_rows(path))),
                         len(raw) - 1)
        self.assertNotIn(0x8008, [a for a, _f, _l in
                                  dwarfline.iter_line_rows(path)])

    def test_address_zero_rows_are_excluded(self):
        # A garbage-collected or unallocated section relocates to 0; those
        # rows are not code.
        p = Program()
        p.set_address(0).copy().advance_pc(4).copy().end_sequence()
        # end_sequence resets the file register to 1, so the next sequence
        # selects entry 0 again the way a real producer does.
        p.set_file(0).set_address(0x9000).copy().end_sequence()
        path = write_elf(self.tmp, "z.elf",
                         {".debug_line": line_unit_v5(p.bytes)})
        self.assertEqual([a for a, _f, _l in dwarfline.iter_line_rows(path)],
                         [4, 0x9000])

    def test_line_zero_rows_are_excluded(self):
        # DWARF line 0 is "compiler-generated code, no source line", and
        # addr2line renders it as `file:?`, which the covered side discards.
        # Keeping it here would add denominator lines the covered side can
        # never report -- 360 of them in one real picolibc image.
        p = Program()
        p.set_address(0x100).copy()          # line 1
        p.advance_line(-1).advance_pc(4).copy()      # line 0
        p.advance_line(7).advance_pc(4).copy()       # line 7
        p.end_sequence()
        path = write_elf(self.tmp, "l0.elf",
                         {".debug_line": line_unit_v5(p.bytes)})
        self.assertEqual([(a, ln) for a, _f, ln in
                          dwarfline.iter_line_rows(path)],
                         [(0x100, 1), (0x108, 7)])
        # The raw parser still reports it; only the filtered view drops it.
        self.assertIn(0, [r.line for r in rows_of(line_unit_v5(p.bytes))])

    def test_missing_debug_line_is_a_clear_error(self):
        path = write_elf(self.tmp, "nodwarf.elf", {".text": b"\x00" * 8})
        with self.assertRaises(DwarfError) as cm:
            list(dwarfline.iter_line_rows(path))
        self.assertIn(".debug_line", str(cm.exception))

    def test_not_an_elf(self):
        path = os.path.join(self.tmp, "junk")
        with open(path, "wb") as f:
            f.write(b"not an elf at all")
        with self.assertRaises(DwarfError):
            dwarfline.read_elf(path)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            dwarfline.read_elf(os.path.join(self.tmp, "nope.elf"))

    def test_comp_dir_comes_from_debug_info_for_v4(self):
        # DWARF 2-4 file tables carry no comp_dir, so a relative name can only
        # be made absolute -- i.e. made to match what addr2line prints -- by
        # reading DW_AT_comp_dir out of the compilation unit.
        line = line_unit_v4(
            Program().set_address(0x100).copy().end_sequence().bytes,
            files=(("a.c", 0),))
        info, abbrev = build_debug_info_v4("/work/proj", stmt_list=0)
        path = write_elf(self.tmp, "cd.elf", {".debug_line": line,
                                              ".debug_info": info,
                                              ".debug_abbrev": abbrev})
        self.assertEqual(list(dwarfline.iter_line_rows(path)),
                         [(0x100, "/work/proj/a.c", 1)])

    def test_relative_directory_is_joined_under_comp_dir(self):
        line = line_unit_v4(
            Program().set_address(0x100).copy().end_sequence().bytes,
            dirs=("sub",), files=(("a.c", 1),))
        info, abbrev = build_debug_info_v4("/work/proj", stmt_list=0)
        path = write_elf(self.tmp, "cd2.elf", {".debug_line": line,
                                               ".debug_info": info,
                                               ".debug_abbrev": abbrev})
        self.assertEqual(list(dwarfline.iter_line_rows(path))[0][1],
                         "/work/proj/sub/a.c")

    def test_unparsable_debug_info_does_not_stop_the_line_table(self):
        line = line_unit_v4(
            Program().set_address(0x100).copy().end_sequence().bytes)
        path = write_elf(self.tmp, "bad.elf",
                         {".debug_line": line,
                          ".debug_info": b"\x10\x00\x00\x00garbage-garbage",
                          ".debug_abbrev": b"\x01\x02\x03"})
        self.assertEqual(list(dwarfline.iter_line_rows(path)),
                         [(0x100, "a.c", 1)])


def build_debug_info_v4(comp_dir, stmt_list=0, little=True):
    """A one-DIE `.debug_info`/`.debug_abbrev` pair carrying DW_AT_comp_dir."""
    DW_TAG_compile_unit = 0x11
    DW_AT_stmt_list, DW_AT_comp_dir = 0x10, 0x1B
    DW_FORM_sec_offset, DW_FORM_string = 0x17, 0x08
    abbrev = (uleb(1) + uleb(DW_TAG_compile_unit) + b"\x00"
              + uleb(DW_AT_stmt_list) + uleb(DW_FORM_sec_offset)
              + uleb(DW_AT_comp_dir) + uleb(DW_FORM_string)
              + uleb(0) + uleb(0) + uleb(0))
    die = (uleb(1) + pack(little, "I", stmt_list)
           + comp_dir.encode() + b"\0")
    body = pack(little, "H", 4) + pack(little, "I", 0) + b"\x04" + die
    return pack(little, "I", len(body)) + body, abbrev


class TestFunctionIndex(unittest.TestCase):
    """Function names for the DWARF denominator come from `.symtab`."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _index(self, little=True, is64=False):
        symtab, strtab = build_symtab(
            {"first": (0x1000, 0x20), "second": (0x1020, 0x10)},
            little, is64)
        path = write_elf(self.tmp, "sym-%d-%d.elf" % (little, is64),
                         {".debug_line": b"", ".symtab": symtab,
                          ".strtab": strtab}, little, is64)
        return dwarfline.FunctionIndex(dwarfline.read_elf(path))

    def test_lookup(self):
        for little in (True, False):
            for is64 in (False, True):
                idx = self._index(little, is64)
                self.assertEqual(idx.at(0x1000), "first")
                self.assertEqual(idx.at(0x101F), "first")
                self.assertEqual(idx.at(0x1020), "second")
                self.assertEqual(idx.at(0x102F), "second")

    def test_address_outside_every_symbol(self):
        idx = self._index()
        self.assertEqual(idx.at(0x0FFF), "")
        self.assertEqual(idx.at(0x9999), "")

    def test_no_symtab_is_not_an_error(self):
        path = write_elf(self.tmp, "nosym.elf", {".debug_line": b""})
        self.assertEqual(
            dwarfline.FunctionIndex(dwarfline.read_elf(path)).at(0x10), "")


# --------------------------------------------------------------------------
# The coverable denominator: source selection, fallback, key parity
# --------------------------------------------------------------------------

FAKE_OBJDUMP = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "sys.stdout.write(%r)\n"
)

# Reads the addresses tcgcov feeds it on stdin and answers from a table, in
# exactly the layout `addr2line -a -f -C -i` produces.
FAKE_ADDR2LINE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "table = %r\n"
    "for line in sys.stdin.read().split():\n"
    "    addr = int(line, 16)\n"
    "    sys.stdout.write('0x%%x\\n' %% addr)\n"
    "    entry = table.get(addr)\n"
    "    if entry is None:\n"
    "        sys.stdout.write('??\\n??:0\\n')\n"
    "    else:\n"
    "        sys.stdout.write('%%s\\n%%s:%%d\\n' %% entry)\n"
)


def make_script(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


class TestDenominatorSources(unittest.TestCase):
    """`--denominator objdump|dwarf|auto` and the fallback between them."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.root = os.path.join(self.tmp, "src")
        self.source = os.path.join(self.root, "mod", "a.c")
        # Two instructions, two source lines, one file -- built so that both
        # denominator sources see exactly the same code.
        self.addrs = {0x9000: 10, 0x9004: 11}
        p = Program()
        p.set_address(0x9000).advance_line(9).copy()
        p.advance_pc(4).special(0, 1)
        p.advance_pc(4).end_sequence()
        unit = line_unit_v5(p.bytes, dirs=(self.root,),
                            files=((os.path.join("mod", "a.c"), 0),))
        symtab, strtab = build_symtab({"f": (0x9000, 0x10)})
        self.elf = write_elf(self.tmp, "t.elf",
                             {".debug_line": unit, ".symtab": symtab,
                              ".strtab": strtab})
        self.objdump = make_script(self.tmp, "fake-objdump", FAKE_OBJDUMP % (
            "t.elf:     file format elf32-microblazeel\n"
            "\nDisassembly of section .text:\n\n"
            "00009000 <f>:\n"
            "    9000:\t3021ffe0 \taddik\tr1, r1, -32\n"
            "    9004:\tb60f0008 \trtsd\tr15, 8\n"))
        self.addr2line = make_script(
            self.tmp, "fake-addr2line",
            FAKE_ADDR2LINE % {a: ("f", self.source, ln)
                              for a, ln in self.addrs.items()})

    def run_coverable(self, *extra, **kw):
        out = os.path.join(self.tmp, kw.pop("out", "cov.jsonl"))
        argv = ["--elf", self.elf, "--out", out,
                "--objdump", kw.pop("objdump", self.objdump),
                "--addr2line", kw.pop("addr2line", self.addr2line),
                "--source-root", self.root] + list(extra)
        err = io.StringIO()
        with redirect_stderr(err):
            rc = coverable.main(argv)
        records = []
        if os.path.exists(out):
            with open(out) as f:
                records = [json.loads(line) for line in f if line.strip()]
        return rc, records, err.getvalue()

    def keys(self, records):
        return {(r["file"], r["line"]) for r in records}

    def test_objdump_source(self):
        rc, records, _err = self.run_coverable("--denominator", "objdump")
        self.assertEqual(rc, 0)
        self.assertEqual(self.keys(records),
                         {(os.path.join("mod", "a.c"), 10),
                          (os.path.join("mod", "a.c"), 11)})
        self.assertEqual({r["denominator"] for r in records}, {"objdump"})

    def test_dwarf_source(self):
        rc, records, _err = self.run_coverable("--denominator", "dwarf")
        self.assertEqual(rc, 0)
        self.assertEqual({r["denominator"] for r in records}, {"dwarf"})
        self.assertEqual({r["function"] for r in records}, {"f"})

    def test_the_two_sources_produce_identical_keys(self):
        """The point of the whole exercise: covered ⊆ coverable must hold.

        The covered side always resolves through addr2line, so a denominator
        that came from somewhere else has to normalize to exactly the same
        (file, line) keys or the merge is silently wrong.
        """
        _rc, objdump_records, _e = self.run_coverable(
            "--denominator", "objdump", out="o.jsonl")
        _rc, dwarf_records, _e = self.run_coverable(
            "--denominator", "dwarf", out="d.jsonl")
        self.assertEqual(self.keys(objdump_records), self.keys(dwarf_records))
        self.assertTrue(self.keys(objdump_records))

    def test_key_parity_holds_for_every_path_mode(self):
        for extra in (["--all-paths"], ["--keep", "/mod/"], []):
            _rc, o, _e = self.run_coverable("--denominator", "objdump",
                                            *extra, out="o2.jsonl")
            _rc, d, _e = self.run_coverable("--denominator", "dwarf",
                                            *extra, out="d2.jsonl")
            self.assertEqual(self.keys(o), self.keys(d), "options %r" % extra)
            self.assertTrue(self.keys(o), "options %r" % extra)

    def test_exclusions_apply_to_the_dwarf_source_too(self):
        rc, _records, err = self.run_coverable(
            "--denominator", "dwarf", "--exclude", "mod/**")
        self.assertNotEqual(rc, 0)
        self.assertIn("Refusing to write an empty coverable inventory", err)

    def test_auto_prefers_objdump(self):
        _rc, records, _err = self.run_coverable("--denominator", "auto")
        self.assertEqual({r["denominator"] for r in records}, {"objdump"})

    def test_auto_falls_back_when_the_disassembly_is_unparsable(self):
        # The real bug: llvm-objdump's layout parsed to zero addresses, which
        # silently emptied the denominator. It later became a hard error --
        # honest, but still no coverage. Now it degrades to DWARF.
        broken = make_script(self.tmp, "broken-objdump", FAKE_OBJDUMP % (
            "t.elf:     file format elf32-microblazeel\n"
            "lots of output\nthat parses to nothing\n"))
        rc, records, err = self.run_coverable("--denominator", "auto",
                                              objdump=broken)
        self.assertEqual(rc, 0)
        self.assertEqual({r["denominator"] for r in records}, {"dwarf"})
        self.assertIn("falling back to the DWARF", err)
        self.assertEqual(self.keys(records),
                         {(os.path.join("mod", "a.c"), 10),
                          (os.path.join("mod", "a.c"), 11)})

    def test_auto_falls_back_when_objdump_is_missing(self):
        rc, records, err = self.run_coverable(
            "--denominator", "auto",
            objdump=os.path.join(self.tmp, "no-such-objdump"))
        self.assertEqual(rc, 0)
        self.assertEqual({r["denominator"] for r in records}, {"dwarf"})
        self.assertIn("objdump denominator is unavailable", err)

    def test_explicit_objdump_still_refuses_an_empty_inventory(self):
        # --denominator objdump must NOT quietly fall back: asking for the
        # conservative source and getting the broad one is a different answer.
        broken = make_script(self.tmp, "broken2-objdump", FAKE_OBJDUMP % (
            "t.elf:     file format elf32-microblazeel\n"
            "lots of output\nthat parses to nothing\n"))
        rc, records, err = self.run_coverable("--denominator", "objdump",
                                              objdump=broken)
        self.assertNotEqual(rc, 0)
        self.assertEqual(records, [])
        self.assertIn("unrecognized disassembly layout", err)

    def test_dwarf_source_needs_neither_objdump_nor_addr2line(self):
        out = os.path.join(self.tmp, "no-toolchain.jsonl")
        err = io.StringIO()
        with redirect_stderr(err):
            rc = coverable.main(["--elf", self.elf, "--out", out,
                                 "--toolchain-prefix", "definitely-not-a-tool-",
                                 "--source-root", self.root,
                                 "--denominator", "dwarf"])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.getsize(out) > 0)

    def test_dwarf_source_reports_a_missing_line_table(self):
        bare = write_elf(self.tmp, "bare.elf", {".text": b"\x00" * 4})
        err = io.StringIO()
        with redirect_stderr(err):
            rc = coverable.main(["--elf", bare, "--out",
                                 os.path.join(self.tmp, "bare.jsonl"),
                                 "--all-paths", "--denominator", "dwarf"])
        self.assertEqual(rc, 1)
        self.assertIn(".debug_line", err.getvalue())

    def test_cross_check_is_quiet_when_the_sources_agree(self):
        _rc, _records, err = self.run_coverable("--denominator", "objdump")
        self.assertNotIn("warning:", err)

    def _disagreeing_toolchain(self, tag):
        """An objdump/addr2line pair that answers about other source lines.

        This is what a silently-wrong parser looks like from the outside: it
        produces plenty of plausible output that has nothing to do with the
        line table.
        """
        addrs = range(0xA000, 0xA100, 4)
        objdump = make_script(self.tmp, tag + "-objdump", FAKE_OBJDUMP % (
            "t.elf:     file format elf32-microblazeel\n"
            "0000a000 <f>:\n"
            + "".join("    %x:\t3021ffe0 \taddik\tr1, r1, -32\n" % a
                      for a in addrs)))
        addr2line = make_script(
            self.tmp, tag + "-addr2line",
            FAKE_ADDR2LINE % {a: ("f", self.source, 500 + i)
                              for i, a in enumerate(addrs)})
        return objdump, addr2line

    def test_cross_check_warns_when_they_disagree(self):
        objdump, addr2line = self._disagreeing_toolchain("odd")
        _rc, records, err = self.run_coverable(
            "--denominator", "objdump", objdump=objdump, addr2line=addr2line)
        self.assertTrue(records)            # it still writes the inventory
        self.assertIn("warning:", err)
        self.assertIn("share NO source line", err)

    def test_no_cross_check_silences_it(self):
        objdump, addr2line = self._disagreeing_toolchain("odd2")
        _rc, _records, err = self.run_coverable(
            "--denominator", "objdump", "--no-cross-check",
            objdump=objdump, addr2line=addr2line)
        self.assertNotIn("warning:", err)


class TestCrossCheckMessages(unittest.TestCase):
    """The comparison itself, without the CLI around it."""

    def inventory(self, lines, path="a.c"):
        return {(path, ln, "f"): 0x1000 + ln for ln in lines}

    def test_agreement_is_silent(self):
        a = self.inventory(range(1, 40))
        self.assertEqual(coverable.cross_check_messages(a, dict(a)), [])

    def test_small_differences_are_tolerated(self):
        # addr2line -i adds inlined call sites the line table never names, so
        # exact agreement is not expected and must not warn.
        a = self.inventory(range(1, 100))
        b = self.inventory(range(1, 96))
        self.assertEqual(coverable.cross_check_messages(a, b), [])

    def test_dwarf_only_lines_are_reported(self):
        a = self.inventory(range(1, 20))
        b = self.inventory(range(1, 60))
        msgs = coverable.cross_check_messages(a, b)
        self.assertTrue(any("DWARF line table names" in m for m in msgs))

    def test_disjoint_sets_name_the_real_cause(self):
        a = self.inventory(range(1, 30), "a.c")
        b = self.inventory(range(1, 30), "b.c")
        msgs = coverable.cross_check_messages(a, b)
        self.assertEqual(len(msgs), 1)
        self.assertIn("path-normalization mismatch", msgs[0])

    def test_an_empty_side_says_nothing(self):
        self.assertEqual(
            coverable.cross_check_messages({}, self.inventory([1, 2])), [])


class TestNormalizationParity(unittest.TestCase):
    """dwarf_inventory must normalize through the very same machinery.

    Not "an equivalent path" -- the same paths.normalize_path call with the
    same PathOptions bundle, because any divergence here breaks
    covered ⊆ coverable in a way no test downstream would notice.
    """

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp())

    def _elf(self, comp_dir, name, dir_index=0, dirs=None):
        p = Program().set_address(0x100).copy().end_sequence()
        unit = line_unit_v5(p.bytes, dirs=dirs or (comp_dir,),
                            files=((name, dir_index),))
        return write_elf(self.tmp, "n.elf", {".debug_line": unit})

    def test_same_normalizer_same_result(self):
        from tcgcov.paths import normalize_path
        root = os.path.join(self.tmp, "proj")
        elf = self._elf(root, os.path.join("lib", "x.c"))
        opts = PathOptions(root, (), (), (), False)

        class Args:
            pass
        args = Args()
        args.elf = elf
        seen, rows = coverable.dwarf_inventory(args, opts)
        self.assertEqual(rows, 1)
        raw = os.path.join(root, "lib", "x.c")
        expected = normalize_path(raw, opts.source_root, opts.markers,
                                  opts.roots, opts.excludes, opts.all_paths)
        self.assertEqual({k[0] for k in seen}, {expected})
        self.assertEqual(expected, os.path.join("lib", "x.c"))

    def test_paths_outside_the_source_root_are_dropped(self):
        elf = self._elf("/opt/toolchain/include", "stdio.h")
        opts = PathOptions(os.path.join(self.tmp, "proj"), (), (), (), False)

        class Args:
            pass
        args = Args()
        args.elf = elf
        seen, rows = coverable.dwarf_inventory(args, opts)
        self.assertEqual(rows, 1)
        self.assertEqual(seen, {})

    def test_dotdot_in_a_dwarf_path_resolves_like_addr2line(self):
        # A relative -c argument makes the compiler record comp_dir + '../x',
        # which addr2line prints verbatim and normalize_path realpath()s. Both
        # sides must land on the same key.
        from tcgcov.paths import normalize_path
        root = os.path.join(self.tmp, "proj")
        elf = self._elf(os.path.join(root, "build"),
                        os.path.join("..", "lib", "x.c"))
        opts = PathOptions(root, (), (), (), False)

        class Args:
            pass
        args = Args()
        args.elf = elf
        seen, _rows = coverable.dwarf_inventory(args, opts)
        addr2line_style = os.path.join(root, "build", "..", "lib", "x.c")
        self.assertEqual(
            {k[0] for k in seen},
            {normalize_path(addr2line_style, opts.source_root, opts.markers,
                            opts.roots, opts.excludes, opts.all_paths)})


class TestNoThirdPartyImports(unittest.TestCase):
    """CI asserts the zero-dependency promise by walking every import; check
    the new module here too, so a bad import fails the fast suite first."""

    def test_only_stdlib(self):
        import ast
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "tcgcov", "dwarfline.py")
        with open(path) as f:
            tree = ast.parse(f.read())
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:
            self.skipTest("python < 3.10 has no stdlib_module_names")
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and not node.level:
                names = [(node.module or "").split(".")[0]]
            for name in names:
                self.assertIn(name, stdlib, "non-stdlib import: %s" % name)


class TestAgainstRealToolchain(unittest.TestCase):
    """If a cross toolchain and a real ELF happen to be present, check the
    reader against `readelf --debug-dump=decodedline`. Skipped otherwise --
    the fixtures above are the hermetic version of this."""

    ELF = os.environ.get("TCGCOV_TEST_ELF", "")
    READELF = os.environ.get("TCGCOV_TEST_READELF", "")

    def test_matches_readelf(self):
        if not (self.ELF and self.READELF and os.path.exists(self.ELF)):
            self.skipTest("set TCGCOV_TEST_ELF and TCGCOV_TEST_READELF")
        import re
        out = subprocess.run([self.READELF, "--debug-dump=decodedline",
                              self.ELF], capture_output=True,
                             encoding="utf-8").stdout
        expected = []
        for line in out.splitlines():
            if line.lstrip().startswith("File name"):
                continue
            m = re.search(r"\s(\d+)\s+(0x[0-9a-fA-F]+|0)(?:\s|$)", line)
            if m:
                addr = m.group(2)
                expected.append((int(addr, 16) if addr.startswith("0x") else 0,
                                 int(m.group(1))))
        mine = sorted((a, ln) for a, _f, ln in
                      dwarfline.iter_line_rows(self.ELF))
        # iter_line_rows drops address-0 and line-0 rows; readelf prints them.
        self.assertEqual(mine, sorted(r for r in expected if r[0] and r[1]))


if __name__ == "__main__":
    unittest.main()
