"""elfinfo: executable-range extraction and debug-info detection."""

import struct
import tempfile
import unittest

from tcgcov.elfinfo import elf_text_info, in_ranges


def _mini_elf(sections, little=True, is64=False):
    """Build a minimal ELF32/ELF64 with the given (name, flags, addr, size)."""
    prefix = "<" if little else ">"
    names = b"\x00"
    offs = {}
    for name, _f, _a, _s in sections:
        offs[name] = len(names)
        names += name + b"\x00"
    shstrndx_name = offs.setdefault(b".shstrtab", len(names))
    names += b".shstrtab\x00"

    shentsize = 64 if is64 else 40
    ehsize = 64 if is64 else 52
    nsec = len(sections) + 2          # null + payload + shstrtab
    shoff = ehsize
    strtab_off = shoff + (nsec * shentsize)

    def shdr(name_off, sh_type, flags, addr, offset, size):
        if is64:
            return struct.pack(prefix + "IIQQQQIIQQ", name_off, sh_type,
                               flags, addr, offset, size, 0, 0, 0, 0)
        return struct.pack(prefix + "IIIIIIIIII", name_off, sh_type, flags,
                           addr, offset, size, 0, 0, 0, 0)

    body = shdr(0, 0, 0, 0, 0, 0)
    for name, flags, addr, size in sections:
        body += shdr(offs[name], 1, flags, addr, strtab_off, size)
    body += shdr(shstrndx_name, 3, 0, 0, strtab_off, len(names))

    e = bytearray(b"\x7fELF")
    e.append(2 if is64 else 1)
    e.append(1 if little else 2)
    e += b"\x01" + b"\x00" * 9
    if is64:
        e += struct.pack(prefix + "HHIQQQIHHHHHH", 2, 0xBAAB, 1, 0, 0, shoff,
                         0, ehsize, 0, 0, shentsize, nsec, nsec - 1)
    else:
        e += struct.pack(prefix + "HHIIIIIHHHHHH", 2, 0xBAAB, 1, 0, 0, shoff,
                         0, ehsize, 0, 0, shentsize, nsec, nsec - 1)
    return bytes(e) + body + names


class ElfInfoTest(unittest.TestCase):
    def _roundtrip(self, sections, **kw):
        with tempfile.NamedTemporaryFile() as f:
            f.write(_mini_elf(sections, **kw))
            f.flush()
            return elf_text_info(f.name)

    def test_exec_ranges_and_dwarf(self):
        ranges, dwarf = self._roundtrip([
            (b".text", 0x6, 0x1000, 0x200),      # ALLOC|EXECINSTR
            (b".data", 0x3, 0x4000, 0x100),      # not exec
            (b".debug_info", 0, 0, 0x40),
        ])
        self.assertEqual(ranges, [(0x1000, 0x1200)])
        self.assertTrue(dwarf)

    def test_no_dwarf(self):
        ranges, dwarf = self._roundtrip([(b".text", 0x6, 0x1000, 0x10)])
        self.assertEqual(ranges, [(0x1000, 0x1010)])
        self.assertFalse(dwarf)

    def test_big_endian_and_64(self):
        for little in (True, False):
            for is64 in (True, False):
                ranges, dwarf = self._roundtrip(
                    [(b".text", 0x6, 0x2000, 0x80)],
                    little=little, is64=is64)
                self.assertEqual(ranges, [(0x2000, 0x2080)],
                                 (little, is64))

    def test_not_elf(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"definitely not an ELF")
            f.flush()
            self.assertEqual(elf_text_info(f.name), (None, None))

    def test_in_ranges(self):
        r = [(0x1000, 0x1200), (0x2000, 0x2100)]
        self.assertTrue(in_ranges(0x1000, r))
        self.assertTrue(in_ranges(0x11FF, r))
        self.assertFalse(in_ranges(0x1200, r))
        self.assertFalse(in_ranges(0x1FFF, r))
        self.assertTrue(in_ranges(0x20FF, r))
        self.assertFalse(in_ranges(0, r))


if __name__ == "__main__":
    unittest.main()
