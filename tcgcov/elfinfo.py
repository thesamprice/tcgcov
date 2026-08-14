"""Minimal ELF facts for diagnostics: executable VA ranges, debug-info presence.

Deliberately independent of dwarfline's section reader: that one returns file
offsets for DWARF parsing and discards sh_addr; this one exists so symbolize
can classify guest addresses (inside/outside the ELF's executable ranges) and
warn when an ELF cannot be symbolized at all. Pure standard library, and every
failure degrades to "no facts" rather than an exception: diagnostics must
never break the pipeline they diagnose.
"""

import struct

_SHF_EXECINSTR = 0x4


def elf_text_info(path):
    """Return (exec_ranges, has_debug_info) for an ELF, or (None, None).

    exec_ranges is a sorted list of (start_va, end_va) for sections with
    SHF_EXECINSTR and a non-zero address. has_debug_info is True iff a
    .debug_info or .zdebug_info section exists. (None, None) means the file
    could not be parsed as ELF; callers should skip classification silently.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None, None
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None, None

    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None, None
    is64 = ei_class == 2
    prefix = "<" if ei_data == 1 else ">"

    try:
        if is64:
            e_shoff = struct.unpack_from(prefix + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                prefix + "HHH", data, 0x3A)
        else:
            e_shoff = struct.unpack_from(prefix + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                prefix + "HHH", data, 0x2E)
    except struct.error:
        return None, None
    if not e_shoff or not e_shentsize:
        return None, None

    def shdr(index):
        off = e_shoff + index * e_shentsize
        if off + e_shentsize > len(data):
            raise ValueError
        if is64:
            (sh_name, _type, sh_flags, sh_addr, _off, sh_size) = \
                struct.unpack_from(prefix + "IIQQQQ", data, off)
        else:
            (sh_name, _type, sh_flags, sh_addr, _off, sh_size) = \
                struct.unpack_from(prefix + "IIIIII", data, off)
        return sh_name, sh_flags, sh_addr, sh_size

    try:
        if e_shnum == 0:
            e_shnum = shdr(0)[3]
        if e_shstrndx >= e_shnum:
            return None, None
        str_name, _f, _a, _s = shdr(e_shstrndx)
        # reread the strtab header for its file offset/size
        off = e_shoff + e_shstrndx * e_shentsize
        if is64:
            _n, _t, _fl, _ad, str_off, str_size = struct.unpack_from(
                prefix + "IIQQQQ", data, off)
        else:
            _n, _t, _fl, _ad, str_off, str_size = struct.unpack_from(
                prefix + "IIIIII", data, off)
        shstr = data[str_off:str_off + str_size]

        ranges = []
        has_dwarf = False
        for i in range(e_shnum):
            sh_name, sh_flags, sh_addr, sh_size = shdr(i)
            end = shstr.find(b"\x00", sh_name)
            name = shstr[sh_name:end if end != -1 else None]
            if name in (b".debug_info", b".zdebug_info"):
                has_dwarf = True
            if (sh_flags & _SHF_EXECINSTR) and sh_addr and sh_size:
                ranges.append((sh_addr, sh_addr + sh_size))
    except (ValueError, struct.error):
        return None, None

    ranges.sort()
    return ranges, has_dwarf


def in_ranges(addr, ranges):
    """True iff addr falls inside any (start, end) of a sorted range list."""
    import bisect
    i = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
    return i >= 0 and ranges[i][0] <= addr < ranges[i][1]
