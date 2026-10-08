"""RTEMS loaded objects: resolve them on an object search path, then split.

An artifact recorded in the plugin's RTEMS loader mode (`rtl_state=`,
`rtl_debug=`) carries, per loader generation, a snapshot of every object the
run-time loader had live: its name as the target saw it, its region bases and
each section's name, size and offset. That is everything needed to attribute
a guest address to (object, section, offset) -- except the host file holding
the object's DWARF. This module supplies that, the way GDB's
`solib-search-path` does for shared libraries:

* Every directory on the object path is scanned recursively; files are
  indexed by basename and `*.a` archives by member name too (libdl records
  only the member name of an archive load, so the archive is never named).
* A loaded name is resolved by its path relative to each directory first,
  then by basename anywhere on the path -- in each case also with every
  --obj-suffix variant, for unstripped host twins of stripped target objects.
* Every candidate is **verified** against the snapshot: each section the
  loader placed must exist in the candidate with the same size. That is the
  check GDB does with a build-id; relocatable objects have no build-id, but
  the loader's own section table catches the common failures: the wrong
  object of the same name, or a rebuilt `.o` whose code changed size.
  Two verified candidates with different contents are an error, not a guess
  (unless exactly one sits at the loaded name's own relative path).

  Known limit: a rebuild that changes no section size -- an edited comment,
  which shifts every line below it -- passes. The target holds the object's
  bytes only after relocation and the plugin does not record them, so there
  is nothing to compare contents against; each slice records the md5 of the
  file it was resolved to (`module_md5`) so the provenance can be checked.

The split then turns one generation-tagged artifact into TCGCOV1 slices:

* one per (object file, section), rebased to section offsets and summed over
  every generation in which that object was live -- different lifetimes at
  the same or different addresses all land on the same offsets, so they merge
  correctly, while a *different* object that later reused the address range
  is kept apart because the generation decides which map applies;
* one for the base image: every address outside the modules live at the
  time it executed;
* a zero-record slice for each executable section of a resolved object that
  never ran, so an object that was loaded but never exercised reports as 0%
  instead of being absent.

Sections are symbolized by name (`addr2line -j`), so an object with several
sections of one name (COMDAT groups, clang -fno-unique-section-names) gets a
slice per section, each analysed against a copy of the object in which only
that section carries the name (section_view).

What could not be attributed is always reported: per unresolved object, the
reason and the number of addresses dropped.
"""

import bisect
import hashlib
import json
import os
import re
import struct
import sys
import zlib

from .format import FLAG_HAS_EDGES, read_full, write_cov

# rap region ids, as in RTEMS <link_elf.h> and the plugin's snapshot keys
RAP_NAMES = ("text", "const", "ctor", "dtor", "data", "bss")
RAP_TEXT = 0

_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4
_SHT_SYMTAB = 2
_SHT_NOBITS = 8


# --- minimal ELF / ar readers -----------------------------------------------

class ElfError(ValueError):
    pass


def elf_parse(data, what="<elf>"):
    """Return {"class", "little", "type", "sections": [...]} for ELF bytes.

    Each section is a dict with name, type, flags, addr, offset, size, align,
    link, entsize. Raises ElfError on anything that is not a parseable ELF.
    Extended section numbering (e_shnum == 0, e_shstrndx == SHN_XINDEX: the
    real values live in section 0) is honoured, and every table read is
    bounds-checked, so a truncated file is an error rather than empty names.
    """
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ElfError("%s: not an ELF file" % what)
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfError("%s: unsupported ELF class/encoding" % what)
    is64, p = ei_class == 2, "<" if ei_data == 1 else ">"
    try:
        e_type = struct.unpack_from(p + "H", data, 16)[0]
        if is64:
            e_shoff = struct.unpack_from(p + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                p + "HHH", data, 0x3A)
            fmt = p + "IIQQQQIIQQ"
        else:
            e_shoff = struct.unpack_from(p + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
                p + "HHH", data, 0x2E)
            fmt = p + "IIIIIIIIII"
        if not e_shoff:
            return {"class": 64 if is64 else 32, "little": ei_data == 1,
                    "type": e_type, "sections": []}
        if e_shentsize < struct.calcsize(fmt):
            raise ElfError("%s: bad section header size" % what)
        sh0 = struct.unpack_from(fmt, data, e_shoff)
        if e_shnum == 0:
            e_shnum = sh0[5]                   # sh_size of section 0
        if e_shstrndx == 0xFFFF:               # SHN_XINDEX
            e_shstrndx = sh0[6]                # sh_link of section 0
        if e_shoff + e_shnum * e_shentsize > len(data):
            raise ElfError("%s: section headers run past end of file" % what)
        raw = [struct.unpack_from(fmt, data, e_shoff + i * e_shentsize)
               for i in range(e_shnum)]
        hdrs = [e_shoff + i * e_shentsize for i in range(e_shnum)]
    except struct.error:
        raise ElfError("%s: truncated ELF section headers" % what)
    if e_shstrndx >= len(raw):
        raise ElfError("%s: bad section-name table index" % what)
    so, ss = raw[e_shstrndx][4], raw[e_shstrndx][5]
    if so + ss > len(data):
        raise ElfError("%s: section-name table runs past end of file" % what)
    shstr = data[so:so + ss]

    sections = []
    for hdr, (nm, typ, flags, addr, off, size, link, _info, align,
              entsize) in zip(hdrs, raw):
        if nm >= len(shstr) and nm:
            raise ElfError("%s: section name offset out of range" % what)
        end = shstr.find(b"\0", nm)
        name = shstr[nm:end if end != -1 else None].decode("utf-8", "replace")
        sections.append({"name": name, "type": typ, "flags": flags,
                         "addr": addr, "offset": off, "size": size,
                         "align": align, "link": link, "entsize": entsize,
                         "sh_name": nm, "hdr": hdr})
    return {"class": 64 if is64 else 32, "little": ei_data == 1,
            "type": e_type, "sections": sections}


def section_view(data, index):
    """A copy of an ELF where section `index` alone has its name.

    Every other section sharing that name is renamed by pointing its sh_name
    one byte further into the string table (".text" -> "text"), so tools that
    select sections by name -- `addr2line -j`, `objdump -d`'s section headers
    -- see exactly one. Section numbers, contents and relocations are
    untouched, and relocations (DWARF's included) refer to sections by
    number, so the debug info still describes the right code.
    """
    elf = elf_parse(data)
    secs = elf["sections"]
    name = secs[index]["name"]
    out = bytearray(data)
    p = "<I" if elf["little"] else ">I"
    for i, sec in enumerate(secs):
        if i != index and sec["name"] == name:
            struct.pack_into(p, out, sec["hdr"], sec["sh_name"] + 1)
    names = [s["name"] for s in elf_parse(bytes(out))["sections"]]
    if names.count(name) != 1:
        raise ElfError("could not give section %d (%s) a unique name"
                       % (index, name))
    return bytes(out)


def elf_symbols(path):
    """{name: value} for every defined symbol in an ELF's .symtab."""
    with open(path, "rb") as f:
        data = f.read()
    elf = elf_parse(data, path)
    p = "<" if elf["little"] else ">"
    out = {}
    for sec in elf["sections"]:
        if sec["type"] != _SHT_SYMTAB or not sec["entsize"]:
            continue
        strsec = elf["sections"][sec["link"]]
        strtab = data[strsec["offset"]:strsec["offset"] + strsec["size"]]
        for i in range(sec["size"] // sec["entsize"]):
            off = sec["offset"] + i * sec["entsize"]
            if elf["class"] == 64:
                nm, _info, _oth, shndx, value, _sz = struct.unpack_from(
                    p + "IBBHQQ", data, off)
            else:
                nm, value, _sz, _info, _oth, shndx = struct.unpack_from(
                    p + "IIIBBH", data, off)
            if not nm or shndx == 0:
                continue
            end = strtab.find(b"\0", nm)
            out.setdefault(strtab[nm:end].decode("utf-8", "replace"), value)
    return out


def ar_entries(f, what="<archive>"):
    """[(member_name, data_offset, size)] of an open ar archive, by seeking.

    Only the headers (and the GNU long-name table) are read, so indexing a
    large library does not pull every member into memory. System V/GNU and
    BSD (#1/len) naming are handled. Thin archives (!<thin>) hold no member
    data and raise ElfError, so the caller can say so instead of the members
    silently reading as "not found".
    """
    f.seek(0, os.SEEK_END)
    total = f.tell()
    f.seek(0)
    magic = f.read(8)
    if magic == b"!<thin>\n":
        raise ElfError("%s: thin archive (members are not stored in it); "
                       "put the member files themselves on --obj-path" % what)
    if magic != b"!<arch>\n":
        raise ElfError("%s: not an ar archive" % what)
    pos, longnames, out = 8, b"", []
    while pos + 60 <= total:
        f.seek(pos)
        hdr = f.read(60)
        name = hdr[:16].decode("utf-8", "replace").rstrip()
        try:
            size = int(hdr[48:58].decode().strip() or "0")
        except ValueError:
            raise ElfError("%s: corrupt member header at %d" % (what, pos))
        body_off = pos + 60
        if body_off + size > total:
            raise ElfError("%s: member at %d runs past end of file"
                           % (what, pos))
        pos = body_off + size + (size & 1)
        if name == "//":                       # GNU long-name table
            longnames = f.read(size)
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue                           # symbol indexes
        if name.startswith("#1/"):             # BSD: name prefixes the body
            n = int(name[3:])
            name = f.read(n).rstrip(b"\0").decode("utf-8", "replace")
            body_off, size = body_off + n, size - n
        elif name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            name = longnames[off:end if end != -1 else None].decode(
                "utf-8", "replace")
        elif name.endswith("/"):
            name = name[:-1]
        out.append((name, body_off, size))
    return out


def ar_members(data, what="<archive>"):
    """Yield (member_name, payload_bytes) from archive bytes."""
    import io
    f = io.BytesIO(data)
    for name, off, size in ar_entries(f, what):
        yield name, data[off:off + size]


# --- the object search path -------------------------------------------------

class Candidate:
    """One host file (or archive member) that might be a loaded object.

    An archive member is located by its byte range, not its name: `ar q`
    happily stores two members with the same name, and reading "the member
    called foo.o" would always return the first.
    """

    def __init__(self, path, member=None, span=None, exact=False):
        self.path = path
        self.member = member
        self.span = span            # (offset, size) inside the archive
        self.exact = exact          # found by the loaded name's relative path
        self._data = None
        self._sections = None
        self._md5 = None

    @property
    def key(self):
        return (os.path.realpath(self.path), self.span)

    @property
    def label(self):
        if self.member is None:
            return self.path
        return "%s(%s@%d)" % (self.path, self.member, self.span[0])

    def data(self):
        if self._data is None:
            with open(self.path, "rb") as f:
                if self.span is None:
                    self._data = f.read()
                else:
                    f.seek(self.span[0])
                    self._data = f.read(self.span[1])
                    if len(self._data) != self.span[1]:
                        raise ElfError("%s: archive changed under us"
                                       % self.label)
        return self._data

    def sections(self):
        if self._sections is None:
            self._sections = elf_parse(self.data(), self.label)["sections"]
        return self._sections

    def md5(self):
        if self._md5 is None:
            self._md5 = hashlib.md5(self.data()).hexdigest()
        return self._md5

    def has_debug(self):
        try:
            return any(s["name"] in (".debug_info", ".zdebug_info",
                                     ".debug_line")
                       for s in self.sections())
        except (OSError, ElfError):
            return False

    def exec_sections(self):
        try:
            return {s["name"] for s in self.sections()
                    if s["flags"] & _SHF_EXECINSTR}
        except (OSError, ElfError):
            return set()


def split_path_args(values):
    """--obj-path values: repeatable, and each may be a ':'-separated list."""
    dirs = []
    for v in values or []:
        dirs += [d for d in v.split(os.pathsep) if d]
    return dirs


class ObjectPath:
    """A GDB solib-search-path for relocatable objects.

    `suffixes` covers the common split where the target loads a stripped
    object and the host keeps the unstripped one under another name: for a
    loaded `foo.o` and suffix S, `foo.oS` and `fooS` are tried as well (so
    ".debug" finds foo.o.debug or foo.debug, and ".dbg.o" finds foo.dbg.o).
    Stripping removes only sections the loader never placed, so the section
    check still matches the two copies.
    """

    def __init__(self, dirs, suffixes=()):
        self.suffixes = list(suffixes)
        self.dirs = [os.path.abspath(d) for d in dirs]
        for d in self.dirs:
            if not os.path.isdir(d):
                raise ValueError("%s: --obj-path entry is not a directory" % d)
        self._by_base = None
        self.skipped = []           # archives that could not be indexed

    def _index(self):
        """basename -> [Candidate], built on first need, headers only."""
        if self._by_base is not None:
            return self._by_base
        idx = {}
        for top in self.dirs:
            for root, subdirs, files in os.walk(top):
                subdirs[:] = sorted(s for s in subdirs if not s.startswith("."))
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    if fn.endswith(".a"):
                        try:
                            with open(full, "rb") as f:
                                entries = ar_entries(f, full)
                        except (OSError, ElfError) as e:
                            self.skipped.append(str(e))
                            continue
                        for m, off, size in entries:
                            idx.setdefault(os.path.basename(m), []).append(
                                Candidate(full, m, (off, size)))
                    else:
                        # Any name: a suffixed debug twin need not end in .o
                        idx.setdefault(fn, []).append(Candidate(full))
        self._by_base = idx
        return idx

    def names(self, name):
        """The loaded name and its suffixed variants, most specific first."""
        out = [name]
        stem = os.path.splitext(name)[0]
        for suf in self.suffixes:
            for v in (name + suf, stem + suf):
                if v not in out:
                    out.append(v)
        return out

    def exact_candidates(self, name):
        """Files at the loaded name's path relative to each directory."""
        out = []
        for n in self.names(name.lstrip("/")):
            for d in self.dirs:
                p = os.path.join(d, n)
                if n and os.path.isfile(p):
                    out.append(Candidate(p, exact=True))
        return _dedupe(out)

    def candidates(self, name):
        """Exact relative-path hits, then basename hits anywhere on the path.

        All of them: an exact hit may be the stripped copy the target loaded
        while its unstripped twin sits elsewhere, and resolve() needs both.
        """
        found = self.exact_candidates(name)
        idx = self._index()
        for n in self.names(os.path.basename(name)):
            found += idx.get(n, [])
        return _dedupe(found)


def _dedupe(cands):
    seen, out = set(), []
    for c in cands:
        if c.key not in seen:
            seen.add(c.key)
            out.append(c)
    return out


def full_name(cand, sec):
    """The candidate's name for a snapshot section whose name was truncated.

    The plugin caps guest string reads and flags a capped name; the real
    name is the one ALLOC section of the candidate that starts with the
    recorded prefix and has the recorded size. None when there is not
    exactly one (or the name was not truncated).
    """
    if not sec.get("name_truncated") or cand is None:
        return None
    try:
        hits = {s["name"] for s in cand.sections()
                if s["flags"] & _SHF_ALLOC and s["size"] == sec["size"]
                and s["name"].startswith(sec["name"])}
    except (OSError, ElfError):
        return None
    return hits.pop() if len(hits) == 1 else None


def verify(cand, snap_sections):
    """None if every loaded section matches the candidate, else a reason."""
    try:
        have = {}
        for s in cand.sections():
            if s["flags"] & _SHF_ALLOC and s["size"]:
                have.setdefault(s["name"], []).append(s["size"])
    except (OSError, ElfError) as e:
        return str(e)
    for sec in snap_sections:
        sizes = have.get(full_name(cand, sec) or sec["name"])
        if sizes is None:
            if sec["name"].startswith(".common.rtems"):
                continue                       # synthesized by the loader
            return "no section %s" % sec["name"]
        if sec["size"] not in sizes:
            return "%s is %d bytes, the target loaded %d" % (
                sec["name"], sizes[0], sec["size"])
        sizes.remove(sec["size"])
    return None


class Resolution:
    """A resolved candidate, or why there is none.

    kind is "missing" (nothing on the path: coverage of that object is simply
    not reported) or "conflict" (something on the path claims the name but
    does not match what the target loaded, or several different files do:
    reporting it would mean reporting against the wrong source, so callers
    treat it as an error).
    """

    def __init__(self, cand=None, error=None, kind=None):
        self.cand, self.error, self.kind = cand, error, kind
        self.warning = None


def _pick(cands, snap_sections):
    """Resolution among candidates: verify, prefer DWARF, then exact path."""
    good, bad = [], []
    for c in cands:
        why = verify(c, snap_sections)
        (bad if why else good).append((c, why))
    if not good:
        return Resolution(error="no candidate matches the loaded sections: "
                          + "; ".join("%s: %s" % (c.label, w) for c, w in bad),
                          kind="conflict")
    # The target's stripped copy and the host's unstripped twin both match
    # the sections; only the one with DWARF can be symbolized, so it wins.
    debug = [c for c, _w in good if c.has_debug()]
    pool = debug or [c for c, _w in good]
    if len({c.md5() for c in pool}) > 1:
        # A file at the loaded name's own relative path outranks same-named
        # files found elsewhere in the tree (another build directory, say).
        exact = [c for c in pool if c.exact]
        if exact and len({c.md5() for c in exact}) == 1:
            pool = exact
        else:
            return Resolution(error="ambiguous, %d different matching files: "
                              "%s" % (len(pool),
                                      ", ".join(c.label for c in pool)),
                              kind="conflict")
    res = Resolution(pool[0])
    if not debug:
        res.warning = ("%s has no DWARF, so its lines cannot be symbolized "
                       "(stripped? put the unstripped copy on --obj-path, "
                       "with --obj-suffix if it is named differently)"
                       % res.cand.label)
    return res


def resolve(objpath, name, snap_sections, no_verify=False):
    """Pick the one host object that is `name` as the loader saw it.

    A verified exact relative-path hit with DWARF settles it without
    walking the tree; otherwise every candidate on the path is considered.
    """
    if objpath is None:
        return Resolution(error="no --obj-path given", kind="missing")
    exact = objpath.exact_candidates(name)
    if exact and no_verify:
        return Resolution(exact[0])
    if exact:
        res = _pick(exact, snap_sections)
        if res.cand is not None and res.warning is None:
            return res
    cands = objpath.candidates(name)
    if not cands:
        return Resolution(error="not found on --obj-path", kind="missing")
    if no_verify:
        return Resolution(cands[0])
    return _pick(cands, snap_sections)


# --- windows ----------------------------------------------------------------

def _int(v):
    return int(v, 0) if isinstance(v, str) else int(v or 0)


def object_windows(obj, cand=None):
    """[(start, end, section_name, rap, occurrence)] for one snapshot entry.

    `occurrence` is None for a section whose name is unique in the object,
    else its 0-based rank among the sections sharing that name (COMDAT
    groups, a reused section attribute, clang -fno-unique-section-names).
    The loader appends sections in ELF index order, so rank k is the k-th
    such section of the .o (see elf_index_for).

    Snapshots from this plugin version carry each section's offset from its
    region base, read from the loader's own section_detail. Older artifacts do
    not; for those the layout is reconstructed the way the loader computes it
    (rtems_rtl_obj_sections_locate: chain order, each section aligned to its
    sh_addralign), which needs the resolved object for the alignments.
    """
    bases = [_int(obj.get(n)) for n in RAP_NAMES]
    align = {}
    if cand is not None:
        try:
            for s in cand.sections():
                align.setdefault(s["name"], max(1, s["align"]))
        except (OSError, ElfError):
            pass
    running = [0] * len(RAP_NAMES)
    out = []
    names = [full_name(cand, sec) or sec["name"]
             for sec in obj.get("sections", [])]
    for sec, name in zip(obj.get("sections", []), names):
        rap, size = int(sec.get("rap", 0)), int(sec["size"])
        if not size or not 0 <= rap < len(RAP_NAMES) or not bases[rap]:
            continue
        if "offset" in sec:
            off = int(sec["offset"])
        else:
            a = align.get(name, 1)
            off = (running[rap] + a - 1) // a * a
            running[rap] = off + size
        start = bases[rap] + off
        occ = None
        if names.count(name) > 1:
            occ = sum(1 for o in out if o[2] == name)
        out.append((start, start + size, name, rap, occ))
    return out


def elf_index_for(cand, name, occurrence, size):
    """The .o section index of the occurrence-th loaded section `name`.

    The loader places only ALLOC sections with a non-zero size, in index
    order, so those are what the rank counts. None when the candidate does
    not have that many, or the size disagrees -- then the sections cannot be
    matched and their records are dropped rather than guessed.
    """
    try:
        same = [(i, s) for i, s in enumerate(cand.sections())
                if s["name"] == name and s["flags"] & _SHF_ALLOC
                and s["size"]]
    except (OSError, ElfError):
        return None
    if occurrence >= len(same) or same[occurrence][1]["size"] != size:
        return None
    return same[occurrence][0]


def _write_once(path, produce):
    """Write produce() to path unless it is there; return path.

    Named by content hash by the callers, so an existing file is the same
    bytes. Written via a temp file and rename, so a concurrent reader never
    sees half of it.
    """
    if not os.path.isfile(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = "%s.%d.tmp" % (path, os.getpid())
        with open(tmp, "wb") as f:
            f.write(produce())
        os.replace(tmp, path)
    return path


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._") or "x"


# --- the split --------------------------------------------------------------

def is_rtl_artifact(meta):
    return (meta.get("ctx_kind") == "loader-generation"
            and isinstance(meta.get("rtl_generations"), dict))


def split(cov_path, objpath, out_dir, obj_dir=None, no_verify=False,
          stem=None):
    """Split one loader-generation artifact; return a summary dict.

    Writes <out_dir>/<stem>.base.cov and one <stem>.<obj>.<md5>__<sec>.cov
    per code section of each resolved object. Returns
      {"base": path, "modules": [{object, file, md5, section, out,
                                  records, generations}],
       "unresolved": {name: {"error", "addrs"}},
       "crossing_edges": n, "unmapped_gens": [..]}
    Raises ValueError for an artifact that is not in loader-generation mode
    or whose snapshot overlaps itself.
    """
    meta, hdr, records, edges = read_full(cov_path)
    if not is_rtl_artifact(meta):
        raise ValueError("%s: not a loader-generation artifact (record it "
                         "with the plugin's rtl_state=/rtl_debug=)" % cov_path)
    stem = stem or _slug(os.path.splitext(os.path.basename(cov_path))[0])
    obj_dir = obj_dir or os.path.join(out_dir, "objs")
    os.makedirs(out_dir, exist_ok=True)
    gens = meta["rtl_generations"]

    resolved = {}        # (name, md5-of-snapshot-sections) -> Resolution
    warnings = set()
    unresolved = {}      # name -> {"error", "addrs"}
    # Per generation: sorted windows (start, end, key, section) where key
    # names the resolved file (or None for an unresolved object).
    gen_windows = {}
    for g, objs in gens.items():
        wins = []
        for obj in objs:
            name = obj.get("object") or "?"
            sig = json.dumps(obj.get("sections", []), sort_keys=True)
            res = resolved.get((name, sig))
            if res is None:
                res = resolve(objpath, name, obj.get("sections", []),
                              no_verify)
                resolved[(name, sig)] = res
            if res.warning:
                warnings.add(res.warning)
            if res.error:
                unresolved.setdefault(name, {"error": res.error,
                                             "kind": res.kind, "addrs": 0})
            if obj.get("truncated"):
                warnings.add(
                    "%s: the plugin's snapshot of it was truncated (%s of %s "
                    "sections recorded, or a name cut short); executions in "
                    "unrecorded sections are reported as base image"
                    % (name, len(obj.get("sections", [])),
                       obj.get("sec_num", "?")))
            if obj.get("chain_truncated"):
                warnings.add(
                    "generation %s: the plugin stopped walking the loader's "
                    "object list at %d objects; later objects' executions are "
                    "reported as base image" % (g, len(objs)))
            for s, e, sec, rap, occ in object_windows(obj, res.cand):
                idx, lost = None, False
                if occ is not None and res.cand is not None:
                    idx = elf_index_for(res.cand, sec, occ, e - s)
                    lost = idx is None
                wins.append((s, e, res.cand, name, sec, rap, lost, idx))
        wins.sort(key=lambda w: w[0])
        for a, b in zip(wins, wins[1:]):
            if b[0] < a[1]:
                raise ValueError(
                    "%s: generation %s snapshot overlaps itself: %s:%s and "
                    "%s:%s" % (cov_path, g, a[3], a[4], b[3], b[4]))
        gen_windows[int(g)] = wins

    def finder(g):
        wins = gen_windows.get(g, [])
        starts = [w[0] for w in wins]

        def find(addr):
            i = bisect.bisect_right(starts, addr) - 1
            if i >= 0 and addr < wins[i][1]:
                return wins[i]
            return None
        return find

    finders = {}
    unmapped_gens = set()

    def window_of(g, addr):
        if g not in finders:
            if g not in gen_windows and g != 0:
                unmapped_gens.add(g)
            finders[g] = finder(g)
        return finders[g](addr)

    base_recs, base_edges = {}, {}
    mods = {}            # (cand.label, section) -> {"recs", "edges", ...}
    ambiguous = {}       # (object, section) -> records dropped (unmatched)

    def mod_slot(w):
        # A same-named section is its own slot, keyed by its .o index.
        key = (w[2].label, w[4], -1 if w[7] is None else w[7])
        slot = mods.get(key)
        if slot is None:
            slot = mods[key] = {"cand": w[2], "object": w[3], "section": w[4],
                                "index": w[7], "rap": w[5], "recs": {},
                                "edges": {}, "gens": set()}
        return slot

    for g, a, c in records:
        c = 1 if c is None else c
        w = window_of(g, a)
        if w is None:
            base_recs[a] = base_recs.get(a, 0) + c
        elif w[2] is None:
            unresolved[w[3]]["addrs"] += 1
        elif w[6]:
            ambiguous[(w[3], w[4])] = ambiguous.get((w[3], w[4]), 0) + 1
        else:
            slot = mod_slot(w)
            off = a - w[0]
            slot["recs"][off] = slot["recs"].get(off, 0) + c
            slot["gens"].add(g)

    crossing = 0
    for g, s, d, c in edges:
        ws, wd = window_of(g, s), window_of(g, d)
        if ws is None and wd is None:
            base_edges[(s, d)] = base_edges.get((s, d), 0) + c
        elif ws is not None and ws is wd and ws[2] is not None \
                and not ws[6]:
            slot = mod_slot(ws)
            k = (s - ws[0], d - ws[0])
            slot["edges"][k] = slot["edges"].get(k, 0) + c
        else:
            crossing += 1           # base<->module, module<->module, unresolved

    # Every code section of every resolved object gets a slice, so an object
    # that was loaded but never ran reports 0% rather than nothing. (The text
    # region also holds .init_array/.fini_array, which are not code.)
    for g, wins in gen_windows.items():
        for w in wins:
            if (w[2] is not None and not w[6] and w[5] == RAP_TEXT
                    and w[4] in w[2].exec_sections()):
                mod_slot(w)

    rtl_keys = ("rtl_generations", "rtl_events", "ctx_enabled", "ctx_kind")
    common = {k: v for k, v in meta.items() if k not in rtl_keys}
    common["rtl_split_from"] = os.path.abspath(cov_path)
    rtype = hdr.get("record_type", 1)
    had_edges = bool(hdr["flags"] & FLAG_HAS_EDGES)

    base_out = os.path.join(out_dir, "%s.base.cov" % stem)
    write_cov(base_out, dict(common), sorted(base_recs.items()),
              [(s, d, c) for (s, d), c in sorted(base_edges.items())],
              record_type=rtype, edges_recorded=had_edges)

    modules = []
    for (label, sec, _idx), slot in sorted(mods.items()):
        if slot["rap"] != RAP_TEXT and not slot["recs"]:
            continue
        cand = slot["cand"]
        if slot["index"] is not None:
            # One of several same-named sections: symbolize against a view
            # of the object in which it alone carries the name.
            path = _write_once(
                os.path.join(obj_dir, "%s.%s.s%d.o" % (
                    _slug(os.path.basename(cand.member or cand.path)),
                    cand.md5()[:8], slot["index"])),
                lambda: section_view(cand.data(), slot["index"]))
        elif cand.member is None:
            path = cand.path
        else:
            # Archive member: extract it once so the toolchain can read it.
            path = _write_once(
                os.path.join(obj_dir, _slug(os.path.basename(cand.path))
                             + "." + cand.md5()[:8],
                             os.path.basename(cand.member)),
                cand.data)
        m = dict(common)
        if slot["index"] is not None:
            m["module_section_index"] = slot["index"]
        m.update({"module": slot["object"], "module_file": path,
                  "module_section": sec, "module_md5": cand.md5(),
                  "module_generations": sorted(slot["gens"]),
                  "rebased_to": "0x0"})
        # The md5 keeps two different files apart that share a basename
        # (/a/foo.o and /b/foo.o, or foo.o rebuilt between loads).
        out = os.path.join(out_dir, "%s.%s.%s__%s%s.cov" % (
            stem, _slug(os.path.basename(slot["object"])), cand.md5()[:8],
            _slug(sec), "" if slot["index"] is None
            else ".s%d" % slot["index"]))
        write_cov(out, m, sorted(slot["recs"].items()),
                  [(s, d, c) for (s, d), c in sorted(slot["edges"].items())],
                  record_type=rtype, edges_recorded=had_edges)
        modules.append({"object": slot["object"], "file": path,
                        "source": cand.label, "md5": cand.md5(),
                        "section": sec, "index": slot["index"], "out": out,
                        "records": len(slot["recs"]),
                        "generations": sorted(slot["gens"])})

    return {"base": base_out, "base_records": len(base_recs),
            "modules": modules, "unresolved": unresolved,
            "warnings": sorted(warnings) + [
                "%s: its sections named %s could not be matched to the "
                "object's (count or sizes differ); %d records dropped"
                % (o, sec, n) for (o, sec), n in sorted(ambiguous.items())],
            "crossing_edges": crossing, "unmapped_gens": sorted(unmapped_gens)}


def unique_stems(covs):
    """One output stem per artifact; same basenames get a path hash."""
    by = {}
    for c in covs:
        by.setdefault(_slug(os.path.splitext(os.path.basename(c))[0]),
                      []).append(c)
    out = {}
    for stem, paths in by.items():
        for c in paths:
            out[c] = stem if len(paths) == 1 else "%s.%08x" % (
                stem, zlib.crc32(os.path.abspath(c).encode("utf-8",
                                                           "surrogateescape"))
                & 0xFFFFFFFF)
    return out


def print_skipped(objpath, out=None):
    """Archives on the path that could not be indexed, said once."""
    out = out or sys.stderr
    for why in (objpath.skipped if objpath else []):
        print("warning: --obj-path: %s" % why, file=out)


def print_summary(cov, summary, out=None):
    """The split's accounting: nothing dropped without a line saying so."""
    out = out or sys.stderr        # at call time: report redirects stderr
    print("%s: %d base-image addrs -> %s" % (cov, summary["base_records"],
                                             summary["base"]), file=out)
    for m in summary["modules"]:
        gens = m["generations"]
        sec = m["section"] if m.get("index") is None else "%s[#%d]" % (
            m["section"], m["index"])
        print("  %s:%s: %d addrs over %d generation(s) -> %s  [%s md5 %s]"
              % (m["object"], sec, m["records"], len(gens),
                 os.path.basename(m["out"]), m["source"], m["md5"][:12]),
              file=out)
    for name, u in sorted(summary["unresolved"].items()):
        print("  warning: %s: %s; %d records (addr x generation) dropped"
              % (name, u["error"], u["addrs"]), file=out)
    for w in summary.get("warnings", []):
        print("  warning: %s" % w, file=out)
    if summary["unmapped_gens"]:
        print("  warning: generations %s have no snapshot; their addrs were "
              "treated as base image" % summary["unmapped_gens"], file=out)


# --- subcommands ------------------------------------------------------------

def add_arguments(parser):
    parser.add_argument("--cov", required=True, nargs="+",
                        help="loader-generation .cov artifact(s)")
    add_obj_path_args(parser)
    parser.add_argument("--out-dir", required=True,
                        help="directory for the base and per-object slices")


def add_obj_path_args(parser):
    parser.add_argument("--obj-path", action="append", default=[],
                        metavar="DIR[:DIR...]",
                        help="where to find the host copies of RTEMS "
                             "dynamically loaded objects: searched "
                             "recursively for *.o and *.a members, by the "
                             "loaded name's relative path then its basename "
                             "(like GDB's solib-search-path). Repeatable")
    parser.add_argument("--obj-suffix", action="append", default=[],
                        metavar="SUFFIX",
                        help="also look for the loaded name with SUFFIX "
                             "appended to it and to its stem (e.g. .debug "
                             "finds foo.o.debug and foo.debug for a loaded "
                             "foo.o), for unstripped host copies of objects "
                             "the target loaded stripped. Repeatable")
    parser.add_argument("--obj-no-verify", action="store_true",
                        help="accept the first candidate without checking "
                             "its sections against what the target loaded")


def run(args):
    try:
        objpath = ObjectPath(split_path_args(args.obj_path),
                             args.obj_suffix) if args.obj_path else None
        rc = 0
        stems = unique_stems(args.cov)
        for cov in args.cov:
            summary = split(cov, objpath, args.out_dir,
                            no_verify=args.obj_no_verify, stem=stems[cov])
            print_summary(cov, summary)
            if any(u["kind"] == "conflict"
                   for u in summary["unresolved"].values()):
                rc = 1
            elif summary["unresolved"] and rc == 0:
                rc = 2
        print_skipped(objpath)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return rc


def add_args_arguments(parser):
    parser.add_argument("elf", help="the base image (the .exe QEMU loads)")
    parser.add_argument("--no-load-hook", action="store_true",
                        help="omit rtl_load= even if the image has the "
                             "rtems_rtl_debugger_load hook")


def run_args(args):
    """Print the -plugin options for RTEMS loader mode, from the ELF itself."""
    try:
        with open(args.elf, "rb") as f:
            elf = elf_parse(f.read(), args.elf)
        syms = elf_symbols(args.elf)
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    if elf["class"] != 32 or not elf["little"]:
        print("error: %s: the plugin's link_map walk assumes a 32-bit "
              "little-endian target" % args.elf, file=sys.stderr)
        return 1
    missing = [n for n in ("_rtld_debug_state", "_rtld_debug")
               if n not in syms]
    if missing:
        print("error: %s: no %s -- not linked with libdl?"
              % (args.elf, ", ".join(missing)), file=sys.stderr)
        return 1
    opts = ["rtl_state=0x%x" % syms["_rtld_debug_state"],
            "rtl_debug=0x%x" % syms["_rtld_debug"]]
    if "rtems_rtl_debugger_load" in syms and not args.no_load_hook:
        opts.append("rtl_load=0x%x" % syms["rtems_rtl_debugger_load"])
    opts.append("elf=%s" % os.path.abspath(args.elf))
    print(",".join(opts))
    return 0
