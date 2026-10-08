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
  the loader's own section table is nearly as discriminating, and it rejects
  the classic failure -- a rebuilt `.o` on the host that no longer matches the
  one the target loaded -- instead of symbolizing against the wrong lines.
  Two verified candidates with different contents are an error, not a guess.

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
        raw = []
        for i in range(e_shnum):
            raw.append(struct.unpack_from(fmt, data, e_shoff + i * e_shentsize))
        if e_shstrndx >= len(raw):
            raise ElfError("%s: bad section-name table index" % what)
        so, ss = raw[e_shstrndx][4], raw[e_shstrndx][5]
        shstr = data[so:so + ss]
    except struct.error:
        raise ElfError("%s: truncated ELF section headers" % what)

    sections = []
    for (nm, typ, flags, addr, off, size, link, _info, align, entsize) in raw:
        end = shstr.find(b"\0", nm)
        name = shstr[nm:end if end != -1 else None].decode("utf-8", "replace")
        sections.append({"name": name, "type": typ, "flags": flags,
                         "addr": addr, "offset": off, "size": size,
                         "align": align, "link": link, "entsize": entsize})
    return {"class": 64 if is64 else 32, "little": ei_data == 1,
            "type": e_type, "sections": sections}


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


def ar_members(data, what="<archive>"):
    """Yield (member_name, payload_bytes) from a System V / GNU / BSD archive."""
    if not data.startswith(b"!<arch>\n"):
        raise ElfError("%s: not an ar archive" % what)
    pos, longnames = 8, b""
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("utf-8", "replace").rstrip()
        try:
            size = int(hdr[48:58].decode().strip() or "0")
        except ValueError:
            raise ElfError("%s: corrupt member header at %d" % (what, pos))
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name == "//":                       # GNU long-name table
            longnames = body
            continue
        if name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue                           # symbol indexes
        if name.startswith("#1/"):             # BSD: name prefixes the body
            n = int(name[3:])
            name, body = body[:n].rstrip(b"\0").decode("utf-8",
                                                       "replace"), body[n:]
        elif name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            name = longnames[off:end if end != -1 else None].decode(
                "utf-8", "replace")
        elif name.endswith("/"):
            name = name[:-1]
        yield name, body


# --- the object search path -------------------------------------------------

class Candidate:
    """One host file (or archive member) that might be a loaded object."""

    def __init__(self, path, member=None):
        self.path = path
        self.member = member
        self._data = None
        self._sections = None

    @property
    def label(self):
        return "%s(%s)" % (self.path, self.member) if self.member else self.path

    def data(self):
        if self._data is None:
            with open(self.path, "rb") as f:
                raw = f.read()
            if self.member is None:
                self._data = raw
            else:
                for name, body in ar_members(raw, self.path):
                    if name == self.member:
                        self._data = body
                        break
                else:
                    raise ElfError("%s: member vanished" % self.label)
        return self._data

    def sections(self):
        if self._sections is None:
            self._sections = elf_parse(self.data(), self.label)["sections"]
        return self._sections

    def md5(self):
        return hashlib.md5(self.data()).hexdigest()

    def has_debug(self):
        try:
            return any(s["name"] in (".debug_info", ".zdebug_info",
                                     ".debug_line")
                       for s in self.sections())
        except (OSError, ElfError):
            return False


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

    def _index(self):
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
                                members = [n for n, _b in
                                           ar_members(f.read(), full)]
                        except (OSError, ElfError):
                            continue
                        for m in members:
                            idx.setdefault(os.path.basename(m), []).append(
                                Candidate(full, m))
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

    def candidates(self, name):
        """Exact relative-path hits first, then basename hits anywhere.

        All of them, not just the first tier: an exact hit may be the
        stripped copy the target loaded while its unstripped twin sits
        elsewhere on the path, and resolve() needs to see both.
        """
        found = []
        for n in self.names(name.lstrip("/")):
            for d in self.dirs:
                p = os.path.join(d, n)
                if n and os.path.isfile(p):
                    found.append(Candidate(p))
        idx = self._index()
        for n in self.names(os.path.basename(name)):
            found += idx.get(n, [])
        seen, out = set(), []
        for c in found:
            key = (os.path.realpath(c.path), c.member)
            if key not in seen:
                seen.add(key)
                out.append(c)
        return out


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
        sizes = have.get(sec["name"])
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


def resolve(objpath, name, snap_sections, no_verify=False):
    """Pick the one host object that is `name` as the loader saw it."""
    if objpath is None:
        return Resolution(error="no --obj-path given", kind="missing")
    cands = objpath.candidates(name)
    if not cands:
        return Resolution(error="not found on --obj-path", kind="missing")
    if no_verify:
        return Resolution(cands[0])
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
    debug = [(c, w) for c, w in good if c.has_debug()]
    good = debug or good
    if len({c.md5() for c, _w in good}) > 1:
        return Resolution(error="ambiguous, %d different matching files: %s"
                          % (len(good), ", ".join(c.label for c, _w in good)),
                          kind="conflict")
    res = Resolution(good[0][0])
    if not debug:
        res.warning = ("%s has no DWARF, so its lines cannot be symbolized "
                       "(stripped? put the unstripped copy on --obj-path, "
                       "with --obj-suffix if it is named differently)"
                       % res.cand.label)
    return res


# --- windows ----------------------------------------------------------------

def _int(v):
    return int(v, 0) if isinstance(v, str) else int(v or 0)


def object_windows(obj, cand=None):
    """[(start, end, section_name, rap)] for one snapshot object entry.

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
    for sec in obj.get("sections", []):
        rap, size = int(sec.get("rap", 0)), int(sec["size"])
        if not size or not 0 <= rap < len(RAP_NAMES) or not bases[rap]:
            continue
        if "offset" in sec:
            off = int(sec["offset"])
        else:
            a = align.get(sec["name"], 1)
            off = (running[rap] + a - 1) // a * a
            running[rap] = off + size
        start = bases[rap] + off
        out.append((start, start + size, sec["name"], rap))
    return out


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._") or "x"


# --- the split --------------------------------------------------------------

def is_rtl_artifact(meta):
    return (meta.get("ctx_kind") == "loader-generation"
            and isinstance(meta.get("rtl_generations"), dict))


def split(cov_path, objpath, out_dir, obj_dir=None, no_verify=False,
          stem=None):
    """Split one loader-generation artifact; return a summary dict.

    Writes <out_dir>/<stem>.base.cov and one <stem>.<obj>__<sec>.cov per
    executable section of each resolved object. Returns
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
            for s, e, sec, rap in object_windows(obj, res.cand):
                wins.append((s, e, res.cand, name, sec, rap))
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

    def mod_slot(w):
        key = (w[2].label, w[4])
        slot = mods.get(key)
        if slot is None:
            slot = mods[key] = {"cand": w[2], "object": w[3], "section": w[4],
                                "rap": w[5], "recs": {}, "edges": {},
                                "gens": set()}
        return slot

    for g, a, c in records:
        c = 1 if c is None else c
        w = window_of(g, a)
        if w is None:
            base_recs[a] = base_recs.get(a, 0) + c
        elif w[2] is None:
            unresolved[w[3]]["addrs"] += 1
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
        elif ws is not None and ws is wd and ws[2] is not None:
            slot = mod_slot(ws)
            k = (s - ws[0], d - ws[0])
            slot["edges"][k] = slot["edges"].get(k, 0) + c
        else:
            crossing += 1           # base<->module, module<->module, unresolved

    # Every executable section of every resolved object gets a slice, so an
    # object that was loaded but never ran reports 0% rather than nothing.
    for g, wins in gen_windows.items():
        for w in wins:
            if w[2] is not None and w[5] == RAP_TEXT:
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
    for (label, sec), slot in sorted(mods.items()):
        if slot["rap"] != RAP_TEXT and not slot["recs"]:
            continue
        cand = slot["cand"]
        if cand.member is None:
            path = cand.path
        else:
            # Archive member: extract it once so the toolchain can read it.
            d = os.path.join(obj_dir, _slug(os.path.basename(cand.path))
                             + "." + cand.md5()[:8])
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, os.path.basename(cand.member))
            if not os.path.isfile(path):
                tmp = "%s.%d.tmp" % (path, os.getpid())
                with open(tmp, "wb") as f:
                    f.write(cand.data())
                os.replace(tmp, path)
        m = dict(common)
        m.update({"module": slot["object"], "module_file": path,
                  "module_section": sec, "module_md5": cand.md5(),
                  "module_generations": sorted(slot["gens"]),
                  "rebased_to": "0x0"})
        out = os.path.join(out_dir, "%s.%s__%s.cov" % (
            stem, _slug(os.path.basename(slot["object"])), _slug(sec)))
        write_cov(out, m, sorted(slot["recs"].items()),
                  [(s, d, c) for (s, d), c in sorted(slot["edges"].items())],
                  record_type=rtype, edges_recorded=had_edges)
        modules.append({"object": slot["object"], "file": path,
                        "source": cand.label, "md5": cand.md5(),
                        "section": sec, "out": out,
                        "records": len(slot["recs"]),
                        "generations": sorted(slot["gens"])})

    return {"base": base_out, "base_records": len(base_recs),
            "modules": modules, "unresolved": unresolved,
            "warnings": sorted(warnings),
            "crossing_edges": crossing, "unmapped_gens": sorted(unmapped_gens)}


def print_summary(cov, summary, out=None):
    """The split's accounting: nothing dropped without a line saying so."""
    out = out or sys.stderr        # at call time: report redirects stderr
    print("%s: %d base-image addrs -> %s" % (cov, summary["base_records"],
                                             summary["base"]), file=out)
    for m in summary["modules"]:
        gens = m["generations"]
        print("  %s:%s: %d addrs over %d generation(s) -> %s  [%s md5 %s]"
              % (m["object"], m["section"], m["records"], len(gens),
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
        for cov in args.cov:
            summary = split(cov, objpath, args.out_dir,
                            no_verify=args.obj_no_verify)
            print_summary(cov, summary)
            if any(u["kind"] == "conflict"
                   for u in summary["unresolved"].values()):
                rc = 1
            elif summary["unresolved"] and rc == 0:
                rc = 2
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
