"""Slice a .cov by a module map: runtime windows -> per-section artifacts.

The RTEMS run-time loader (and anything like it) places each section of a
relocatable object at an independently allocated runtime address; the
object's DWARF describes 0-based section offsets.  Given a JSON module map

    [
      {"object": "dl-o1.o",
       "file": "/path/to/dl-o1.o",          # optional: ELF to symbolize with
       "sections": [
         {"name": ".text", "addr": "0x900a1b60", "size": 1240},
         ...
       ]},
      ...
    ]

this slices the artifact into one TCGCOV1 file per (object, section), with
each address rebased to its section offset, so the existing
`symbolize --section NAME --elf FILE` pipeline runs unchanged per object —
the same machinery `rebase` provides for a single window, generalized.

Two properties are non-negotiable (docs/RTEMS-DL.md, DYNAMIC-OBJECTS.md §7):

* **Overlapping windows are an error, not a guess.**  A map with two
  windows sharing addresses describes reuse the artifact cannot represent
  (a TCGCOV1 address set has no time axis), so slicing must fail loudly
  rather than attribute an address to whichever entry it found first.
* **What was dropped is always reported.**  Addresses outside every window
  are the base image (or unlisted modules); their count is printed so a
  wrong or stale map is distinguishable from a run that never entered the
  modules.
"""

import argparse
import json
import os
import re
import sys

from .format import read_all, write_cov, parse_header


def _to_int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def load_map(path):
    """Parse and validate a module map -> list of window dicts.

    Each returned window is {object, section, file, start, end}. Raises
    ValueError on malformed entries or any pairwise overlap.
    """
    with open(path) as f:
        raw = json.load(f)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: module map must be a JSON list of objects")

    windows = []
    for i, obj in enumerate(raw):
        name = obj.get("object")
        if not name:
            raise ValueError(f"{path}: entry {i} has no \"object\" name")
        for sec in obj.get("sections", []):
            sname, addr = sec.get("name"), sec.get("addr")
            size = sec.get("size")
            if not sname or addr is None or size is None:
                raise ValueError(f"{path}: {name}: section entries need "
                                 f"name/addr/size (got {sec})")
            start, size = _to_int(addr), _to_int(size)
            if size <= 0:
                continue                    # empty section: nothing to slice
            windows.append({"object": name, "section": sname,
                            "file": obj.get("file"),
                            "start": start, "end": start + size})

    windows.sort(key=lambda w: w["start"])
    for a, b in zip(windows, windows[1:]):
        if b["start"] < a["end"]:
            raise ValueError(
                f"{path}: windows overlap: {a['object']}:{a['section']} "
                f"[{a['start']:#x},{a['end']:#x}) and "
                f"{b['object']}:{b['section']} [{b['start']:#x},"
                f"{b['end']:#x}). A single map cannot describe reused "
                f"address ranges; capture one map per loader generation "
                f"instead of merging them.")
    return windows


def _slug(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._") or "x"


def slice_cov(cov_path, windows, out_dir, ctx=None):
    """Write one rebased artifact per (object, section); return a report.

    Returns (outputs, matched, unmatched) where outputs is a list of
    {object, section, file, out, records, edges}.
    """
    with open(cov_path, "rb") as f:
        hdr = parse_header(f.read(), cov_path)
    meta, addrs, counts, edges = read_all(cov_path, ctx=ctx)
    records = [(a, counts.get(a, 1) if counts else 1) for a in addrs]

    os.makedirs(out_dir, exist_ok=True)
    starts = [w["start"] for w in windows]

    import bisect

    def find(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and addr < windows[i]["end"]:
            return i
        return None

    kept = {}       # window index -> [(offset, count)]
    kept_edges = {}
    matched = 0
    for a, c in records:
        i = find(a)
        if i is None:
            continue
        matched += 1
        kept.setdefault(i, []).append((a - windows[i]["start"], c))
    for s, d, c in edges:
        i, j = find(s), find(d)
        if i is not None and i == j:
            kept_edges.setdefault(i, []).append(
                (s - windows[i]["start"], d - windows[i]["start"], c))

    outputs = []
    for i, w in enumerate(windows):
        recs = kept.get(i)
        if not recs:
            continue
        out = os.path.join(out_dir,
                           f"{_slug(w['object'])}__{_slug(w['section'])}.cov")
        m = dict(meta)
        m["module"] = w["object"]
        m["module_section"] = w["section"]
        if w["file"]:
            m["module_file"] = w["file"]
        m["rebased_from"] = "0x%x" % w["start"]
        m["rebased_window"] = "0x%x" % (w["end"] - w["start"])
        m["rebased_to"] = "0x0"
        write_cov(out, m, recs, kept_edges.get(i, []),
                  record_type=hdr["record_type"])
        outputs.append({"object": w["object"], "section": w["section"],
                        "file": w["file"], "out": out,
                        "records": len(recs),
                        "edges": len(kept_edges.get(i, []))})
    return outputs, matched, len(records) - matched


def add_arguments(parser):
    parser.add_argument("--cov", required=True, help="input .cov")
    parser.add_argument("--map", required=True, dest="module_map",
                        help="JSON module map (see module docstring)")
    parser.add_argument("--out-dir", required=True,
                        help="directory for the per-(object,section) slices")
    parser.add_argument("--ctx", type=lambda v: int(v, 0), default=None,
                        help="slice only this context of a TCGCOV2 artifact "
                             "first (e.g. one loader generation)")


def run(args):
    try:
        windows = load_map(args.module_map)
        outputs, matched, unmatched = slice_cov(
            args.cov, windows, args.out_dir, ctx=args.ctx)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    for o in outputs:
        extra = f" (elf: {o['file']})" if o["file"] else ""
        print(f"  {o['object']}:{o['section']}: {o['records']} records, "
              f"{o['edges']} edges -> {o['out']}{extra}", file=sys.stderr)
    print(f"{args.cov}: {matched} addrs in mapped windows, {unmatched} "
          f"outside (base image / unlisted modules)", file=sys.stderr)
    if not outputs:
        print("warning: nothing matched any window -- wrong map, or the "
              "modules never executed", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
