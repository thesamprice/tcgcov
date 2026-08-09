"""ELF -> coverable-line inventory JSONL (the denominator for real coverage).

A source line is "coverable" iff at least one EXECUTABLE instruction address in
the ELF maps to it via the DWARF line table -- a conservative definition that
avoids DWARF artifacts.

Two denominator sources, selected with --denominator:

  objdump  Disassemble the ELF (`<prefix>objdump -d`, which emits only
           executable sections) to enumerate every instruction address, then
           resolve them through the DWARF line table with the SAME batched
           addr2line and SAME path normalization as the covered side. This is
           the conservative definition above, and it is what the covered side
           does, so the two sets are comparable by construction.

  dwarf    Read `.debug_line` directly (tcgcov.dwarfline, pure stdlib): the
           line-number program already maps code addresses to (file, line) for
           all code, executed or not. No objdump, no addr2line, no
           architecture knowledge. Slightly less conservative -- a line-table
           row is not proof that an instruction was emitted at that address --
           and it does not see inlined CALL SITES, which addr2line -i reports
           as extra frames. On a real picolibc image the DWARF denominator was
           a strict subset of the objdump one: 662 identical lines plus 15
           inlined call sites only objdump found. `lcov` unions the covered
           lines into the denominator, so no hit is lost to that difference.

  auto     (default) objdump first, DWARF as a fallback when the objdump path
           fails or yields nothing usable. An unrecognized disassembly layout
           used to be a hard error (before that, a silent empty inventory that
           made every report read 100%); now it degrades to a correct, slightly
           broader denominator instead of no coverage at all.

When the objdump path is used, the DWARF row set is computed anyway and the two
are compared: a source that silently produces garbage shows up as a large
one-sided difference. That check warns, it never fails.

Output JSONL fields: file, line, function, arch, denominator, address.
"""

import argparse
import json
import subprocess
import sys

from . import dwarfline
from .cfg import match_insn_line
from .symbolize import iter_covered_lines
from .cliargs import add_symbolize_args
from .paths import path_options, normalize_path

DENOMINATOR_SOURCES = ("objdump", "dwarf", "auto")

# Cross-check tolerances. The two sources are not expected to agree exactly:
# addr2line -i adds the inlined call sites that a line-table row does not
# mention, and the line table can name an address in a section objdump did not
# disassemble. Only a difference big enough to mean "one of these parsers is
# broken" is worth a warning.
CROSS_CHECK_MIN_LINES = 5       # absolute floor, so tiny binaries stay quiet
CROSS_CHECK_FRACTION = 0.05     # of the union, for the DWARF-only direction
CROSS_CHECK_INLINE_FRACTION = 0.5   # of the union, for the objdump-only one


def parse_addresses(text):
    """Return a sorted list of unique instruction addresses in `text`.

    Uses cfg.match_insn_line -- the SAME line matcher as the branch inventory,
    so the coverable denominator and the branch denominator can never be
    computed from different ideas of what a disassembly line looks like.
    """
    addrs = set()
    for line in text.splitlines():
        matched = match_insn_line(line)
        if matched is not None:
            addrs.add(matched[0])
    return sorted(addrs)


def disassemble_addresses(objdump, elf):
    """Return (addresses, raw objdump text) for the ELF's executable sections.

    The text comes back so the caller can tell "objdump printed nothing" (an
    empty binary) from "objdump printed plenty and we understood none of it"
    (a parse failure, which must not be reported as an empty inventory).
    Decoding is pinned to UTF-8/surrogateescape so a non-UTF-8 byte in a path
    or symbol name cannot abort the run under LC_ALL=C.
    """
    proc = subprocess.run([objdump, "-d", elf], capture_output=True,
                          encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        raise RuntimeError(f"{objdump} failed: {proc.stderr.strip()}")
    return parse_addresses(proc.stdout), proc.stdout


def objdump_addresses(args, objdump):
    """Instruction addresses from `--disasm` or a fresh objdump run.

    Raises RuntimeError when no address could be parsed. That is never a
    benign result: an empty coverable inventory makes `lcov` use the covered
    lines as their own denominator and report 100%.
    """
    if args.disasm:
        with open(args.disasm, encoding="utf-8", errors="surrogateescape") as f:
            text = f.read()
        addrs = parse_addresses(text)
        source = args.disasm
    else:
        addrs, text = disassemble_addresses(objdump, args.elf)
        source = objdump

    if addrs:
        return addrs
    if text.strip():
        raise RuntimeError(
            f"{args.elf}: {source} produced {len(text.splitlines())} lines of "
            f"output but no instruction addresses were parsed from it -- "
            f"unrecognized disassembly layout")
    raise RuntimeError(f"{args.elf}: {source} disassembled no executable code "
                       f"at all")


def objdump_inventory(args, opts, objdump, addr2line):
    """Build the inventory from disassembled instruction addresses.

    Returns ({(file, line, function): representative address}, address count).
    """
    addrs = objdump_addresses(args, objdump)
    seen = {}
    for norm, line, func, _depth, addr in iter_covered_lines(
            addr2line, args.elf, addrs, opts):
        seen.setdefault((norm, line, func), addr)
    return seen, len(addrs)


def dwarf_inventory(args, opts):
    """Build the inventory from `.debug_line` alone.

    Returns ({(file, line, function): representative address}, row count).

    The line table already carries the file and the line, so this skips
    addr2line entirely -- but it must produce byte-identical keys to the
    objdump path, which means running every path through the SAME
    paths.normalize_path with the SAME PathOptions bundle. Function names come
    from `.symtab` (the line table has none); they only feed LCOV FN records,
    never the line denominator.
    """
    elf = dwarfline.read_elf(args.elf)
    functions = dwarfline.FunctionIndex(elf)
    seen = {}
    rows = 0
    for addr, path, line in dwarfline.iter_line_rows(elf):
        rows += 1
        norm = normalize_path(path, opts.source_root, opts.markers, opts.roots,
                              opts.excludes, opts.all_paths)
        if norm is None:
            continue
        seen.setdefault((norm, line, functions.at(addr)), addr)
    return seen, rows


def cross_check_messages(objdump_seen, dwarf_seen):
    """Compare two inventories' (file, line) keys; return warning strings.

    Function names are left out of the comparison: they come from addr2line on
    one side and `.symtab` on the other, and a name difference says nothing
    about the denominator.
    """
    a = {(f, ln) for f, ln, _fn in objdump_seen}
    b = {(f, ln) for f, ln, _fn in dwarf_seen}
    if not a or not b:
        return []
    union = len(a | b)
    only_dwarf = b - a
    only_objdump = a - b
    margin = max(CROSS_CHECK_MIN_LINES, int(union * CROSS_CHECK_FRACTION))
    inline_margin = max(CROSS_CHECK_MIN_LINES,
                        int(union * CROSS_CHECK_INLINE_FRACTION))

    msgs = []
    if not a & b:
        msgs.append(
            f"the objdump and DWARF denominators share NO source line at all "
            f"({len(a)} vs {len(b)} lines). That is a path-normalization "
            f"mismatch, not a coverage result")
        return msgs
    if len(only_dwarf) > margin:
        sample = ", ".join(f"{f}:{ln}" for f, ln in sorted(only_dwarf)[:3])
        msgs.append(
            f"the DWARF line table names {len(only_dwarf)} source lines the "
            f"objdump denominator does not (of {union} total), e.g. {sample}. "
            f"The disassembly may be being parsed incompletely")
    if len(only_objdump) > inline_margin:
        sample = ", ".join(f"{f}:{ln}" for f, ln in sorted(only_objdump)[:3])
        msgs.append(
            f"the objdump denominator names {len(only_objdump)} source lines "
            f"the DWARF line table does not (of {union} total), e.g. {sample}. "
            f"Inlined call sites explain some of this, but not usually this "
            f"many")
    return msgs


def add_arguments(parser):
    parser.add_argument("--elf", required=True, help="ELF to inventory")
    add_symbolize_args(parser)
    parser.add_argument("--denominator", choices=DENOMINATOR_SOURCES,
                        default="auto",
                        help="where the coverable set comes from: 'objdump' "
                             "(disassemble + addr2line), 'dwarf' (read "
                             ".debug_line directly -- no target toolchain "
                             "needed), or 'auto' (objdump, falling back to "
                             "dwarf if it fails or finds nothing). "
                             "Default: auto")
    parser.add_argument("--no-cross-check", dest="cross_check",
                        action="store_false", default=True,
                        help="skip comparing the objdump denominator against "
                             "the DWARF line table (the comparison is cheap "
                             "and catches a parser that silently produces "
                             "garbage)")
    parser.add_argument("--objdump", help="explicit objdump path")
    parser.add_argument("--disasm", metavar="FILE",
                        help="read pre-captured `objdump -d` output from FILE "
                             "instead of running objdump. The branch inventory "
                             "needs the same disassembly, so capturing it once "
                             "per ELF and passing it to both halves avoids "
                             "disassembling every binary twice.")
    parser.add_argument("--out", required=True, help="output coverable .jsonl")


def run(args):
    objdump = args.objdump or (args.toolchain_prefix + "objdump")
    addr2line = args.addr2line or (args.toolchain_prefix + "addr2line")
    opts = path_options(args)
    want = getattr(args, "denominator", None) or "auto"

    seen = None
    used = ""
    detail = ""

    if want in ("objdump", "auto"):
        try:
            seen, count = objdump_inventory(args, opts, objdump, addr2line)
            if not seen:
                raise RuntimeError(
                    f"{args.elf}: {count} instruction addresses resolved to no "
                    f"source line inside the selected paths (check "
                    f"--source-root/--keep/--exclude, and that the ELF has "
                    f"DWARF)")
            used, detail = "objdump", f"{count} instr addrs"
        except (OSError, RuntimeError, ValueError) as e:
            if want == "objdump":
                print(f"error: {e}", file=sys.stderr)
                print(f"error: refusing to write an empty coverable "
                      f"inventory, which would make every report read 100%. "
                      f"Try --denominator dwarf.", file=sys.stderr)
                return 1
            seen = None
            print(f"note: the objdump denominator is unavailable ({e})",
                  file=sys.stderr)
            print(f"note: falling back to the DWARF .debug_line denominator",
                  file=sys.stderr)

    if seen is None:
        try:
            seen, rows = dwarf_inventory(args, opts)
        except (OSError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if not seen:
            print(f"error: {args.elf}: the DWARF line table has {rows} rows "
                  f"but none resolved to a source line inside the selected "
                  f"paths (check --source-root/--keep/--exclude). Refusing to "
                  f"write an empty coverable inventory, which would make every "
                  f"report read 100%.", file=sys.stderr)
            return 1
        used, detail = "dwarf", f"{rows} line-table rows"

    if used == "objdump" and getattr(args, "cross_check", True):
        try:
            other, _rows = dwarf_inventory(args, opts)
        except (OSError, RuntimeError) as e:
            print(f"note: denominator cross-check skipped ({e})",
                  file=sys.stderr)
        else:
            for msg in cross_check_messages(seen, other):
                print(f"warning: {args.elf}: {msg}", file=sys.stderr)

    with open(args.out, "w") as out:
        for key in sorted(seen):
            norm, line, func = key
            out.write(json.dumps({
                "file": norm, "line": line, "function": func,
                "arch": args.arch, "denominator": used,
                "address": "0x%x" % seen[key],
            }) + "\n")

    files = len({k[0] for k in seen})
    print(f"{args.elf}: {detail} -> {len(seen)} coverable lines across "
          f"{files} files ({used} denominator) -> {args.out}", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
