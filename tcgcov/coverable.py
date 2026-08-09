"""ELF -> coverable-line inventory JSONL (the denominator for real coverage).

A source line is "coverable" iff at least one EXECUTABLE instruction address in
the ELF maps to it via the DWARF line table -- a conservative definition that
avoids DWARF artifacts. Implementation: disassemble the ELF (`<prefix>objdump
-d`, which emits only executable sections) to enumerate every instruction
address, then resolve them through the DWARF line table with the SAME batched
addr2line and SAME path normalization as the covered side, so coverable and
covered keys are guaranteed comparable.

Output JSONL fields: file, line, function, arch, address.
"""

import argparse
import json
import subprocess
import sys

from .cfg import match_insn_line
from .symbolize import iter_covered_lines
from .cliargs import add_symbolize_args
from .paths import path_options


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


def add_arguments(parser):
    parser.add_argument("--elf", required=True, help="ELF to inventory")
    add_symbolize_args(parser)
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

    try:
        if args.disasm:
            with open(args.disasm, encoding="utf-8",
                      errors="surrogateescape") as f:
                text = f.read()
            addrs = parse_addresses(text)
        else:
            addrs, text = disassemble_addresses(objdump, args.elf)
    except (OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not addrs:
        # An empty coverable inventory is not a benign result: `lcov` then uses
        # the covered lines as their own denominator and reports 100%. Fail
        # loudly instead, and distinguish the two ways of getting here.
        source = args.disasm or objdump
        if text.strip():
            print(f"error: {args.elf}: {source} produced "
                  f"{len(text.splitlines())} lines of output but no "
                  f"instruction addresses were parsed from it -- unrecognized "
                  f"disassembly layout. Refusing to write an empty coverable "
                  f"inventory, which would make every report read 100%.",
                  file=sys.stderr)
        else:
            print(f"error: {args.elf}: {source} disassembled no executable "
                  f"code at all", file=sys.stderr)
        return 1

    # (file, line, function) -> representative address. A line is coverable if
    # ANY executable address maps to it.
    seen = {}
    try:
        for norm, line, func, _depth, addr in iter_covered_lines(
                addr2line, args.elf, addrs, path_options(args)):
            seen.setdefault((norm, line, func), addr)
    except (OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    with open(args.out, "w") as out:
        for key in sorted(seen):
            norm, line, func = key
            out.write(json.dumps({
                "file": norm, "line": line, "function": func,
                "arch": args.arch, "address": "0x%x" % seen[key],
            }) + "\n")

    files = len({k[0] for k in seen})
    print(f"{args.elf}: {len(addrs)} instr addrs -> {len(seen)} coverable "
          f"lines across {files} files -> {args.out}", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
