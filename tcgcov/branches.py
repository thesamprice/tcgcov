"""ELF + .cov edges -> per-branch-outcome JSONL (the input to LCOV BRDA).

Line coverage says a line ran. It cannot say that `if (rc != 0)` was only ever
false -- the line runs either way, so the untested error path stays green. That
is what branch coverage is for, and it needs two things this module joins:

  * the DENOMINATOR: every conditional branch in the ELF and its two outcomes,
    reconstructed statically from `objdump -d` (see cfg.py). Every branch is
    emitted even if it never executed -- a branch that never ran must show as
    uncovered, not be absent.
  * the NUMERATOR: the EDGE records the QEMU plugin writes, each one an
    observed (last-insn-of-source-block -> first-insn-of-dest-block) transfer.
    An edge resolves an outcome when its source lies in the branch's block at
    or after the branch, which is what makes delay-slot architectures work.

Branches whose target is not statically knowable (register targets, jump
tables, PowerPC's implicit-LR conditional returns) are counted and EXCLUDED --
reporting them as uncovered would be a lie, since nothing could ever cover them.
The count appears in the summary line.

Output JSONL fields: file, line, function, address, block, taken, nottaken,
evaluated, target, fallthrough, arch, test_id, bsp.
"""

import argparse
import json
import sys
from collections import defaultdict

from . import cfg
from .format import read_all
from .symbolize import iter_covered_lines
from .cliargs import add_symbolize_args
from .paths import path_options


def resolve_locations(addr2line, elf, addrs, args):
    """Return {address: (file, line, function)} for the branch addresses.

    Uses the same batched addr2line and the same path normalization as the
    covered/coverable producers, so branch records key on exactly the source
    identity that line coverage and merging already use. The innermost
    (smallest-depth) frame wins: that is the source construct the branch
    belongs to.
    """
    best = {}
    depths = {}
    for norm, line, func, depth, addr in iter_covered_lines(
            addr2line, elf, addrs, path_options(args)):
        if addr not in depths or depth < depths[addr]:
            depths[addr] = depth
            best[addr] = (norm, line, func)
    return best


def build_records(branch_points, counts, locations, base_fields):
    """Join static branch points with observed counts -> LCOV-ready records.

    `block` numbers the branch points that share a source line, in address
    order, so the (file, line, block, branch) key stays stable across the
    different test binaries an aggregate merges -- the same way line coverage
    keys on (file, line) rather than on an address.
    """
    by_line = defaultdict(list)
    for bp in branch_points:
        if bp.indirect:
            continue
        loc = locations.get(bp.addr)
        if loc is None:
            continue          # branch in code with no (kept) source mapping
        by_line[(loc[0], loc[1])].append((bp, loc[2]))

    records = []
    for (sf, line) in sorted(by_line):
        entries = sorted(by_line[(sf, line)], key=lambda e: e[0].addr)
        for block, (bp, func) in enumerate(entries):
            bc = counts.get(bp.addr)
            rec = {
                "file": sf, "line": line, "function": func,
                "address": "0x%x" % bp.addr, "block": block,
                "taken": bc.taken if bc else 0,
                "nottaken": bc.nottaken if bc else 0,
                "evaluated": bool(bc and bc.evaluated),
                "target": "0x%x" % bp.taken,
                "fallthrough": "0x%x" % bp.fallthrough,
            }
            rec.update(base_fields)
            records.append(rec)
    return records


def add_arguments(parser):
    parser.add_argument("--elf", required=True,
                        help="ELF whose branches form the denominator")
    parser.add_argument("--cov", action="append", default=[], metavar="FILE",
                        help="input .cov (TCGCOV1) with EDGE records "
                             "(repeatable; omit for a static-only inventory "
                             "where every branch is reported unexecuted)")
    add_symbolize_args(parser)
    parser.add_argument("--objdump", help="explicit objdump path")
    parser.add_argument("--disasm", metavar="FILE",
                        help="read `objdump -d` output from FILE instead of "
                             "running objdump (debugging / offline use)")
    parser.add_argument("--arch-profile", action="append", default=[],
                        metavar="FILE",
                        help="JSON arch profile(s) to register before "
                             "analysis, so an unsupported ISA can be added "
                             "without editing the package (repeatable)")
    parser.add_argument("--test-id", help="override test_id from .cov metadata")
    parser.add_argument("--bsp", help="override bsp from .cov metadata")
    parser.add_argument("--out", required=True, help="output .jsonl file")


def run(args):
    addr2line = args.addr2line or (args.toolchain_prefix + "addr2line")
    objdump = args.objdump or (args.toolchain_prefix + "objdump")

    for path in args.arch_profile:
        try:
            names = cfg.load_profile_file(path)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"arch profile(s) from {path}: {', '.join(names)}",
              file=sys.stderr)

    # Edges + metadata from every .cov, summed (each run is another sample of
    # the same static CFG).
    meta = {}
    edges = []
    for path in args.cov:
        try:
            m, _addrs, _counts, e = read_all(path)
        except (OSError, ValueError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        meta = meta or m
        if not e:
            print(f"warning: {path} has no EDGE records (plugin run without "
                  f"edge collection?)", file=sys.stderr)
        edges.extend(e)

    try:
        if args.disasm:
            with open(args.disasm) as f:
                text = f.read()
        else:
            text = cfg.disassemble(objdump, args.elf)
    except (OSError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    arch = args.arch or meta.get("target_name", "") or cfg.detect_arch(text)
    profile = cfg.get_profile(arch)
    if not profile.supported:
        known = sorted({p.name for p in cfg.ARCH_PROFILES.values()
                        if p.supported})
        print(f"error: branch coverage unsupported for this arch "
              f"({arch or 'unknown'}): no branch mnemonics are known for it, "
              f"and guessing would produce wrong data.\n"
              f"       known arches: {', '.join(known)}\n"
              f"       add your own with --arch-profile FILE (see "
              f"tcgcov/cfg.py load_profile_file for the schema)",
              file=sys.stderr)
        return 2

    try:
        graph = cfg.analyze(text, profile)
    except cfg.DisassemblyParseError as e:
        # An empty branch inventory and exit 0 would read downstream as "this
        # binary has no branches", i.e. a wrong number reported as success.
        print(f"error: {args.disasm or args.elf}: {e}", file=sys.stderr)
        return 1
    counts, stats = cfg.match_edges(graph, edges)

    locations = {}
    direct = [bp for bp in graph.branch_points if not bp.indirect]
    if direct:
        try:
            locations = resolve_locations(
                addr2line, args.elf, [bp.addr for bp in direct], args)
        except (OSError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    base = {
        "arch": arch,
        "test_id": args.test_id or meta.get("test_id", ""),
        "bsp": args.bsp or meta.get("bsp", ""),
    }
    records = build_records(graph.branch_points, counts, locations, base)

    with open(args.out, "w") as out:
        for rec in records:
            out.write(json.dumps(rec) + "\n")

    n_total = len(graph.branch_points)
    n_indirect = len(graph.indirect_branches)
    n_unmapped = len(direct) - len({r["address"] for r in records})
    outcomes = 2 * len(records)
    hit = sum((1 if r["taken"] else 0) + (1 if r["nottaken"] else 0)
              for r in records)
    evaluated = sum(1 for r in records if r["evaluated"])
    pct = (100.0 * hit / outcomes) if outcomes else 0.0

    print(f"{args.elf} [{profile.name}]: {n_total} conditional branches "
          f"({n_indirect} indirect/unknown target -> EXCLUDED from branch "
          f"coverage, {n_unmapped} without source mapping), "
          f"{len(records)} reported / {outcomes} outcomes",
          file=sys.stderr)
    print(f"  edges: {stats['edges']} observed, {stats['matched']} matched, "
          f"{stats['ignored']} ignored (source block does not end in a "
          f"conditional branch), {stats['unresolved']} unresolved",
          file=sys.stderr)
    print(f"  {evaluated}/{len(records)} branches evaluated, {hit}/{outcomes} "
          f"outcomes taken ({pct:.1f}%) -> {args.out}", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(ap)
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
