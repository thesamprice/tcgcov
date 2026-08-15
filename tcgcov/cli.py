"""Unified `tcgcov` CLI dispatching to the subcommand modules."""

import argparse

from . import (addr2line, branches, contexts, coverable, lcov, merge, dump,
               modmap, restrict, gap, rebase)
from . import __version__

# (subcommand name, module, short help). The module supplies add_arguments(p)
# and run(args); `symbolize`/`coverable` are the covered/coverable producers.
SUBCOMMANDS = [
    ("dump", dump, "inspect a .cov artifact (header/metadata/addresses/edges)"),
    ("symbolize", addr2line, "covered .cov + ELF -> per-source-line JSONL"),
    ("coverable", coverable, "ELF -> coverable-line inventory JSONL"),
    ("branches", branches,
     "ELF + .cov edges -> per-branch-outcome JSONL (BRDA input)"),
    ("rebase", rebase,
     "shift a runtime-address window to link addresses (kernel modules)"),
    ("contexts", contexts,
     "list a TCGCOV2 artifact's contexts, or extract one as TCGCOV1"),
    ("modmap", modmap,
     "slice a .cov by a JSON module map into per-section artifacts"),
    ("lcov", lcov, "symbolized JSONL -> per-test LCOV .info"),
    ("merge", merge, "merge per-test .info -> aggregate (by source+line)"),
    ("restrict", restrict,
     "limit an aggregate .info to symbols present in a target ELF"),
    ("gap", gap,
     "lines an app executes that a baseline (suite) does not cover"),
]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="tcgcov",
        description="Host-side tooling for tcgcov QEMU coverage artifacts.")
    parser.add_argument("--version", action="version",
                        version=f"tcgcov {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True
    for name, mod, help_text in SUBCOMMANDS:
        sp = sub.add_parser(
            name, help=help_text, description=mod.__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)
        mod.add_arguments(sp)
        sp.set_defaults(_run=mod.run)
    args = parser.parse_args(argv)
    return args._run(args)


if __name__ == "__main__":
    import sys
    sys.exit(main())
