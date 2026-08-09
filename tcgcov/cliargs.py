"""Shared argparse options used by the symbolize (addr2line) and coverable
(dwarf_lines) subcommands."""

from .paths import PRESETS


def add_symbolize_args(parser):
    """Add the path/toolchain options common to symbolize and coverable."""
    parser.add_argument("--toolchain-prefix", default="",
                        help="toolchain prefix for objdump/addr2line, e.g. "
                             "riscv64-unknown-elf- (default: empty, i.e. the "
                             "host toolchain)")
    parser.add_argument("--addr2line",
                        help="explicit addr2line path (overrides "
                             "--toolchain-prefix)")
    parser.add_argument("--source-root",
                        help="source root: keep every source file under it, "
                             "normalized relative to it, and drop files "
                             "outside it (toolchain headers, libc, other "
                             "trees). Required for cross-binary merging")
    parser.add_argument("--preset", choices=sorted(PRESETS), metavar="NAME",
                        help="project layout preset, expanding to a fixed set "
                             "of markers/trees/exclusions (choices: %s)"
                             % ", ".join(sorted(PRESETS)))
    parser.add_argument("--keep", action="append", default=[], metavar="MARKER",
                        help="extra 'keep from here' path substring "
                             "(repeatable), e.g. /myproject/ to keep source "
                             "living outside the source root")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="PATTERN",
                        help="drop normalized paths matching this fnmatch "
                             "glob (repeatable), e.g. 'tests/**' "
                             "(default: no exclusions)")
    parser.add_argument("--include-testsuites", action="store_true",
                        help="with --preset rtems, keep testsuites/** lines "
                             "that the preset excludes")
    parser.add_argument("--all-paths", action="store_true",
                        help="keep every source file by absolute path (for "
                             "app ELFs mixing code from different trees); "
                             "absolute paths defeat cross-binary merging")
    parser.add_argument("--arch", default="",
                        help="arch tag for output records (covered: defaults to "
                             "the .cov target_name when empty)")
