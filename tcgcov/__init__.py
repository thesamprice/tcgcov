"""tcgcov -- host-side tooling for tcgcov QEMU code-coverage artifacts.

The QEMU TCG plugin (tcgcov.c) writes compact TCGCOV1 .cov files; this
package turns them into symbolized, source-line LCOV/HTML coverage reports,
and -- from the plugin's EDGE records plus a static CFG recovered from
`objdump -d` -- LCOV branch coverage.

Public API:
    read_cov, read_edges, read_all, normalize_path, PathOptions,
    path_options, run_addr2line, iter_covered_lines, analyze, get_profile

CLI (also runnable as `python3 -m tcgcov`):
    tcgcov dump|symbolize|coverable|branches|lcov|merge
"""

from .format import (read_cov, read_edges, read_all, MAGIC, FLAG_HAS_COUNTS,
                     FLAG_HAS_EDGES, FLAG_EDGE_COUNTS)
from .paths import normalize_path, path_options, PathOptions, PRESETS
from .symbolize import run_addr2line, iter_covered_lines
from .cfg import analyze, get_profile, load_profile_file, ARCH_PROFILES

__version__ = "0.1.0"

__all__ = [
    "read_cov", "read_edges", "read_all", "normalize_path", "path_options",
    "PathOptions", "PRESETS", "run_addr2line",
    "iter_covered_lines", "analyze", "get_profile", "load_profile_file",
    "ARCH_PROFILES", "MAGIC", "FLAG_HAS_COUNTS", "FLAG_HAS_EDGES",
    "FLAG_EDGE_COUNTS", "__version__",
]
