"""The genhtml command line, shared by `report`, `restrict` and `gap`.

lcov 2 checks a trace file for consistency before rendering it, and one of
its checks rejects data tcgcov produces faithfully: "line is hit but no
branches on line have been evaluated". When the optimizer duplicates a source
line, as it does for the tails of switch cases and if/else arms, the copy that
ran may hold no branch while the copies that hold the line's branches never
ran. The line was executed and its branches were not, and the branch records
say exactly that ('-', never evaluated). gcov cannot produce this, since it
counts per basic block of the source rather than per executed instruction,
which is why lcov treats it as corruption.

Reporting such a branch as '0' instead would claim it was evaluated, which is
the one thing branch coverage must not get wrong. So the check is downgraded
to a warning instead: with lcov 2 or later, genhtml is run with
`--ignore-errors inconsistent`. lcov 1.x has no such category and rejects it,
so the version is checked first.
"""

import re
import subprocess

_MAJOR = {}


def lcov_major(genhtml="genhtml"):
    """The major version of the lcov that `genhtml` belongs to, or None when
    it cannot be run or does not say."""
    if genhtml not in _MAJOR:
        # Popen, not run: callers' tests mock subprocess.run to stand in for
        # the rendering itself, and the probe must not consume that mock.
        try:
            with subprocess.Popen([genhtml, "--version"], text=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT) as p:
                out = p.communicate(timeout=30)[0] or ""
        except (OSError, subprocess.SubprocessError):
            out = ""
        m = re.search(r"LCOV version (\d+)", out)
        _MAJOR[genhtml] = int(m.group(1)) if m else None
    return _MAJOR[genhtml]


def ignore_errors(genhtml="genhtml"):
    """The --ignore-errors categories for this genhtml."""
    cats = ["source"]
    major = lcov_major(genhtml)
    if major is not None and major >= 2:
        cats.append("inconsistent")
    return ",".join(cats)


def command(info, html_dir, genhtml="genhtml", branch_coverage=False,
            extra=()):
    """The genhtml argv rendering INFO into HTML_DIR (both made absolute by
    the caller).  EXTRA is appended last, so it can override."""
    cmd = [genhtml, info, "--output-directory", html_dir,
           "--quiet", "--ignore-errors", ignore_errors(genhtml)]
    if branch_coverage:
        cmd.append("--branch-coverage")
    cmd.extend(extra)
    return cmd
