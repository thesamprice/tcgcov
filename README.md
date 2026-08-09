# tcgcov

[![CI](https://github.com/thesamprice/tcgcov/actions/workflows/ci.yml/badge.svg)](https://github.com/thesamprice/tcgcov/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tcgcov.svg)](https://pypi.org/project/tcgcov/)
[![Python](https://img.shields.io/pypi/pyversions/tcgcov.svg)](https://pypi.org/project/tcgcov/)
[![Licence: GPL-2.0-or-later](https://img.shields.io/badge/licence-GPL--2.0--or--later-blue.svg)](LICENSE)

**Source-line and branch coverage for binaries running under QEMU — no guest
instrumentation, no `--coverage` rebuild, no instruction trace.**

*tcgcov* = **TCG** + **cov**erage. TCG is QEMU's [Tiny Code
Generator](https://www.qemu.org/docs/master/devel/tcg.html), the just-in-time
translator that turns guest instructions into host code. It is also the layer
QEMU's plugin API hooks into, and it is how this tool observes execution: a
callback per translated block. That is the whole reason nothing has to be
rebuilt or instrumented — the coverage comes from the emulator's own
translation step, not from the program.

A small QEMU TCG plugin records which guest code addresses execute and writes
one compact binary artifact per run. Host-side Python (pure standard library,
no third-party dependencies) then symbolizes those addresses against DWARF,
builds a **coverable-line denominator** by disassembling the ELF, and emits
LCOV `.info` files that `genhtml` renders. Because both the numerator and the
denominator are reduced to `(source path, line)` keys by the same normalizer,
reports from separately-linked binaries **merge correctly**.

It works on bare-metal firmware with no OS, no filesystem and no libc — the
guest never knows it is being measured. If QEMU can run it, tcgcov can measure
it.

> **Status: early.** tcgcov was extracted from a working internal tool (it was
> called *RTQCov* and lived inside a QEMU fork, where it measured RTEMS test
> suites). It has been used in anger, but only against a narrow set of targets.
> The generalization is new: expect rough edges outside the paths that were
> exercised in its previous life. Bug reports with a reproducer are very
> welcome.

---

## The pipeline

```
  target ELF
      │
      ├──►  QEMU system emulation + libtcgcov.so  ──►  run.cov
      │         (executed guest addresses, optional hit counts, optional edges)
      │
      │     ┌─────────────────────────────────────────────────────────────┐
      └────►│ objdump -d  +  addr2line   (target toolchain, DWARF)        │
            └─────────────────────────────────────────────────────────────┘
                    │                                   │
                    ▼                                   ▼
            covered.jsonl                        coverable.jsonl
        (source lines that ran)          (source lines that COULD run — the
                    │                     denominator: every line with at
                    │                     least one emitted instruction)
                    └──────────────┬──────────────────┘
                                   ▼
                          per-run LCOV .info
                                   │
                    merge by (source path, line)
                                   ▼
                        aggregate .info  ──►  genhtml  ──►  HTML
```

Everything after the `.cov` file is offline. The emulated run itself costs one
hash-table insert per translation block.

---

## Why merge by source + line, not by address

This is the design decision the rest of the tool hangs off.

The same source file is frequently compiled into **several separately-linked
binaries** — a per-test-case executable in a statically-linked test suite, the
same library linked into two applications, one firmware image built for two
boards. A given source line then lands at a **different address in each
binary**, and the same address means a different line in each binary.

Merging coverage by address is therefore simply wrong across binaries: it is
neither a union nor an intersection of anything meaningful. Tools that emit raw
address sets (DrCov and friends) hit this wall by construction — their identity
is "offset *N* into module *M*".

tcgcov normalizes every covered *and* coverable address to a repo-relative
`(source path, line)` key and merges on that identity. Both sides go through
one symbolizer and one path normalizer, so the keys are guaranteed comparable:
`covered ⊆ coverable` holds with no path drift. The result is that you can run
a hundred separately-linked test executables and get one honest percentage for
the shared code underneath them.

---

## Installation

```bash
pip install tcgcov        # host-side tooling; pure stdlib, no dependencies
```

The PyPI distribution name is `tcgcov`. Until the first release lands, install
from a checkout (editable, so edits take effect immediately):

```bash
git clone https://github.com/thesamprice/tcgcov
pip install -e ./tcgcov
```

You can also skip installing entirely and run the package in place:

```bash
python3 -m tcgcov --help
# or from anywhere:
PYTHONPATH=/path/to/tcgcov python3 -m tcgcov --help
```

If your system Python is externally managed (PEP 668), use `pipx` or a venv.

**Prerequisites**

| Need | For |
|---|---|
| QEMU built with `--enable-plugins` | running the plugin |
| Target toolchain `<prefix>addr2line` and `<prefix>objdump` on `PATH` | symbolization and the coverable inventory |
| `genhtml` (from `lcov`) | the HTML report — optional, `.info` files are useful alone |
| Python ≥ 3.8 | the host tools |

The target binary must carry DWARF (`-g`). It does **not** need to be built
with `--coverage`, `-fprofile-arcs`, or any other instrumentation, and it does
not need to be unoptimized.

---

## Building the plugin

The plugin compiles against `qemu-plugin.h` and glib only — a full configured
QEMU tree is not required:

```bash
cd plugin
make QEMU_INCLUDE=<qemu-source>/include      # from a QEMU checkout
# or
make QEMU_PLUGIN_H=/path/to/qemu-plugin.h    # from a single header
```

This produces `libtcgcov.so` (`libtcgcov.dylib` on macOS, built as a bundle).

> The header **must match the QEMU you load the plugin into**. QEMU versions
> its plugin ABI via `QEMU_PLUGIN_VERSION` and refuses to load a mismatch.

---

## Running it

Add the plugin to any QEMU system-emulation command line:

```bash
qemu-system-<target> ... \
  -plugin ./libtcgcov.so,out=run1.cov,mode=tb-insn,elf=/path/to/image.elf,counts=1
```

Plugin arguments are `key=value`, comma-separated:

| Argument | Default | Meaning |
|---|---|---|
| `out=` | `tcgcov.cov` | output artifact path (written atomically via `.tmp` + rename) |
| `mode=` | `tb-insn` | see the fidelity table below |
| `filter=` | *(none)* | `0xSTART-0xEND[,…]` address ranges to record; empty means everything |
| `counts=` | `off` | record 64-bit execution counts (turns the report into a hotspot view) |
| `edges=` | `off` | record control-flow edges, the input to branch coverage |
| `elf=` | `""` | path to the ELF, copied into the artifact's metadata so the host tools need no manifest |
| `test_id=`, `bsp=` | `""` | free-form labels (run name, board/platform) copied into the metadata |
| `verbose=` | `off` | log a one-line summary at exit |

Boolean arguments accept `on`/`off`, `true`/`false`, `yes`/`no` and `1`/`0`.
**An unknown argument, an unparseable value or a malformed `filter=` range
refuses to start QEMU** rather than running with settings you did not ask for —
a run that silently records nothing costs far more to diagnose than a failed
launch.

`mode=` trades cost against fidelity:

| `mode=` | Records | Fidelity |
|---|---|---|
| `tb` | one address per executed block (its start) | exact for what it claims: reaching a block proves its first instruction was reached |
| `tb-insn` *(default)* | every instruction that individually executed | **exact** — an execution callback per instruction, so an instruction after an abort point (exception, interrupt) is never reported |
| `tb-insn-fast` | every instruction the block was *translated* with, gated on block entry | cheap, but **over-reports**: a block that aborts part way through still reports all of its instructions |

The artifact records which fidelity it was produced at, so a reader can tell.

**How it works.** A translation callback records each block and its in-range
instruction addresses; a minimal execution callback marks the block executed.
At QEMU exit the executed blocks are expanded to addresses, sorted,
de-duplicated and written. Output size tracks *unique code covered*, not how
long the run was — an hour-long soak test and a one-second smoke test produce
files of comparable size. The structure follows QEMU's own
`contrib/plugins/drcov.c`.

**Guests that never exit cleanly** — the usual case for firmware — are fine.
QEMU runs the plugin's exit notifier on `SIGTERM`, so the artifact is still
written when the harness kills the emulator.

The on-disk format (`TCGCOV1`) is documented in [`docs/FORMAT.md`](docs/FORMAT.md);
`tcgcov dump` inspects any artifact.

### Hit counts

With `counts=1` the plugin records how many times each block executed, and the
count survives all the way to `DA:<line>,<count>` in the LCOV output, so the
same HTML report doubles as a hotspot view. Coverage is just `count > 0`, so
percentages are identical to a run without counts. Granularity is the
translation block: every instruction in a block shares the block's count, and a
line's count is the **max** over its instruction addresses (so it is not
inflated by how many instructions a line compiled into). The counter is 64-bit,
because an idle loop overflows 32 bits easily.

---

## The host-side tools

One command, several subcommands. `tcgcov <command> --help` for the full
options of each.

| Command | Does |
|---|---|
| `dump` | inspect a `.cov` artifact — header, metadata, addresses, counts, edges |
| `symbolize` | `.cov` + ELF → JSONL of covered `(file, line, function)` — the numerator |
| `coverable` | ELF → JSONL of every coverable source line — the denominator |
| `branches` | `.cov` + ELF → branch outcomes for LCOV `BRDA:` records |
| `lcov` | symbolized JSONL (+ coverable, + branches) → per-run `.info` |
| `merge` | many per-run `.info` → one aggregate, merged by source + line |
| `restrict` | narrow a finished aggregate to only the code present in a target ELF |
| `gap` | lines an application executes that a baseline suite never covers |

### `symbolize` — what ran

Runs every covered address through a single batched
`addr2line -a -f -C -i` (`-a` delimits address groups, `-i` preserves inlined
frames), then normalizes each resulting path.

```bash
tcgcov symbolize --cov run1.cov --elf image.elf \
  --toolchain-prefix riscv64-unknown-elf- --source-root /path/to/src \
  --out run1.covered.jsonl
```

### `coverable` — the denominator

A line is coverable **iff at least one executable instruction address maps to
it**. The implementation is deliberately dependency-free: disassemble the
executable sections with `objdump -d` to enumerate instruction addresses, then
resolve them through `.debug_line` with the *same* `addr2line` and the *same*
normalizer used for covered lines. That shared path is what guarantees the two
sets are comparable.

```bash
tcgcov coverable --elf image.elf \
  --toolchain-prefix riscv64-unknown-elf- --source-root /path/to/src \
  --out image.coverable.jsonl
```

This inventory depends only on the ELF, not on the run, so the driver caches it
per binary.

**Two sources, selected with `--denominator`.** Disassembly is the most fragile
part of the tool — a layout the parser does not recognise yields *nothing*, and
an empty denominator makes every report read 100%. So there is a second,
architecture-independent source:

| `--denominator` | Source | Notes |
|---|---|---|
| `objdump` | `objdump -d` + `addr2line` | The conservative definition above. Identical mechanism to the covered side, so the keys match by construction. |
| `dwarf` | `.debug_line`, read directly | No objdump, no addr2line, no architecture knowledge. Slightly broader: a line-table row is not proof an instruction was emitted, and it does not see the inlined call sites `addr2line -i` reports. |
| `auto` *(default)* | objdump, falling back to DWARF | An unrecognised disassembly degrades to a correct, slightly broader denominator instead of no coverage at all. |

The DWARF reader is pure standard library (`tcgcov/dwarfline.py`) and handles
DWARF 2–5, both endiannesses, ELF32/64, the 64-bit DWARF format and compressed
debug sections. It is checked row-for-row against `readelf --debug-dump=decodedline`.

Whenever the objdump source is used the DWARF rows are computed anyway and the
two are compared; a large one-sided difference means one of the parsers is
producing garbage. That check warns, never fails, and `--no-cross-check` turns
it off.

> Both sources run every path through the *same* normalizer, because the
> covered side resolves addresses through `addr2line`: if the two disagreed
> about a path, `covered ⊆ coverable` would quietly stop holding. On the
> reference binary they produce a byte-identical `.info`.

### `lcov` and `merge`

`lcov` emits `DA:line,1` for hit lines and `DA:line,0` for coverable-but-not-hit
lines, so `genhtml` shows a true percentage. Without `--coverable` you get a
covered-only report, which trivially reads 100%.

`merge` combines per-run `.info` files by source path and line, tracking
coverable and covered separately: a line is covered in the aggregate if **any**
run covered it, and coverable if **any** run listed it. Counts are summed, so
the aggregate shows total executions across the campaign.

### `restrict` and `gap` — two complementary questions

These exist for qualification work, where "what is our coverage number" is not
actually the question you have.

- **`restrict`** — *"how well is the code in **this** binary tested?"* Take a
  finished aggregate and keep only the lines present in a given target ELF,
  dropping everything else. It is filter-only: covered counts come from the
  aggregate and lines the campaign never had are not invented, so
  `restricted ⊆ aggregate`. The percentage usually *rises*, because the
  denominator shrinks to just the shipping code.

- **`gap`** — *"what does my application run that the test suite never tests?"*
  The set difference (app-covered − baseline-covered). The report's universe is
  the app-executed lines and a line counts as covered only if the baseline also
  covers it — so in the HTML the **red lines are the gap**: code your
  application demonstrably executes and your tests demonstrably do not.

Both require that the two sides share normalization: symbolize with the same
path flags and the same source root, or the keys will not line up.

A few behaviours worth knowing:

- **`gap --app` detects its input by content, not by filename.** It accepts
  either a symbolized `.jsonl` or an LCOV `.info` whatever the file is called;
  an unrecognizable file is an error rather than a silent empty report.
- **`gap` reports branch outcomes too** when the app side is an `.info`
  carrying `BRDA` records. The branch universe is the outcomes the app took,
  and an outcome counts as covered only if the baseline took it as well — the
  same rule as lines, so red still means gap. Outcomes the app never evaluated
  stay out of the denominator.
- **Neither command will write an empty report.** An empty aggregate, an empty
  target inventory, an empty baseline, or zero overlap between the two sides is
  a hard error. All of those used to exit 0 with a plausible-looking `0.0%` or
  `0 GAP lines` — which reads as "nothing to worry about" when it actually
  means the two sides' paths never matched. When it is a normalization
  mismatch, the error says so.

### Path selection

Every producer must be given the *same* path options, or the covered and
coverable sides derive different keys and the merge is wrong. The driver below
does this for you.

- `--source-root <dir>` — **the normal choice.** Keep every source file under
  the root, normalized relative to it, and drop everything outside it
  (toolchain headers, C-library sources, crt objects). Relative paths are what
  make cross-binary merging work.
- `--all-paths` — keep every source file by its **absolute** path. Best for
  single-binary reports; absolute paths defeat cross-binary merging by design.
- `--keep <marker>` (repeatable) — a "keep from here" path substring, for code
  that lives outside the source root. That tree is kept and normalized relative
  to the marker.
- `--exclude <glob>` (repeatable) — drop normalized paths matching an
  `fnmatch` glob, e.g. `--exclude 'tests/**'`. No exclusions by default.
- `--preset <name>` — a named bundle of the above for a known project layout.
  `rtems` keeps only `cpukit`, `bsps` and `contrib` and excludes
  `testsuites/**`. Presets are a one-entry dict in `tcgcov/paths.py`; adding
  one for your project is a few lines.

With **none** of these given, the tools keep absolute paths and print a warning
rather than dropping everything — a report you cannot merge is better than a
silently empty one.

### One-command driver

`tcgcov-report.sh` runs the whole chain over a directory of `.cov` files. It
reads each binary's path from the artifact's own metadata, so there is no
manifest to maintain:

```bash
./tcgcov-report.sh --raw-dir coverage/raw --out-dir coverage \
  --source-root /path/to/src \
  --toolchain-prefix riscv64-unknown-elf- --arch riscv
```

Producing:

```
coverage/symbolized/*.jsonl
coverage/coverable/*.jsonl
coverage/branches/*.jsonl
coverage/lcov/per-test/*.info
coverage/lcov/aggregate-<arch>.info
coverage/html/index.html
```

The arch label defaults to the target recorded by the plugin, and an empty
`--toolchain-prefix` uses the host toolchain (for measuring host binaries under
QEMU user-mode or a host-targeted image).

---

## Branch coverage

Line coverage answers "did this line run". It cannot tell you that an `if`
always took the same side. tcgcov additionally reconstructs the static control
flow — basic blocks and, for each conditional branch, its taken and fall-through
successors — and matches it against the edges the plugin observed, emitting
LCOV `BRDA:` records. `genhtml --branch-coverage` then reports a branch whose
`else` side never executed as **half covered** rather than fully covered.

Enable edge recording with `edges=1` on the plugin, then run
`tcgcov branches`; the driver does both by default and takes `--no-branches` to
turn it off. See `tcgcov branches --help` for the current options.

### How a branch is identified across binaries

Branch records have to merge across separately-linked binaries for the same
reason lines do, so they need a source-level identity too. An LCOV branch is
addressed by `BRDA:<line>,<block>,<branch>`, and tcgcov fills `block` with **the
source line the branch jumps to** (falling back to its fall-through's line, then
to 0), resolved through the same `addr2line` and the same path normalizer as
everything else.

The obvious alternative — numbering the branches found on a line — is wrong, and
was the original implementation. A rank is a property of *this* binary: inline a
call site once more in one image, or let the optimizer fold one half of
`a && b` away in another, and every rank after it shifts, so the aggregate sums
two unrelated branches and reports a count belonging to neither. A target's
source line does not move when the image is relinked.

Two branches on one line normally jump to different lines — for `a || b`, the
first test exits into the body and the second past it — so they normally stay
distinct. Where they genuinely coincide (`a && b` compiled so both tests exit to
the same `else`) they are indistinguishable at source-line granularity and are
summed, which costs a little resolution and invents nothing.

DWARF's `discriminator` would be the purpose-built answer and `addr2line` does
print it, but measurement says it cannot carry this: GCC assigns discriminators
to the *blocks* on a line rather than to the branches that select them (for
`if (a && b)` at `-O2`, both condition branches come back with no discriminator
while the two call blocks get 1 and 2), and Clang emits none at all unless built
with `-fdebug-info-for-profiling`. A column number would be better still, and
`addr2line` does not report one.

---

## Architecture support

**Line coverage is architecture-independent.** It needs nothing but `objdump`
and `addr2line` from the target's own toolchain, so any target QEMU emulates
and binutils understands works out of the box.

**Branch coverage needs a per-architecture profile.** Deciding which
disassembled mnemonics are conditional branches, which are calls or returns,
and where each branch's targets are, is ISA-specific. So is delay-slot
behaviour: on MicroBlaze, MIPS and SPARC the instruction *after* a branch
executes before the transfer happens, which changes both which block an
instruction belongs to and which address appears as an edge's source.

A profile captures exactly that. Architectures without one are **not guessed
at** — tcgcov reports branch coverage as unsupported for that target rather
than emitting numbers it cannot justify, and line coverage is unaffected. You
can supply a profile from a file without modifying the package; see
`tcgcov branches --help`. Contributing a profile for your ISA is the single
most useful patch you can send.

**Bringing tcgcov up on a new processor:**
[`docs/ARCHITECTURES.md`](docs/ARCHITECTURES.md) is the reference for that
work — the per-architecture status of the eight shipped profiles and how much
evidence stands behind each (they are *not* equally confident), the known gaps
per ISA, a porting checklist in which every item is a bug this project shipped
and fixed, the `--arch-profile` JSON schema with a worked example, and a
procedure for telling whether your profile is actually right.

---

## Documentation

| Document | What it is |
|---|---|
| [`docs/FORMAT.md`](docs/FORMAT.md) | The `TCGCOV1` on-disk format: byte-exact header, record layouts, flag semantics, metadata schema, and a worked hexdump. Enough to write an independent reader. |
| [`docs/ARCHITECTURES.md`](docs/ARCHITECTURES.md) | **Read this before bringing tcgcov up on a new processor.** Per-profile status with the evidence behind each, known gaps per ISA, a porting checklist where every item is a bug this project shipped, and the `--arch-profile` schema. |
| [`examples/branch-coverage/`](examples/branch-coverage/) | A worked example whose four conditionals have hand-checkable outcomes, so you can verify a report rather than just read it. Explains the `-` vs `0` BRDA distinction and why machine-level "taken" is not source-level "the `if` was true". |
| [`docs/QEMU-CROSSCHECK.md`](docs/QEMU-CROSSCHECK.md) | The architecture profiles checked against QEMU's own target translators — a second, independent authority on what transfers control. Found ARM defects the binutils opcode tables did not. |
| [`docs/QEMU-BLOCK-SCANNING.md`](docs/QEMU-BLOCK-SCANNING.md) | **Design proposal, not implemented.** How QEMU could be taught to decode without executing, so the code inventory came from its decoders instead of from per-architecture regexes. |
| [`docs/DYNAMIC-OBJECTS.md`](docs/DYNAMIC-OBJECTS.md) | **Design proposal, not implemented.** Coverage of `dlopen`'d objects, and why the debugger handshake RTEMS already ships is inert. |

The two proposals are marked as such at the top of each file. Everything else
describes shipped behaviour.

---

## Limitations

Read these before trusting a number.

- **Translation-block granularity.** In `tb-insn` mode a line counts as covered
  if the block containing it executed. A fault, a trap, or a guard that leaves
  a block early can therefore over-report the tail of that block. This is
  acceptable for measuring OS and library completeness; it is not
  instruction-exact.
- **The coverable set is conservative by design.** Lines with no emitted
  instructions — fully optimized away, or purely declarative — are not counted
  as coverable. This makes the denominator honest about what the *binary* can
  execute, not about what the *source* contains, which is the right choice for
  optimized builds but means the number is not comparable to a `gcov` figure
  from an unoptimized build.
- **Only what the ELF explains.** Anything without DWARF (hand-written
  assembly, a prebuilt blob, a stripped library) is invisible. Sources that
  DWARF names but that are not on disk count toward the denominator yet cannot
  be rendered; run `genhtml --ignore-errors source`, as the driver does.
- **Dynamically loaded code is not handled.** Code loaded at runtime (RTEMS
  libdl `dlopen`, Linux shared objects) lands at addresses the offline
  symbolizer knows nothing about, so it does not appear in coverage at all.
  This needs a runtime module map; the design is written up in
  [`docs/DYNAMIC-OBJECTS.md`](docs/DYNAMIC-OBJECTS.md) and is **not
  implemented**.
- **Line coverage is not branch coverage is not MC/DC.** tcgcov does the first
  two. It does not do MC/DC and makes no certification claim.

---

## Related work

Non-intrusive emulator-based coverage is not a new idea, and several of these
tools do the observation part at least as well as tcgcov does. The honest
summary is that tcgcov's difference is on the **reporting** side, not the
capture side.

| Project | Approach | Output | Coverable denominator? | Merges across separately-linked binaries? |
|---|---|---|---|---|
| [swirsz/qemu-coverage](https://github.com/swirsz/qemu-coverage) | QEMU TCG plugin | ASCII block listing with disassembly | No | No |
| [Ayrx/qcov](https://github.com/Ayrx/qcov) | QBDI (via Frida), native process | DrCov v2 | No | No |
| [afl-qemu-cov](https://github.com/andreafioraldi/afl-qemu-cov) | patched QEMU user-mode + AFL forkserver | CSV of `(testcase, basic-block address)` | No | No |
| [NQC2](https://arxiv.org/abs/2601.02238) + [qemu-etrace](https://github.com/edgarigl/qemu-etrace) | QEMU TCG plugin → external DWARF tool | Xilinx `etrace` binary → LCOV → HTML | **Yes**, in `qemu-etrace` | Not by the tool |
| **tcgcov** | QEMU TCG plugin + offline DWARF | `.cov` → LCOV → HTML | Yes | Yes, by `(source path, line)` |

Notes, so the table is not read as a scorecard:

- **swirsz/qemu-coverage** is a compact TCG-plugin demonstration (~150 lines,
  last code change 2021). It prints executed blocks and their disassembly. It
  does not parse the ELF at all, so its "total blocks" figure counts blocks
  that *ran*, not blocks that *exist*.
- **qcov** is an abandoned 2019 proof of concept that instruments a native
  userspace process with QBDI and writes DrCov for Lighthouse-class reverse
  engineering tools. It is not an emulator and cannot target bare metal or a
  foreign ISA. Different problem, listed because the name invites confusion.
- **afl-qemu-cov** is a standalone repo (not part of AFL or AFL++, despite the
  name) that replays an AFL queue and logs which basic-block addresses each
  testcase reached, for coverage-*growth* plots. The AFL-adjacent tool that
  does emit real lcov percentages is `afl-cov`, but it requires a separate
  source build compiled with `--coverage` — source instrumentation, not
  emulation. Modern AFL++ ships a DrCov TCG plugin, i.e. addresses again.
- **NQC2** (Bosbach et al., RAPIDO '24; arXiv 2601.02238 is a 2026 posting of
  the 2024 paper) is the closest relative and is genuinely good work. It is a
  stock TCG plugin emitting Xilinx `etrace` format, and it is explicit that its
  contributions are **portability and performance** — reimplementing an
  intrusive QEMU fork as a plugin, with an asynchronous multi-buffer writer that
  beats the Xilinx approach by up to 8.5×. It does reach genuine line
  percentages, via the external `qemu-etrace` tool, which builds a denominator
  by walking every address in each symbol's range through DWARF. So **a
  DWARF-derived denominator is not novel** and tcgcov should not claim it is.
  Two practical differences: `qemu-etrace` hardcodes a 4-byte instruction
  stride (fine for fixed-width ISAs, wrong for x86) and needs `dwarfdump` plus
  binutils, whereas tcgcov enumerates real instruction addresses from
  `objdump -d` and depends only on binutils and the Python standard library.

**What tcgcov actually does differently**, stated as narrowly as it deserves:

1. **Merging by `(source path, line)` across separately-linked binaries** is,
   as far as we can tell, not offered by any of the above. For NQC2 you could
   approximate it with `lcov -a` downstream; for the address-set tools it is not
   expressible at all. This is the feature tcgcov was built for, and it is what
   makes a hundred-executable test suite produce one meaningful number.
2. **`restrict` and `gap`** — intersecting a campaign's coverage with a
   deliverable binary, and diffing an application's executed set against a
   baseline. These are qualification questions rather than coverage questions
   and we have not found them elsewhere in this space.
3. **Zero dependencies on the host side** — the standard library plus the
   target's own binutils. No `pyelftools`, no `dwarfdump`, no lcov Perl for
   anything but the final HTML.

Everything else here — non-intrusive TCG-plugin capture, a DWARF-derived
denominator, LCOV output — has prior art, and NQC2 in particular got to the
same place first.

---

## Licence

**The whole repository is GPL-2.0-or-later.** See [`LICENSE`](LICENSE).

The QEMU plugin (`plugin/tcgcov.c`) derives from QEMU's
`contrib/plugins/drcov.c`, which is *"GNU GPL, version 2 or later"*. A
derivative work must be distributed under those terms, so the plugin's licence
is not a choice.

The Python package could in principle carry a different, more permissive
licence, since it is a separate program that only consumes the plugin's output
file. We have deliberately **not** done that. The two halves are designed
together, share a file format, and are only useful as a pair; splitting the
licence would create a boundary that has to be explained in every contribution,
every backport and every corporate review, in exchange for a freedom nobody has
asked for. One licence for one tool is simpler and matches how it is actually
used. If you have a concrete need for the host tools under different terms,
open an issue and make the case.

New files should carry an SPDX identifier:

```c
/* SPDX-License-Identifier: GPL-2.0-or-later */
```

---

## Contributing

Issues and pull requests are welcome at
<https://github.com/thesamprice/tcgcov>.

```bash
python3 -m unittest discover -s tests -t .   # the test suite
```

CI runs the tests on Python 3.8 and 3.12, compiles the plugin against the
upstream `qemu-plugin.h`, shellchecks the driver, asserts the zero-dependency
promise by walking every import in the package, and rejects committed absolute
developer paths.

Particularly useful contributions, in rough order of value:

1. **An architecture profile for branch coverage on an ISA we do not cover.**
2. **A report from a target we have not tried** — especially one that does not
   work. The generalization away from its original target is recent and
   under-tested.
3. Anything from [`docs/DYNAMIC-OBJECTS.md`](docs/DYNAMIC-OBJECTS.md), which is
   a plan looking for an implementer.

Please keep the host package free of third-party dependencies; CI enforces it.
