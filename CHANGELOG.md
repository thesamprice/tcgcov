# Changelog

Notable changes to tcgcov. Dates are release dates.

The version is `0.x` deliberately: the CLI and the `TCGCOV1` artifact format are
young, both changed during the extraction, and [`docs/QEMU-BLOCK-SCANNING.md`](docs/QEMU-BLOCK-SCANNING.md)
proposes changing them further. Expect breaking changes between minor versions
until 1.0.

## 0.1.0 — 2026-08-09

First public release. Extracted from an internal tool called *RTQCov* that
lived inside a QEMU fork and measured RTEMS test suites, then generalised.

### Added

- **Branch coverage.** The plugin can record directed control-flow edges
  (`edges=on`); the host reconstructs a static CFG to enumerate every
  conditional branch and both its outcomes, and emits LCOV `BRDA`/`BRF`/`BRH`.
  A branch that never executed is reported as uncovered rather than being
  absent — the same principle as the coverable-line denominator.
- **Architecture profiles** for microblaze, thumb, arm, aarch64, x86/x86_64,
  riscv, mips, micromips, mips16, powerpc and sparc, each verified against the
  binutils opcode tables and cross-checked against QEMU's own target
  translators. An architecture with no profile refuses to guess.
- **A second denominator source.** `--denominator {objdump,dwarf,auto}`; the
  DWARF reader (`tcgcov/dwarfline.py`, pure standard library) handles DWARF 2–5,
  both endiannesses, ELF32/64, 64-bit DWARF and compressed debug sections, and
  is checked row-for-row against `readelf`. `auto` falls back to it when
  disassembly cannot be parsed.
- **Exact instruction fidelity.** `mode=tb-insn` (the default) registers a
  per-instruction callback, so an instruction after an abort point is never
  reported. `mode=tb-insn-fast` keeps the cheaper block-level approximation and
  is documented as over-reporting.
- `restrict` and `gap` for qualification work, `dump` for inspecting artifacts,
  a one-command driver, and a `--preset` mechanism for project path layouts.
- Documentation: the on-disk format, an architecture porting reference, a
  QEMU cross-check, a worked example with hand-checkable outcomes, and two
  design proposals.

### Changed from RTQCov

- Renamed throughout, including the artifact magic (`RTQCov1` → `TCGCOV1`).
  The header grew from 80 to 88 bytes for the edge section. Old artifacts are
  not readable.
- **The path normaliser no longer assumes an RTEMS source layout.** It
  previously hardcoded `cpukit`/`bsps`/`contrib` and dropped everything else,
  so on any other project the default configuration silently discarded
  essentially all coverage. The default is now source-root-relative; the RTEMS
  behaviour is `--preset rtems`.
- The toolchain prefix defaults to the host toolchain, not `microblaze-rtems6-`.
- The plugin refuses to start on an unknown argument, an unparseable boolean or
  a malformed `filter=` range, rather than running with settings the caller did
  not ask for.

### Fixed

Every one of these produced a wrong number and exited 0.

- `objdump` output from llvm-objdump parsed to **zero** instructions — the
  parser required a tab after the address colon and llvm-objdump emits a space
  — so branch coverage silently vanished while line coverage kept working.
- An empty coverable inventory made every report read **100%**.
- Branch identity was a per-binary ordinal, so merging two binaries could sum
  two genuinely different branches. It is now derived from the source.
- MicroBlaze absolute branches (`brai` and friends) were treated as
  PC-relative, injecting false basic-block leaders.
- Stripped binaries lost every direct branch, because targets print as bare hex
  with no symbol.
- Indirect transfers on aarch64, riscv, mips, sparc and powerpc had no pattern,
  so a register displacement could be read as a branch target.
- ARM predicated register transfers (`bxeq`, `tbbeq`) were invisible, ALU
  writes to PC were unmodelled, and predicated returns never became branch
  points. Conditional `bl<cc>` was classified as a call and never counted.
- The plugin could rename a truncated artifact over a good one, produce
  unreadable metadata if a path contained a quote, and corrupt itself when two
  runs shared an output path.
- `restrict --elf` failed with a `TypeError` on every invocation.
- `gap` chose its input format by filename extension, so a mis-named file
  reported "0 gaps" at exit 0.

### Known limitations

- Branch coverage has no end-to-end CI on any target; only MicroBlaze has been
  validated end to end under emulation.
- Indirect branch targets are excluded from branch coverage by construction.
- Coverage of dynamically loaded objects is not implemented — see
  [`docs/DYNAMIC-OBJECTS.md`](docs/DYNAMIC-OBJECTS.md).
- Concurrent runs sharing one `out=` path are safe but last-writer-wins.
- No big-endian *host* writer path exists; the reader rejects `endian=2`.
