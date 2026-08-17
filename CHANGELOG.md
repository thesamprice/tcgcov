# Changelog

Notable changes to tcgcov. Dates are release dates.

The version is `0.x` deliberately: the CLI and the `TCGCOV1` artifact format are
young, both changed during the extraction, and [`docs/QEMU-BLOCK-SCANNING.md`](docs/QEMU-BLOCK-SCANNING.md)
proposes changing them further. Expect breaking changes between minor versions
until 1.0.

## Unreleased

### Added

- **`examples/uclibc-ng/` — a C library measured by its own test suite.**
  uClibc-ng 1.0.55 built static for microblazeel, its 115-test upstream suite
  run under qemu-user with the plugin, and the per-test `.cov` files merged by
  source line into a library-only LCOV report (40.5% lines, 54.2% functions,
  30.9% branches). Demonstrates the static-link workflow — symbolize each test
  against its own binary, then `merge` by source identity — plus the
  `SIMULATOR=` integration point that needs no changes to the suite. The
  example's function column depends on a not-yet-upstreamed `addr2line`
  determinism fix; it says so.

- **Coverage of RTEMS dynamically loaded (`dlopen`'d) objects.** libdl code no
  longer resolves to nothing: it is attributed to its source object and section
  and rebased for symbolization, end to end. Three pieces, verified R0–R4
  against RTEMS 7 `dl01`/`dl09` on the riscv/mbv BSP — see
  [`docs/RTEMS-DL.md`](docs/RTEMS-DL.md) and [`examples/rtems-dl/`](examples/rtems-dl/):
  - **Plugin loader-generation mode.** New arguments `rtl_state=<&_rtld_debug_state>`
    and `rtl_debug=<&_rtld_debug>` (given together) put the plugin in RTEMS
    loader mode: it watches the loader's rendezvous, bumps a **generation** on
    each completed `dlopen`/`dlclose`, snapshots the `link_map` chain (object
    names and per-section runtime bases) into artifact metadata
    (`rtl_generations`, `ctx_kind: "loader-generation"`), and tags every record
    with the generation in force. Address *reuse* across load/unload — the same
    address carrying two different objects over time — is thereby kept apart.
    Requires `qemu_plugin_read_memory_vaddr` (plugin API v4). Optional
    `rtl_load=<&rtems_rtl_debugger_load>` (a 30-line RTEMS fork hook) also
    attributes code that runs inside `dlopen`, e.g. a constructor.
  - **`tcgcov modmap`.** Slices a `.cov` by a JSON module map — which can be the
    artifact's own `rtl_generations` metadata — into one artifact per
    `(object, section)`, rebased to each section's link-time offset for
    `symbolize --section`. Refuses overlapping windows (one map has no time
    axis); `--ctx <gen>` slices a single loader generation first. Always reports
    how many base-image addresses were not attributed.
  - **`tcgcov rebase`.** The single-window generalization for fixed placement
    (Linux kernel modules): shift records in `[base, base+size)` by `to - base`.
  Note: the **Linux `ET_DYN` / `ld.so`** shared-library rendezvous remains a
  design proposal ([`docs/DYNAMIC-OBJECTS.md`](docs/DYNAMIC-OBJECTS.md)); this
  release ships the RTEMS `ET_REL` path only.

- `tcgcov dump --scrub` and `--scrub-out FILE` redact the absolute ELF path an
  artifact embeds, so a `.cov` can be attached to a bug report without
  disclosing the filesystem layout of the machine that produced it. The
  redacted copy is a fully valid artifact; analysing it needs `--elf`
  explicitly, since it no longer names its own ELF.

### Fixed

- A `--keep` marker no longer rebases an **in-tree** file onto the marker.
  RTEMS has `testsuites/validation/bsps/ts-fatal-extension.c`, and the `rtems`
  preset's `/bsps/` marker rewrote it to `bsps/ts-fatal-extension.c` — a path
  that names no file, that `genhtml` could not open, and that could collide
  with a real file of that name under `bsps/`. It also defeated the preset's
  `testsuites/**` exclude. For a file under the source root, a marker now
  decides only *whether* to keep it, never what it is relative to.

### Changed — breaking

- **Execution counts are always on, and the `counts=` plugin argument is gone.**
  Passing `counts=` now fails the launch rather than being silently accepted as
  an argument that no longer means anything.

  This is a speed-up, not a cost. The plugin previously carried both a
  monotonic `executed` flag and a `count` per instruction, and the per-instruction
  hot path was: load the flag, compare, maybe store; load the global `counts`
  setting, branch; then maybe increment. Making the count unconditional makes
  the flag redundant — `count != 0` *is* executed — so the flag and its test
  were deleted, and the hot path is now a single relaxed atomic add. Fewer
  instructions than before, and one less mode to document and test.

  Address records are consequently always the 16-byte `{addr, count}` form.
  **The binary format did not change**: `HAS_COUNTS` and `EDGE_COUNTS` are
  simply always set now, so existing readers keep working.

- **`edges=` now defaults to on**, so branch coverage works without being asked
  for. The option is retained, unlike `counts=`, because the edge path cannot be
  folded away — it needs a per-block callback and a hash insert per block
  execution — so `edges=off` remains meaningful for long-running measurements.

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
