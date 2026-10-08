# Changelog

Notable changes to tcgcov. Dates are release dates.

The version is `0.x` deliberately: the CLI and the `TCGCOV1` artifact format are
young, both changed during the extraction, and [`docs/QEMU-BLOCK-SCANNING.md`](docs/QEMU-BLOCK-SCANNING.md)
proposes changing them further. Expect breaking changes between minor versions
until 1.0.

## Unreleased

### Fixed

- **`--section` on a relocatable object now means that section only** (#12).
  Every section of a `.o` starts at address 0, but `coverable` neither
  restricted the disassembly to the section nor passed `-j` to addr2line,
  and `branches` matched edges against every section's instructions. With
  `-ffunction-sections` objects that was wrong in the aggregate, not just
  per test: on the pay_a/pay_b fixture 7 lines per object (all of the
  never-called `pad_uncovered()`, plus two in `pay_entry()`) were missing
  from the denominator, overstating coverage, and `pay_entry()`'s branch was
  reported on `spin()`'s loop line. Both now read only the section's own
  `Disassembly of section` block (so one shared `--disasm` capture still
  serves every section) and resolve through `addr2line -j`.
- **The DWARF denominator says why it cannot read a `.o`.** A relocatable
  object's line table is unrelocated (every sequence at 0, RISC-V address
  advances and string offsets left to relocations), so `--denominator dwarf`
  on one now fails with that reason instead of "check --source-root", and
  the objdump/DWARF cross-check is skipped for it rather than compared
  against garbage.

### Added

- **`tcgcov report` — the whole chain in one command.** `.cov` artifacts to an
  aggregate LCOV `.info`, running `symbolize`, `coverable`, `branches`, `lcov`
  and `merge` with one set of options:

  ```bash
  tcgcov report --raw-dir coverage/raw --out-dir coverage \
      --source-root /path/to/src --toolchain-prefix riscv64-unknown-elf-
  ```

  The pipeline itself is not new — `tcgcov-report.sh` has driven it all along —
  but that script ships only in the sdist, is not installed by the wheel, and
  needs bash. The subcommand is installed with the package and runs wherever
  Python does. It also does what the script could not: the ELF each artifact
  names is read without loading the artifact's records; the per-ELF denominator
  is cached under a key that includes the path options, so a re-run with a
  different `--source-root` cannot reuse an inventory built for the old one;
  `objdump -d` runs once per ELF for both the coverable and the branch side;
  and each parallel worker's output stays together instead of interleaving.
  HTML is opt-in (`--html`), so a report no longer requires `genhtml`.

  `--denominator dwarf --no-branches` needs no target toolchain at all.

- **Slices from `tcgcov modmap` report with no per-object flags.** A slice
  records the object it was cut from (`module_file`) and the section its
  addresses are offsets into (`module_section`); `report` analyses it against
  those rather than against the `elf` key it inherited from the base image —
  which is the wrong binary for a dynamically loaded object. `--elf` and
  `--section` still override, for a stripped image whose DWARF lives in an
  unstripped copy, a moved tree, or a `dump --scrub-out` artifact.

- **RTEMS loaded objects found on a search path (`--obj-path`).** `report`
  now splits an artifact recorded in the plugin's RTEMS loader mode by
  itself: base-image addresses go to the base ELF, and each loaded object's
  addresses go to its own `.o`, rebased per section and summed over every
  generation it was live. Objects are found the way GDB's
  `solib-search-path` finds shared libraries: give one or more directories
  (repeatable, or `:`-separated), searched recursively by the loaded name's
  relative path, then its basename, including members of `*.a` archives.
  Each candidate is **verified** against the sections the target actually
  loaded (name and size, standing in for the build-id a `.o` lacks); a
  mismatching or ambiguous match fails the run, an absent one is a warning
  with the count of records dropped. A rebuild that changes no section size
  is not detected (the target's relocated bytes are not recorded); the
  resolved file's md5 is kept for provenance. `--obj-suffix .debug` finds unstripped
  host twins (`foo.o.debug`, `foo.debug`) of objects the target loaded
  stripped, and the copy with DWARF wins. Loaded but never executed code
  reports as 0% rather than being absent. The resolved file and its md5 are
  recorded in each slice (`module_file`, `module_md5`).

  ```bash
  tcgcov report run.cov --out-dir cov --obj-path build/riscv/mbv/testsuites \
      --toolchain-prefix riscv-rtems7-
  ```

  `tcgcov rtl-split` does just the split; **`tcgcov rtems-args IMAGE`** prints
  the `rtl_state=…,rtl_debug=…[,rtl_load=…],elf=…` plugin options from the
  base image's symbol table, replacing the hand-run `nm`.

- **The plugin flags incomplete snapshots.** Its guest-read caps are raised
  (1024 objects, 4096 sections per object, 512-byte names) and hitting one is
  now recorded (`truncated`, `name_truncated`, `chain_truncated`, plus the
  loader's own `sec_num`), so the host warns instead of silently reporting
  the lost sections' executions as base image. A cut-short name is matched to
  the object's one section with that prefix and size.

- **The plugin records each loaded section's true offset** (`offset` in
  `rtl_generations`, read from the loader's `section_detail`). Host-side
  placement no longer assumes sections are packed: const data with 8-byte
  alignment really is padded (dl09's `.srodata.cst8` sits at 472, not 468).
  Older artifacts without it are laid out the loader's way, aligning each
  section to the resolved object's `sh_addralign`.

- **`format.read_metadata()`** reads an artifact's metadata by seeking to it,
  instead of parsing every address record to reach the few hundred bytes of
  JSON at the front. `parse_header()` takes an optional `total_size` so its
  section-bounds checks still run when it is handed only the header.

### Changed

- **`tcgcov-report.sh` is now a wrapper around `tcgcov report --html`.** Every
  option it accepted is an option of the subcommand and `JOBS` maps to
  `--jobs`, so existing callers keep working and produce the same tree; there
  is no longer a second implementation of the pipeline to keep in step.

## 0.2.0 — 2026-08-17

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
