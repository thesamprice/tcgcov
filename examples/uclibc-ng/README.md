# Coverage of a C library by its own test suite: uClibc-ng under QEMU

Measured 2026-08-17: **uClibc-ng 1.0.55** built for **microblazeel**, its
upstream test suite run under **qemu-microblazeel** (linux-user, QEMU 11.0.0,
`--enable-plugins`) with the tcgcov plugin. No `--coverage` rebuild, no gcov
runtime in the guest, no instrumentation of the library — the coverage is
reconstructed offline from the addresses QEMU executed.

This is the case tcgcov is built for: a C library measured *by the tests that
already exist for it*, on a target where you would not want to link gcov into
every test binary.

## Result

115 tests across 16 subsystems, coverage attributed to the **library** sources
(the harness's own `.c` is excluded):

```
lines......: 40.5%  (4893 of 12072)
functions..: 54.2%  (359 of 662)
branches...: 30.9%  (2297 of 7436)
```

| subsystem | lines | | subsystem | lines |
|---|---|---|---|---|
| `string`  | **92%** (1170/1264) | | `stdlib`  | 62% (706/1129) |
| `librt`   | 87% (21/24)         | | `signal`  | 42% (24/57)    |
| `pwd_grp` | 79% (113/143)       | | `inet`    | 25% (511/2018) |
| `sysdeps/linux` | 73% (403/550) | | `misc`    | 15% (744/4729) |
| `stdio`   | 69% (1135/1641)     | | `unistd`  | 11% (58/503)   |

The shape is the suite's, not the tool's: `string` is exercised hard, while
`misc` is dominated by `regex` (3480 lines, mostly untouched by the two `regex`
tests) and `inet` by `resolv.c` (1212 lines, no live resolver under qemu-user).
The committed [`uclibc-ng.info`](uclibc-ng.info) is the full LCOV artifact;
`genhtml` renders it per file and per branch.

## How it was built

The toolchain on hand was a Buildroot microblazeel **glibc** cross gcc, which
does not target uClibc. Rather than build a second toolchain, retarget the one
you have at a freshly built static uClibc with `--sysroot`
([`mb-uclibc-gcc`](mb-uclibc-gcc)):

```sh
# uClibc-ng, little-endian, debug info, static (see uclibc-ng.config.fragment)
make ARCH=microblaze defconfig
#   ... apply the fragment, set CROSS_COMPILE + KERNEL_HEADERS ...
make ARCH=microblaze CROSS_COMPILE=microblazeel-linux- oldconfig
make ARCH=microblaze CROSS_COMPILE=microblazeel-linux-
make ARCH=microblaze PREFIX=$PWD/uc-install install

microblazeel-linux-gcc --sysroot=uc-install/usr/microblaze-linux-uclibc \
    -static -g -idirafter <kernel-headers> test.c -o test   # what mb-uclibc-gcc does
```

Static only, on purpose: the standalone microblazeel *shared* loader does not
link (its `.S` objects assemble little-endian but the `ld-uClibc.so` link
defaults to microblaze **big**-endian emulation — a gap in uClibc-ng's
microblazeel port). qemu-user runs static ET_EXEC fine, and static linking is
what makes the merge step below correct.

## How it was run

The test suite is [`uclibc-ng-test`](https://github.com/wbx-github/uclibc-ng-test)
(the suite is not in the library tarball). Its harness prepends `$(SIMULATOR)`
to every test, which is the whole integration:

```sh
source env.sh
./run-suite.sh      # compile each subdir, then `make run SIMULATOR=./qemu-cov`
```

[`qemu-cov`](qemu-cov) runs each test under
`qemu-microblazeel -plugin libtcgcov.so,out=<subdir>__<test>.cov,mode=tb-insn,edges=on,elf=<bin>`.
A test that exits nonzero still leaves a valid `.cov` — the plugin writes at
exit, before the harness inspects the return code — so `-k` past failures loses
no coverage.

## How it was aggregated

```sh
./aggregate.sh      # symbolize + coverable + branches -> lcov -> merge -> genhtml
```

The tests are **static**, so the same `libc` line lives at a *different address*
in every binary. Each `.cov` is therefore symbolized against its own binary's
DWARF, and [`tcgcov merge`](../../README.md) unions the per-test LCOV files **by
source line**, not by address (execution counts summed, a branch outcome
counted taken if any test took it). Coverage is restricted to the library:
`--exclude uclibc-ng-test` drops the harness on the way in, and only `SF` blocks
under the library source root are kept on the way out.

## Caveats this example demonstrates

- **The denominator is the suite's reach, not the library's size.** 40.5% is
  *"of the 12072 library lines these 115 tests can reach"*. `regex` and the
  resolver drag it down precisely because the suite barely touches them — which
  is the useful signal, not noise. Thread/locale/dlopen subdirs were skipped
  (no NPTL, no shared objects in this static build); adding them raises the
  denominator and the honest number moves.
- **Reproducibility needs a fixed `addr2line`.** These are `-O0 -g` binaries
  full of inlined libc; `addr2line -i` on stock binutils names a *different*
  inlined function from run to run when two share an equal address range, so
  `FN`/`FNDA` (and this report's function total) wobble while `DA`/`BRDA` do
  not. The fix is not upstream yet — it is the bfd/dwarf2 DIE-offset tie-break
  patch carried alongside this work. Use a patched `addr2line` if you need the
  function column to be stable across runs.
- **`-O0` flatters line mapping.** `DODEBUG=y` builds uClibc at `-O0`; an `-Os`
  library (drop `DODEBUG`, keep `-g`) measures fewer, denser lines. Coverage
  measures the binary that exists.

## Files

| file | what |
|---|---|
| `env.sh` | paths (edit for your tree) |
| `uclibc-ng.config.fragment` | the uClibc-ng `.config` knobs that matter |
| `mb-uclibc-gcc` | glibc cross gcc retargeted at static uClibc via `--sysroot` |
| `qemu-cov` | `SIMULATOR` hook: one `.cov` per test |
| `run-suite.sh` | build + run the curated subset |
| `aggregate.sh` | `.cov` &rarr; merged, library-only LCOV + HTML |
| `coverage-summary.txt` | the numbers, per subsystem, in plain text |
| `uclibc-ng.info` | the coverage artifact (259 files; force-added past `.gitignore`'s `*.info`) |
| `sample-string__tst-strlen.cov` | one scrubbed `.cov` (`tcgcov dump` it) |
