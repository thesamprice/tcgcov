# Worked example: branch coverage with verifiable output

`branches.c` has four conditionals whose outcomes are known by construction, so
you can check the report rather than just look at it. This is the example used
to validate the branch-coverage implementation end to end on a real target
(MicroBlaze, `qemu-system-microblazeel`, `petalogix-s3adsp1800`).

## Expected result

| line | function | why | outcomes taken |
|---|---|---|---|
| 5 | `taken_both` | called with 9 and with 1 | **2 of 2** |
| 9 | `taken_one` | called with 1 only, condition never true | 1 of 2 |
| 13 | `never_called` | never called | **0 of 2, never evaluated** |
| 20 | `main` | `sink` is 2 here, never 12345 | 1 of 2 |

Totals: **4 of 8 outcomes, 3 of 4 branches evaluated.**

## Running it

Build freestanding for your target with `-O0 -g` and link with your own crt0
and linker script, then:

```sh
# 1. Build the plugin against the QEMU you will run it under.
make -C plugin QEMU_INCLUDE=<qemu-source>/include

# 2. Record. edges=1 is what enables branch coverage.
<qemu-system-target> -M <machine> -kernel branches.elf \
    -nographic -monitor none -serial file:uart.txt \
    -plugin ./plugin/libtcgcov.so,out=branches.cov,mode=tb-insn,edges=1,elf=branches.elf

# 3. Analyse.
PREFIX=<your-toolchain-prefix->     # e.g. riscv64-unknown-elf-
tcgcov branches  --cov branches.cov --elf branches.elf \
                 --toolchain-prefix $PREFIX --arch <arch> --all-paths --out br.jsonl
tcgcov symbolize --cov branches.cov --elf branches.elf \
                 --toolchain-prefix $PREFIX --arch <arch> --all-paths --out sym.jsonl
tcgcov coverable --elf branches.elf \
                 --toolchain-prefix $PREFIX --arch <arch> --all-paths --out cab.jsonl
tcgcov lcov sym.jsonl --coverable cab.jsonl --branches br.jsonl --out branches.info

genhtml branches.info --branch-coverage -o html
```

## The LCOV this produces

```
SF:.../branches.c
BRDA:5,0,0,1
BRDA:5,0,1,1
BRDA:9,0,0,1
BRDA:9,0,1,0
BRDA:13,0,0,-
BRDA:13,0,1,-
BRDA:20,0,0,1
BRDA:20,0,1,0
BRF:8
BRH:4
...
DA:12,0
DA:13,0
DA:14,0
DA:15,0
```

Three things to notice, because they are the parts that are easy to get wrong:

- **Line 13 reports `-`, not `0`.** `-` means the branch was never *evaluated*;
  `0` means it was evaluated but that outcome never occurred. Line 9 shows the
  difference: `BRDA:9,0,1,0`. `genhtml` renders them differently and conflating
  them overstates coverage.
- **Lines 12-15 appear at all, with count 0.** Code that never executed is
  present in the report as uncovered rather than silently missing. That is what
  the DWARF-derived coverable-line denominator buys you: the percentage has a
  real denominator.
- **"Taken" is a machine-level outcome, not a source-level one.** At `-O0` a
  compiler typically emits the *inverted* test — it branches *over* the body
  when the source condition is false. So `taken_one` reports `taken=1` even
  though `x > 1000` was never true: the machine branch that skips the body is
  the one that fired. This is normal for machine-level branch coverage; do not
  read `BRDA` outcome 0 as "the `if` was true".

## Why `-O0`

At `-O1` and above these functions inline into `main` and every condition
constant-folds. In the validation run, `-O1` left 27 executed instructions and
3 edges with no conditionals surviving; `-O0` left 76 instructions and 17
edges with all four branches intact. Branch coverage of optimised code is still
meaningful for real programs — it just cannot be demonstrated on a toy like
this one.
