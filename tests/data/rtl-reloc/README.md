Fixtures for `tests/test_dwarf_reloc.py` (issue #18): `examples/rtems-dl/pay_a.c`
compiled to relocatable objects with `-g -ffunction-sections -fdata-sections`
and `-fdebug-prefix-map` (so the debug info names `/src/pay_a.c`, not a local
path):

| file | compiler | flags |
|---|---|---|
| `pay_a-riscv32-O0.o` | `riscv-rtems7-gcc` 15.2 | `-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0` |
| `pay_a-riscv32-O2.o` | `riscv-rtems7-gcc` 15.2 | same, `-O2` (everything inlined into `pay_entry`) |
| `pay_a-microblaze-O0.o` | `microblaze-rtems7-gcc` 12.4 | `-O0` |

`expected.json` comes from binutils, not from tcgcov: `readelf_rows` is the
(line@address -> count) multiset of `readelf --debug-dump=decodedline`, which
applies the relocations itself, and `objdump_lines` is each code section's
objdump + `addr2line -j` coverable set.
