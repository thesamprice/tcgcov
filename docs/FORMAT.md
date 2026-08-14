# TCGCOV1 file format

This document specifies the binary artifact written by the `tcgcov` QEMU TCG
plugin (`plugin/tcgcov.c`). It is complete enough to write an independent
reader without consulting the plugin source.

Conventional file extension: `.cov`. The plugin assembles the artifact in a
temporary file in the destination's **own directory** and `rename(2)`s it into
place, so a `.cov` file is either absent or complete — a reader never sees a
partially written one. Two further guarantees follow from how that is done:

* **A failed write never destroys a good artifact.** Every write is checked,
  and so are the flush and the close — which is where an out-of-space or quota
  error on a small artifact actually surfaces, since stdio buffers. On any
  failure the temporary is deleted, the rename is skipped, and the error is
  reported on stderr; a `.cov` already at that path is left byte-for-byte
  intact.
* **Concurrent writers do not corrupt each other.** The temporary name is
  unique per writing process, so several QEMU runs may target one `out=` path
  at once. They race only to `rename(2)`; the last to finish wins and the file
  under that name is always the complete output of exactly one run. (Their
  coverage is *not* merged — for that, write separate files and merge them
  offline.)

---

## 1. Overview

A TCGCOV1 file has four sections, always in this order:

```
+--------------------------------------------------+ offset 0
| header            (88 bytes, fixed)              |
+--------------------------------------------------+ metadata_offset (= 88)
| metadata          (JSON text, metadata_size B)   |
+--------------------------------------------------+ records_offset
| address records   (records_size bytes)           |
+--------------------------------------------------+ edges_offset
| edge records      (edges_size bytes)             |   (optional)
+--------------------------------------------------+ EOF
```

* The **address records** answer "which guest code addresses executed?"
  (line/statement coverage).
* The **edge records** answer "which control-flow transfers were taken?"
  (branch coverage). The plugin records them by default; they are absent only
  when it was run with `edges=off`.

Address records always carry an execution count in files written by this
plugin — see §3 and §10. The count-less forms the format also defines are still
described here, because a reader must handle artifacts from any producer.

There is **no padding and no alignment** between sections. `metadata_size` is
the exact byte length of the JSON text and is usually not a multiple of 8, so
`records_offset` and `edges_offset` are frequently **not 8-byte aligned**.
Readers must not cast a raw pointer into the mapped file to `uint64_t *`; copy
each field out (`memcpy`, `struct.unpack_from`, `int.from_bytes`, ...) instead.

---

## 2. Header

88 bytes. Field offsets and sizes below are byte-exact. The C declaration
contains no packing attribute because every field is already naturally aligned
at its declared offset; the plugin carries a
`G_STATIC_ASSERT(sizeof(tcgcov_header) == 88)` **and one `offsetof` assertion
per field** — the total size alone would still hold if a field moved and the
padding moved with it — so an ABI that lays the struct out differently fails
the build rather than emitting an unreadable file.

| Offset | Size | Type       | Field             | Meaning |
|-------:|-----:|------------|-------------------|---------|
| 0      | 8    | `char[8]`  | `magic`           | `"TCGCOV1\0"` — the ASCII bytes `54 43 47 43 4F 56 31 00`. The trailing NUL is part of the magic, not a terminator. |
| 8      | 2    | `uint16`   | `version`         | Format version. Currently `1`. A reader should reject values it does not know. |
| 10     | 2    | `uint16`   | `endian`          | Byte order of every multi-byte field in this file: `1` = little-endian, `2` = big-endian. The current writer always emits `1`. |
| 12     | 4    | `uint32`   | `header_size`     | Size of this header in bytes. Always `88` for TCGCOV1. See §7. |
| 16     | 4    | `uint32`   | `record_type`     | Granularity of the address records: `1` = `TB_ADDR` (each record is a translation-block start address), `2` = `INSN_ADDR` (each record is a single instruction address). |
| 20     | 4    | `uint32`   | `flags`           | Bitfield, see §3. |
| 24     | 8    | `uint64`   | `record_count`    | Number of address records. |
| 32     | 8    | `uint64`   | `metadata_offset` | Absolute file offset of the metadata JSON. Always `88`. |
| 40     | 8    | `uint64`   | `metadata_size`   | Length of the metadata JSON in bytes. **Not** NUL-terminated and the length does **not** include a NUL. |
| 48     | 8    | `uint64`   | `records_offset`  | Absolute file offset of the first address record. Equals `metadata_offset + metadata_size`. |
| 56     | 8    | `uint64`   | `records_size`    | Total size of the address record section = `record_count * address_record_size` (see §4). |
| 64     | 8    | `uint64`   | `edge_count`      | Number of edge records. `0` when edges were not recorded. |
| 72     | 8    | `uint64`   | `edges_offset`    | Absolute file offset of the first edge record, or `0` when the `HAS_EDGES` flag is clear. When `HAS_EDGES` is set this equals `records_offset + records_size`. |
| 80     | 8    | `uint64`   | `edges_size`      | Total size of the edge section = `edge_count * edge_record_size` (see §5). `0` when `HAS_EDGES` is clear. |

Total: **88 bytes**, offsets `0..87`.

Header fields not otherwise constrained are zero-filled by the writer
(`memset` before population); there are no reserved fields left over in
TCGCOV1 — offsets `0..87` are entirely accounted for by the table above.

---

## 3. Flags

`flags` is a 32-bit little-endian bitfield.

| Bit | Mask  | Name          | Meaning |
|----:|-------|---------------|---------|
| 0   | `0x1` | `HAS_COUNTS`  | Each **address** record carries an execution count and is 16 bytes instead of 8. Applies only to the address record section. |
| 1   | `0x2` | `HAS_EDGES`   | An edge section is present. `edge_count`/`edges_offset`/`edges_size` are meaningful. |
| 2   | `0x4` | `EDGE_COUNTS` | Each **edge** record carries a traversal count and is 24 bytes instead of 16. Only meaningful when `HAS_EDGES` is also set; readers should ignore it otherwise. |
| 3   | `0x8` | `HAS_CTX`     | **TCGCOV2 only.** Every address and edge record is prefixed with a `uint64` address-space context ID; see §11. Illegal in a file bearing the `TCGCOV1` magic — a v1 reader would mis-stride the sections, so the magic changed with the flag. |

All other bits are reserved and are written as zero. A reader that encounters
an unknown bit set should still be able to read the sections it understands,
because unknown bits never change the size or position of the sections
described above; whether to warn is up to the reader.

### What the current producer always sets

`HAS_COUNTS` is **always set** by the current plugin, and `EDGE_COUNTS` is
always set whenever `HAS_EDGES` is. Execution counts used to be the optional
`counts=1`; that argument no longer exists, because keeping the count always
made the plugin's separate "was this executed" flag redundant (`count != 0` is
the same predicate) and so removing the option removed work from the
per-instruction hot path rather than adding it. `HAS_EDGES` is set unless the
run passed `edges=off`.

So a file from this producer has `flags == 7` normally, or `flags == 1` with
`edges=off`. **A reader must not rely on that.** All four combinations of bit 0
and bit 2 are independently legal, other producers may write any of them, and
artifacts predating this change have bit 0 clear — which is why both record
layouts remain specified in §4 and §5 and both must be implemented.

When edges were not recorded (`edges=off`), the writer guarantees:
`HAS_EDGES` clear, `EDGE_COUNTS` clear, `edge_count == 0`,
`edges_offset == 0`, `edges_size == 0`.

When edges were recorded but none were observed (for example, a run where only
a single TB ever executed), `HAS_EDGES` is **set**, `edge_count == 0`,
`edges_size == 0`, and `edges_offset` points at end-of-file. Do not use
`edges_offset != 0` as the presence test — test the `HAS_EDGES` flag.

---

## 4. Address records

Located at `records_offset`, `record_count` records, `records_size` bytes
total. `record_type` says whether an address denotes a translation-block start
(`1`) or a single instruction (`2`); it does not change the record layout.

**`HAS_COUNTS` clear — 8 bytes per record.** Never written by the current
plugin (§3), but legal, and produced by versions of it that predate the removal
of the `counts=` argument:

| Offset | Size | Type     | Field  |
|-------:|-----:|----------|--------|
| 0      | 8    | `uint64` | `addr` |

**`HAS_COUNTS` set — 16 bytes per record.** What the current plugin always
writes:

| Offset | Size | Type     | Field   |
|-------:|-----:|----------|---------|
| 0      | 8    | `uint64` | `addr`  |
| 8      | 8    | `uint64` | `count` |

Guarantees:

* `addr` is a guest **virtual** address (`metadata.address_kind == "vaddr"`).
* Records are sorted ascending by `addr`.
* `addr` values are unique — duplicates arising from retranslated or
  overlapping translation blocks are merged before writing, and in counts mode
  their `count` values are summed.
* `count` is the number of executions attributed to that address.
* A `count` of `0` should not occur, but is not structurally illegal. The
  current plugin cannot emit one: a zero count is precisely how it decides an
  address never executed and omits the record.

### 4.1 Fidelity: what an address record actually proves

The producer's `mode=` argument decides both `record_type` and how much an
address record is worth. `metadata.insn_fidelity` states the answer directly so
a reader does not have to infer it from `mode`.

| `mode` | `record_type` | `insn_fidelity` | An emitted address means |
|---|---|---|---|
| `tb` | `1` (`TB_ADDR`) | `"exact"` | The CPU entered this translation block, so its **first instruction** was reached. Nothing is claimed about the rest of the block. |
| `tb-insn` *(default)* | `2` (`INSN_ADDR`) | `"exact"` | The CPU reached **this instruction**. A per-instruction execution callback is registered on every in-range instruction, so an instruction the CPU never got to is never emitted. |
| `tb-insn-fast` | `2` (`INSN_ADDR`) | `"tb-approx"` | The CPU entered the block this instruction was translated into. **The instruction itself may never have run.** |

`tb-insn-fast` is the cheap mode: one callback per block, expanded at exit to
every instruction the block was translated with. When a block aborts part way
through — a synchronous exception, an interrupt, an MMIO access that stops the
machine — every instruction *after* the abort point is still reported as
covered. That is a genuine over-report of executed code, so `tb-insn-fast`
should be used only when the block-entry approximation is understood and the
run-time cost of `tb-insn` is unacceptable.

The exactness of `tb` and `tb-insn` is bounded by one thing, in both modes: an
address is emitted when the CPU **reached** it, not when it **retired**. An
instruction that itself faults (a load that traps, an MMIO write that stops the
machine) has already fired its callback, so it appears in the records. Its
successors do not. "Reached" is the coverage question — did control get here —
so this is the intended meaning, but a reader computing anything stricter must
account for it.

Counts follow the same rule. In `tb-insn` each instruction carries its own
observed execution count; in `tb-insn-fast` every instruction of a block
inherits that block's entry count.

---

## 5. Edge records

Located at `edges_offset`, `edge_count` records, `edges_size` bytes total.
Present only when `HAS_EDGES` is set.

**`EDGE_COUNTS` clear — 16 bytes per record.** Never written by the current
plugin (§3), but legal:

| Offset | Size | Type     | Field |
|-------:|-----:|----------|-------|
| 0      | 8    | `uint64` | `src` |
| 8      | 8    | `uint64` | `dst` |

**`EDGE_COUNTS` set — 24 bytes per record.** What the current plugin always
writes when there is an edge section at all:

| Offset | Size | Type     | Field   |
|-------:|-----:|----------|---------|
| 0      | 8    | `uint64` | `src`   |
| 8      | 8    | `uint64` | `dst`   |
| 16     | 8    | `uint64` | `count` |

Guarantees:

* Records are sorted ascending by `(src, dst)`, compared as unsigned 64-bit
  integers, `src` major.
* The `(src, dst)` pair is unique across the section.
* `count` is the number of times the edge was traversed, summed over all
  vCPUs.

### 5.1 Edge semantics

An edge is a **directed control-flow transfer between translation blocks**:

* `src` is the virtual address of the **last instruction of the translation
  block that executed immediately before** the destination block, on the same
  vCPU.
* `dst` is the **start** virtual address of the destination translation block.

Using the *last instruction* of the source block rather than its start address
is deliberate. On delay-slot architectures — MicroBlaze, SPARC, MIPS — the
branch instruction is followed by a delay-slot instruction that executes
before control actually transfers, so the last instruction of the block is the
one an offline tool can meaningfully attribute the transfer to. On
architectures without delay slots the last instruction *is* the branch, so the
same rule works unchanged.

Both endpoints are *observed*, not inferred. `dst` is committed when the
destination block is entered, and `src` is committed by a callback on the
source block's last instruction — so an edge exists only if that instruction
really executed. A block that was entered but aborted part way through
therefore contributes **no** outgoing edge, and the block that runs next (an
exception handler, say) is not falsely attributed to a branch that was never
reached. This holds in every mode, including `mode=tb`.

Consequences a reader must account for:

* `src` is an **instruction** address regardless of `record_type`. In
  `record_type == 1` (`TB_ADDR`) files, `src` will generally **not** appear in
  the address record section, because that section holds block starts. `dst`
  always corresponds to a block start and therefore does appear (in
  `TB_ADDR` mode) — in `INSN_ADDR` mode both endpoints are instruction
  addresses that appear in the record section.
* The first block executed on each vCPU has no predecessor and produces no
  edge.
* Edges are per-vCPU: the predecessor is tracked separately for each
  `cpu_index`, so interleaved execution on an SMP guest does not manufacture
  cross-CPU edges. Traversal counts are then summed across vCPUs into a single
  global edge set.
* Edges cross **all** transfer kinds — direct branches, indirect branches,
  calls and returns — because they are derived from observed block sequencing,
  not from decoding the branch. A reader doing branch coverage should expect
  call/return edges alongside conditional-branch edges and filter by
  symbol/line if it wants only the latter.
* Entry into an interrupt or exception handler is **not** an edge when
  `metadata.discon_tracking` is `true`: the producer is notified of the
  discontinuity and drops the pending source, so the handler's first block is
  not attributed to whatever instruction happened to run last. When
  `discon_tracking` is `false` (the producer was built against a QEMU plugin
  API older than 5, which has no such notification) an asynchronous event taken
  at a block boundary can still appear as an edge from the preceding block's
  last instruction into the handler. Exceptions raised *inside* a block are
  never recorded as edges in either case, because the block never reached its
  last instruction.
* Both endpoints respect the plugin's `filter=` address ranges. Blocks whose
  start address falls outside every range are not instrumented at all, and an
  edge is suppressed when the source block's last instruction falls outside
  every range. A side effect: if execution passes through an un-instrumented
  region, the next recorded edge jumps *over* it rather than being split into
  two edges. This is the same trade-off the address records already make.

---

## 6. Metadata

`metadata_size` bytes of UTF-8 JSON text at `metadata_offset`, with no NUL
terminator. The writer emits pretty-printed JSON ending in a newline; readers
must not depend on the whitespace, key order, or the trailing newline, only on
it being valid JSON.

Schema. Every key below is written by the current producer; the two marked
*(added)* did not exist in the first release, so a reader that wants them must
tolerate their absence in older files, and — as always with JSON — must ignore
keys it does not know.

| Key                | JSON type | Meaning |
|--------------------|-----------|---------|
| `format`           | string    | Always `"tcgcov"`. |
| `version`          | number    | Always `1`. Mirrors `header.version`. |
| `mode`             | string    | `"tb"`, `"tb-insn"` or `"tb-insn-fast"`. The first corresponds to `record_type` `1`, the other two to `record_type` `2`. Treat it as an open set: match the values you know and fall back on `record_type` and `insn_fidelity`. |
| `target_name`      | string    | QEMU target name reported by `qemu_info_t.target_name`, e.g. `"microblazeel"`. May be empty. |
| `system_emulation` | boolean   | `true` for `qemu-system-*`, `false` for user-mode emulation. |
| `test_id`          | string    | Free-form metadata string supplied via the `test_id=` plugin argument. Empty when not given. Opaque to the format. |
| `bsp`              | string    | Free-form metadata string supplied via the `bsp=` plugin argument. Empty when not given. Opaque to the format. |
| `elf`              | string    | Path to the guest ELF, supplied via the `elf=` plugin argument, for offline symbolization. Empty when not given. |
| `address_kind`     | string    | Always `"vaddr"` in version 1: addresses are guest virtual addresses. |
| `counts_enabled`   | boolean   | Mirrors the `HAS_COUNTS` flag. Always `true` from the current producer; older files may have `false`. |
| `record_count`     | number    | Mirrors `header.record_count`. |
| `edges_enabled`    | boolean   | Mirrors the `HAS_EDGES` flag. `true` from the current producer unless it was run with `edges=off`. |
| `edge_count`       | number    | Mirrors `header.edge_count`. |
| `insn_fidelity`    | string    | *(added)* `"exact"` when every emitted address provably reached the CPU, `"tb-approx"` when instruction addresses were inferred from block entry and may include instructions after an abort point. See §4.1. Treat it as an open set; an unrecognised value should be read as "weaker than exact". |
| `discon_tracking`  | boolean   | *(added)* `true` when the producer was notified of interrupt/exception discontinuities and dropped pending edge sources across them. Always `false` when `edges_enabled` is `false`, or when the producer was built against a QEMU plugin API older than 5. See §5.1. |
| `filters`          | array     | The active `filter=` ranges, in argument order; empty when unfiltered. Each element is `{"start": "0x...", "end": "0x..."}` with **hex strings** (JSON numbers cannot hold 64-bit values losslessly). `start` is inclusive, `end` is exclusive. |

The binary header is authoritative. Where a metadata field duplicates a header
field, a reader should prefer the header and may treat a mismatch as
corruption.

### 6.1 Escaping

`test_id`, `bsp` and `elf` are free-form strings taken from the plugin's
command line, and `elf` is a filesystem path — a Windows-style path or a
shell-quoted label really does contain `"` or `\`. The producer therefore
JSON-escapes them: `"` and `\` are backslash-escaped, and control characters
are emitted as `\b`, `\f`, `\n`, `\r`, `\t` or `\u00XX`.

**The metadata section is valid JSON and valid UTF-8 whatever those arguments
contain.** This matters more than it looks: the metadata is one blob, so a
single stray quote used to make the *entire artifact* unreadable — every
correct binary record in it included — and the failure appeared at read time,
far from the launch line that caused it.

A reader must unescape normally and must not assume these values contain no
backslashes.

One case is lossy. A POSIX path is a byte string with no encoding attached, so
it may contain a byte that is not part of a well-formed UTF-8 sequence. Such a
byte is emitted as the escape `\u00XX` of its own value, because the
alternative — passing it through — yields a metadata section the reader cannot
decode at all. That value reads back as text but is not byte-recoverable.
Well-formed UTF-8 passes through unchanged.

---

## 7. Endianness and versioning rules

* `magic` is a byte sequence and is not byte-swapped.
* Every other header field, and every field of every address and edge record,
  is stored in the byte order named by `endian`.
* The current writer always writes native little-endian and sets `endian = 1`.
  `endian = 2` (big-endian) is defined by the format so that a big-endian host
  build could write native-order files; a reader should implement both and
  reject any other value.
* `endian` describes the **file**, not the guest. A big-endian guest observed
  by a little-endian host produces `endian = 1`.
* A reader should validate, in this order: `magic` equals the 8 magic bytes;
  `endian` is `1` or `2`; `version` is `1`; `header_size` is at least 88.
* `header_size` is the forward-compatibility hinge. Read `header_size` bytes
  for the header, use only the first 88, and locate the metadata via
  `metadata_offset` rather than assuming it starts at 88. A future version
  that appends fields will grow `header_size` and such a reader keeps working.

### Backwards compatibility

Earlier files produced by this plugin under its previous name used the magic
`"RTQCov1"` and an **80-byte** header without the three edge fields. The magic
changed to `"TCGCOV1"` in the same release that added the edge fields, so
there is no ambiguity and no compatibility shim is required: **every file whose
magic is `"TCGCOV1\0"` has an 88-byte header containing the edge fields.**
A reader may reject `"RTQCov1"` outright. Even so, prefer driving section
lookup from `header_size` and the `*_offset` fields rather than from hardcoded
constants.

---

## 8. Worked example

A real 497-byte file: `record_type = 1` (TB addresses), counts off, edges on
without edge counts, three address records and two edges, no filters.

This capture predates the removal of the `counts=` argument, so it is a
combination the current plugin can no longer produce — 8-byte address records
and 16-byte edge records. It is kept exactly as captured *because* of that: it
is a worked example of the cleared-flag layouts a reader must still handle, and
the equivalent file from today's plugin differs only in having bits 0 and 2 set
and the wider records that implies.

```
metadata_size  = 353
records_offset = 88 + 353  = 441   (0x1b9)
records_size   = 3 * 8     = 24    (0x18)
edges_offset   = 441 + 24  = 465   (0x1d1)
edges_size     = 2 * 16    = 32    (0x20)
total          = 497
```

Note that `records_offset = 441` is not 8-byte aligned — as warned in §1.

```
00000000: 5443 4743 4f56 3100 0100 0100 5800 0000  TCGCOV1.....X...
00000010: 0100 0000 0200 0000 0300 0000 0000 0000  ................
00000020: 5800 0000 0000 0000 6101 0000 0000 0000  X.......a.......
00000030: b901 0000 0000 0000 1800 0000 0000 0000  ................
00000040: 0200 0000 0000 0000 d101 0000 0000 0000  ................
00000050: 2000 0000 0000 0000 7b0a 2020 2266 6f72   .......{.  "for
00000060: 6d61 7422 3a20 2274 6367 636f 7622 2c0a  mat": "tcgcov",.
00000070: 2020 2276 6572 7369 6f6e 223a 2031 2c0a    "version": 1,.
00000080: 2020 226d 6f64 6522 3a20 2274 6222 2c0a    "mode": "tb",.
00000090: 2020 2274 6172 6765 745f 6e61 6d65 223a    "target_name":
000000a0: 2022 6d69 6372 6f62 6c61 7a65 656c 222c   "microblazeel",
000000b0: 0a20 2022 7379 7374 656d 5f65 6d75 6c61  .  "system_emula
000000c0: 7469 6f6e 223a 2074 7275 652c 0a20 2022  tion": true,.  "
000000d0: 7465 7374 5f69 6422 3a20 2222 2c0a 2020  test_id": "",.  
000000e0: 2262 7370 223a 2022 222c 0a20 2022 656c  "bsp": "",.  "el
000000f0: 6622 3a20 2222 2c0a 2020 2261 6464 7265  f": "",.  "addre
00000100: 7373 5f6b 696e 6422 3a20 2276 6164 6472  ss_kind": "vaddr
00000110: 222c 0a20 2022 636f 756e 7473 5f65 6e61  ",.  "counts_ena
00000120: 626c 6564 223a 2066 616c 7365 2c0a 2020  bled": false,.  
00000130: 2272 6563 6f72 645f 636f 756e 7422 3a20  "record_count": 
00000140: 332c 0a20 2022 6564 6765 735f 656e 6162  3,.  "edges_enab
00000150: 6c65 6422 3a20 7472 7565 2c0a 2020 2265  led": true,.  "e
00000160: 6467 655f 636f 756e 7422 3a20 322c 0a20  dge_count": 2,. 
00000170: 2022 696e 736e 5f66 6964 656c 6974 7922   "insn_fidelity"
00000180: 3a20 2265 7861 6374 222c 0a20 2022 6469  : "exact",.  "di
00000190: 7363 6f6e 5f74 7261 636b 696e 6722 3a20  scon_tracking": 
000001a0: 6661 6c73 652c 0a20 2022 6669 6c74 6572  false,.  "filter
000001b0: 7322 3a20 5b5d 0a7d 0a00 1000 0000 0000  s": [].}........
000001c0: 0010 1000 0000 0000 0020 1000 0000 0000  ......... ......
000001d0: 000c 1000 0000 0000 0010 1000 0000 0000  ................
000001e0: 001c 1000 0000 0000 0000 1000 0000 0000  ................
000001f0: 00                                       .
```

### Header decoded

| Offset | Bytes                     | Field             | Value |
|-------:|---------------------------|-------------------|-------|
| 0x00   | `54 43 47 43 4F 56 31 00` | `magic`           | `"TCGCOV1\0"` |
| 0x08   | `01 00`                   | `version`         | 1 |
| 0x0A   | `01 00`                   | `endian`          | 1 (little) |
| 0x0C   | `58 00 00 00`             | `header_size`     | 88 |
| 0x10   | `01 00 00 00`             | `record_type`     | 1 (`TB_ADDR`) |
| 0x14   | `02 00 00 00`             | `flags`           | `HAS_EDGES` only |
| 0x18   | `03 00 00 00 00 00 00 00` | `record_count`    | 3 |
| 0x20   | `58 00 ...`               | `metadata_offset` | 88 |
| 0x28   | `61 01 ...`               | `metadata_size`   | 353 |
| 0x30   | `b9 01 ...`               | `records_offset`  | 441 |
| 0x38   | `18 00 ...`               | `records_size`    | 24 |
| 0x40   | `02 00 ...`               | `edge_count`      | 2 |
| 0x48   | `d1 01 ...`               | `edges_offset`    | 465 |
| 0x50   | `20 00 ...`               | `edges_size`      | 32 |

### Metadata (offsets 0x58 .. 0x1B8 inclusive, 353 bytes)

```json
{
  "format": "tcgcov",
  "version": 1,
  "mode": "tb",
  "target_name": "microblazeel",
  "system_emulation": true,
  "test_id": "",
  "bsp": "",
  "elf": "",
  "address_kind": "vaddr",
  "counts_enabled": false,
  "record_count": 3,
  "edges_enabled": true,
  "edge_count": 2,
  "insn_fidelity": "exact",
  "discon_tracking": false,
  "filters": []
}
```

`discon_tracking` is `false` here because this capture was taken with a plugin
built against a QEMU whose plugin API predates the discontinuity callback; see
§5.1 for what that costs.

### Address records (offset 441 = 0x1B9, 3 × 8 bytes)

| Offset | Bytes                     | `addr`   |
|-------:|---------------------------|----------|
| 0x1B9  | `00 10 00 00 00 00 00 00` | `0x1000` |
| 0x1C1  | `10 10 00 00 00 00 00 00` | `0x1010` |
| 0x1C9  | `20 10 00 00 00 00 00 00` | `0x1020` |

Sorted ascending, as required.

### Edge records (offset 465 = 0x1D1, 2 × 16 bytes)

| Offset | `src`    | `dst`    | Reading |
|-------:|----------|----------|---------|
| 0x1D1  | `0x100c` | `0x1010` | the block starting at `0x1000` ran to its last instruction at `0x100c` and fell through / branched to the block at `0x1010` |
| 0x1E1  | `0x101c` | `0x1000` | the block starting at `0x1010` ran to its last instruction at `0x101c` and transferred back to `0x1000` (a loop back-edge) |

Sorted ascending by `(src, dst)`: `0x100c < 0x101c`.

---

## 9. Reader pseudocode

```python
import json, struct

def read(path):
    blob = open(path, "rb").read()

    magic = blob[0:8]
    if magic != b"TCGCOV1\0":
        raise ValueError("not a TCGCOV1 file")

    endian = int.from_bytes(blob[10:12], "little")   # endian field itself is
    e = "<" if endian == 1 else ">"                  # symmetric in both orders
    if endian not in (1, 2):
        raise ValueError("bad endian field")

    (version, _endian, header_size, record_type, flags,
     record_count, metadata_offset, metadata_size,
     records_offset, records_size,
     edge_count, edges_offset, edges_size) = struct.unpack_from(
        e + "HHIII8Q", blob, 8)

    if version != 1 or header_size < 88:
        raise ValueError("unsupported version")

    meta = json.loads(blob[metadata_offset:metadata_offset + metadata_size])

    has_counts  = bool(flags & 0x1)
    has_edges   = bool(flags & 0x2)
    edge_counts = bool(flags & 0x4)

    arec = 16 if has_counts else 8
    assert records_size == record_count * arec

    addrs = []
    for i in range(record_count):
        off = records_offset + i * arec
        if has_counts:
            addrs.append(struct.unpack_from(e + "QQ", blob, off))
        else:
            addrs.append((struct.unpack_from(e + "Q", blob, off)[0], None))

    edges = []
    if has_edges:
        erec = 24 if edge_counts else 16
        assert edges_size == edge_count * erec
        for i in range(edge_count):
            off = edges_offset + i * erec
            if edge_counts:
                edges.append(struct.unpack_from(e + "QQQ", blob, off))
            else:
                src, dst = struct.unpack_from(e + "QQ", blob, off)
                edges.append((src, dst, None))

    return meta, record_type, addrs, edges
```

The `<`/`>` prefix also disables struct alignment, which is what makes the
single `unpack_from(e + "HHIII8Q", blob, 8)` land on exactly offsets
8, 10, 12, 16, 20, 24, 32, 40, 48, 56, 64, 72, 80 — matching the table in §2.

---

## 10. Producer arguments

For reference, the plugin arguments that shape the output:

| Argument       | Default        | Effect |
|----------------|----------------|--------|
| `out=PATH`     | `tcgcov.cov`   | Output file path. Written via a private temporary in the same directory and renamed into place; a failed write leaves any existing file untouched, and concurrent runs sharing one path do not corrupt each other. See §1. |
| `mode=tb`      | —              | `record_type = 1`, one record per executed translation-block start. Cheapest; one callback per block. |
| `mode=tb-insn` | *(default)*    | `record_type = 2`, one record per instruction the CPU actually reached. `insn_fidelity = "exact"`. Costs one callback per in-range instruction — the slowest mode, and the default because a coverage tool that over-reports is worse than a slow one. `mode=insn` is an accepted alias. |
| `mode=tb-insn-fast` | —         | `record_type = 2`, but instruction addresses are expanded from a single per-block callback. `insn_fidelity = "tb-approx"`; **over-reports instructions after an aborted block**. See §4.1. |
| `edges=`       | **on**         | `edges=off` clears `HAS_EDGES` and omits the edge section. |
| `ctx=`         | off            | `ctx=on` records per-address-space-context and writes a **TCGCOV2** file with `HAS_CTX`; see §11. Requires a plugin built against a QEMU with the context-visibility API, and `mode=tb` or `mode=tb-insn-fast` (fails the launch otherwise). |
| `filter=A-B[,C-D...]` | none    | Only record addresses in `[start, end)`. Values accept `0x` hex. Recorded in `metadata.filters`. |
| `elf=PATH`     | none           | Recorded in `metadata.elf` for offline symbolization. JSON-escaped, so any path is safe; see §6.1. |
| `test_id=STR`  | none           | Free-form metadata string. JSON-escaped; see §6.1. |
| `bsp=STR`      | none           | Free-form metadata string. JSON-escaped; see §6.1. |
| `verbose=1`    | off            | Diagnostics on stderr; does not affect the file. |

Boolean arguments accept `1`/`0` as well as QEMU's own `on`/`off`,
`true`/`false`, `yes`/`no`. A malformed argument fails the plugin's
installation rather than being ignored, so a bad launch line cannot masquerade
as a coverage regression.

With `edges=off` the edge section is absent, `HAS_EDGES` is clear, and no
per-block edge-tracking work is done at run time.

**There is no `counts=` argument.** Execution counts are unconditional, so
`HAS_COUNTS` is always set and address records are always 16 bytes. Passing
`counts=` at all — `on` or `off` — **fails the launch** with a message saying
so, rather than being accepted as a no-op: a stale script that asked for a
different artifact must find out at launch, not at read time.

Counts are unconditional because making them so was a *simplification*. The
plugin used to keep a separate monotonic "executed" flag beside the count, and
the per-instruction callback had to maintain both and test the `counts` setting
in between. Once the count is always maintained the flag is redundant — an
address executed if and only if its count is non-zero — so the flag, its test
and the setting lookup were all deleted and the callback became a single
relaxed atomic increment. `edges=` survives as an option precisely because the
same argument does *not* apply to it: edges need an extra per-block callback
and a hash-table insert per block execution, which is real work that `edges=off`
genuinely removes.

### Change of default fidelity

The default `mode=tb-insn` used to be what is now `mode=tb-insn-fast`: it
expanded a per-block callback into every instruction of the block. Files
written by the current producer therefore report **fewer** instruction
addresses than older ones for the same run whenever a block aborted part way
through — the removed addresses are ones that never executed. A reader
comparing artifacts across that change should key off `metadata.insn_fidelity`
rather than assume the two are directly comparable; a missing `insn_fidelity`
means the file predates the change and is `"tb-approx"` in `tb-insn` mode.

### Change of counts and edges defaults

Counts became unconditional and edges became on-by-default in the same release.
This is **not** a format change — no offset, field or flag bit moved, and a
reader written against the previous version of this document reads the new
files correctly, because it already had to handle both flag states.

What changes is what a reader will actually see in the wild: address records
from the current producer are 16 bytes and always carry a count, and an edge
section is present unless the run asked for `edges=off`. Code that branched on
`HAS_COUNTS`/`HAS_EDGES` keeps working and simply takes the other arm more
often; code that *assumed* 8-byte address records without checking the flag was
always wrong and will now notice. Neither the covered-address set nor the edge
set is affected — an address is reported as covered under exactly the same
condition as before.

---

## 11. TCGCOV2: context records

TCGCOV2 answers the question TCGCOV1 cannot: *which guest address space
executed this address?* On a full-system guest with an MMU, every process
occupies the same VA range; a v1 artifact of a Linux boot is a blend of every
process that ran. TCGCOV2 keys every record by an **address-space context
ID** — an opaque, target-defined value reported by QEMU's (proposed)
plugin context-visibility API (MicroBlaze: the 8-bit MMU PID in `RPID`; see
`docs/QEMU-RFC-context.md`).

### What changes, exactly

* `magic` is `"TCGCOV2\0"` and `version` is `2`. The two always change
  together; a reader must reject a mismatch.
* Flag bit 3 (`HAS_CTX`, `0x8`) may be set. When it is:
  * every **address record** gains a leading `uint64 ctx`:
    `{ ctx, addr }` (16 bytes) or `{ ctx, addr, count }` (24 bytes with
    `HAS_COUNTS`), sorted ascending by `(ctx, addr)`;
  * every **edge record** gains a leading `uint64 ctx`:
    `{ ctx, src, dst }` (24 bytes) or `{ ctx, src, dst, count }` (32 bytes
    with `EDGE_COUNTS`), sorted ascending by `(ctx, src, dst)`.
* The same `addr` may appear once per context; `record_count` counts
  `(ctx, addr)` pairs. Likewise for edges.
* A context value of `2^64 - 1` means the producer could not learn the
  context (`QEMU_PLUGIN_CTX_UNAVAILABLE`): the API existed but the target
  did not report one.
* Everything else — header layout, endianness rules, metadata encoding,
  section bounds discipline — is unchanged. A TCGCOV2 file **without**
  `HAS_CTX` is byte-for-byte a TCGCOV1 file with the new magic, and is legal.

### Metadata additions

The producer records, when `ctx=on`:

* `"ctx_enabled": true`
* `"ctx_switches": N` — context-change callbacks observed;
* `"contexts": { "<decimal ctx>": { "entries": N }, ... }` — how many times
  each context was switched into (its first observation counts as an entry).

Hardware context IDs are not process IDs. Naming a context — joining it to a
binary — is a host-side step: `tcgcov contexts FILE --elf BIN` scores each
context's addresses against the ELF's executable ranges, which identifies the
context of a binary linked at a distinctive base. A guest-side
`/proc/*/maps` dump can serve the same purpose when VA ranges alone cannot.

### Edge semantics across a switch

The producer treats a context switch as a control-flow discontinuity: the
pending edge source is invalidated, so no edge is ever recorded from one
context's block to another's. An edge with context `C` asserts both endpoints
executed in `C`.

### Reader guidance

Collapsing the context axis (summing counts of the same address across
contexts, merging identical edges) reproduces exactly what a TCGCOV1 run
would have recorded; the reference reader's `read_all()` does this by
default, so v1-era consumers work on v2 files unchanged. Slicing one context
(`read_all(path, ctx=N)`, or `tcgcov contexts FILE --extract N -o OUT` to
materialize a TCGCOV1 file) is what makes per-process coverage: symbolize
the slice against that process's ELF and the entire v1 pipeline applies.
