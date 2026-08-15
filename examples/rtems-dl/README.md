# RTEMS Stage R0: coverage of a dynamically loaded object

Measured 2026-08-15 (docs/RTEMS-DL.md stage R0): RTEMS 7 `dl01` test on the
riscv/mbv BSP (`amd-microblaze-v-generic`), QEMU 10.2.4 + tcgcov plugin,
**zero RTEMS modifications** — the map comes from the loader's existing
`_rtld_debug_state()` notification, which `dlopen` really does call.

An RTEMS loadable object is ET_REL (libdl rejects ET_DYN outright), built
here with function-sections: `dl01-o1.o`'s code is a 112-byte
`.text.rtems_main`, placed at a runtime address only the loader knows.

## The run

    qemu-system-riscv32 -M amd-microblaze-v-generic -m 256m \
        -display none -monitor none -serial file:serial.log -no-reboot \
        -icount shift=0,sleep=off -s -S \
        -plugin libtcgcov.so,out=dl01.cov,mode=tb,edges=on \
        -device loader,file=dl01.exe,cpu-num=0 &
    riscv-rtems7-gdb -batch -x capture-map.gdb dl01.exe > map-raw.txt
    # ... wait for "END OF TEST" on the serial log, then SIGTERM

`capture-map.gdb` breaks on `_rtld_debug_state`, skips the pre-load RT_ADD
hit, and at the post-load RT_CONSISTENT hit walks `_rtld_debug.r_map`
printing every object's rap-region bases and `sec_detail[]` (name/size/rap),
then detaches so the test runs to completion. Captured here:

    OBJ /dl01-o1.o
    BASE text 0x80044ae0 const 0x80044a50 data (nil) bss (nil)
    SEC .text.rtems_main off 0 size 112 rap 0

## The pipeline

    tcgcov modmap --cov dl01.cov --map dl01-map.json --out-dir mods/
    #   dl01-o1.o:.text.rtems_main: 6 records, 3 edges
    #   6 addrs in mapped windows, 3101 outside (base image)
    tcgcov symbolize --cov "mods/dl01-o1.o__text.rtems_main.cov" \
        --elf .../dl01/dl01-o1.o --section .text.rtems_main \
        --addr2line riscv-rtems7-addr2line --all-paths --out sym.jsonl

## The result, against ground truth

`dl01` loads the object and calls `rtems_main` twice — once with argc=2,
once with argc=3 — and the serial log shows exactly 2 then 3 argv lines
printed. The coverage agrees line by line:

    dl01-o1.c:43  rtems_main entry   count=2    (the two calls)
    dl01-o1.c:46  for-loop           count=5    (2 + 3 iterations)
    dl01-o1.c:47  loop body

6/6 module addresses resolved; the 3,101 base-image addresses were fenced
by the map, not lost — they symbolize against `dl01.exe` as usual.

## Limits (why this is R0, not the destination)

One map, no time axis: valid only while no allocator range was reused.
`modmap` refuses overlapping windows loudly. Unload/reload workloads need
the loader-generation tagging of docs/RTEMS-DL.md stage R3.

---

# Stage R3/R4: loader generations — reuse, separately attributed

Measured 2026-08-15. Same board and QEMU; the plugin's RTEMS mode
(`plugin/tcgcov-rtems.c`) replaces both the GDB capture *and* the sidecar:

    -plugin libtcgcov.so,out=dl09.cov,mode=tb,edges=on,\
            rtl_state=0x<addr _rtld_debug_state>,rtl_debug=0x<addr _rtld_debug>

(the two addresses come from `nm` of the base image). The plugin watches
the loader's notification, bumps a **generation** per completed
load/unload, tags every record with it (TCGCOV2,
`ctx_kind: "loader-generation"`), and snapshots the module map per
generation into `metadata.rtl_generations` — the map source is now the
artifact itself.

## dl01 (single load): the no-GDB pipeline

Three generations — boot, module-live, unloaded (its snapshot correctly an
empty chain). Slicing generation 1 with a map built from
`rtl_generations["1"]` reproduces the R0 result exactly: entry 2, loop 5,
text base `0x80044ae0` identical to the independent GDB capture above.

## dl09 (address reuse): the R4 acceptance

dl09 loads o1–o5, runs them, unloads all, and repeats — four cycles, and
RTL's allocator hands back the **identical addresses** every cycle:

    o1 window [0x800523c0,0x8005254e):
      gen  5: 14 addrs, 14 execs      gen 25: 14 addrs, 14 execs
      gen 15: 14 addrs, 14 execs      gen 35: 14 addrs, 14 execs

Four separate lifetimes of the same address range, kept apart by the
generation tag. Per-lifetime slices symbolize to identical, correct
coverage (12 lines of `dl09-o1.c`, each count 1); a TCGCOV1 artifact
would have recorded count 4 per address with the lifetimes
unrecoverable. And the guard holds: feeding two lifetimes' windows to
`modmap` as one map is refused —

    error: windows overlap: ... A single map cannot describe reused
    address ranges; capture one map per loader generation instead.

The stock dl tests only ever reuse a range with the *same* object;
the harder different-object case is pinned by a format-level unit test
(`tests/test_modmap.py::GenerationReuseTest`): same address, counts 5
and 7 in two generations, each attributed to its own object's ELF.

## Constructor caveat (the R2 hooks' remaining value)

Generations bump at `RT_CONSISTENT`, which the loader signals *after*
running constructors — so ctor coverage lands one generation early,
where it shows up as unattributed rather than silently wrong. The
optional `rtems_rtl_debugger_load/unload` hooks (DYNAMIC-OBJECTS §5)
close that window; nothing in these examples needed them.

---

# Stage R1 + the cross-object reuse fixture

Measured 2026-08-15. `rtl-map-dump.c` is the R1 deliverable: ~50 lines of
**application-side** code (public RTL API only — still zero RTEMS
modifications) that prints every loaded object's per-section *runtime*
placement between markers:

    RTLMAP A-LOADED OBJ /pay_a.o SEC .text.spin 0x8004a700 78 EXEC
    ...

That is ground truth the `link_map` cannot give (it has only aggregate
region bases) — and it validated the metadata reconstruction: RTL placed
the rap-text sections exactly contiguously, as the plugin's
sequential-offset assumption predicts.

`reuse-init.c` + `pay_a.c`/`pay_b.c` + `build-reuse-fixture.sh` are the
different-object reuse fixture the stock dl tests never provide. The
payloads are structurally identical (so `-O0` emits identical section
sizes and first-fit hands B exactly A's freed block) but differ in
constants and therefore in file, counts, and line numbers. One run under
the plugin's rtl mode:

    RTLMAP A-LOADED ... .text.spin 0x8004a700 78 EXEC
    RTLMAP B-LOADED ... .text.spin 0x8004a700 78 EXEC     <- same addresses

    generation 1 -> pay_a.c: spin loop body count 7,  pad_uncovered absent
    generation 3 -> pay_b.c: spin loop body count 11, pad_uncovered absent

The same TB address (`0x8004a716`) carries count 7 in generation 1 and 11
in generation 3, each attributed to its own source file via maps parsed
straight from the RTLMAP dump. The unit-test case of R4 is now also
demonstrated live.

Build notes: links against the mbv waf build tree directly (includes +
`-B/-L` + `librtemsbsp -lrtemscpu`), with the dl-testsuite's two-pass
`rtems-syms` link for the runtime symbol table. See the script for the
exact recipe.

---

# Stage R2: the per-object hooks (RTEMS patch, fork-only)

2026-08-15. The one RTEMS modification of the plan, prepared and verified
but **not submitted anywhere**: branch `rtl-debugger-hooks` (d9ca18310d)
on the GitLab fork adds `rtems_rtl_debugger_load/unload(obj)` — empty,
`RTEMS_NO_INLINE`, per object — called from `rtl.c` after cache sync /
before constructors, and before teardown, exactly per DYNAMIC-OBJECTS §5.
30 inserted lines including the installed header and spec entry.

Verified without rebuilding the BSP: `RTL_OVERRIDE=1` makes
`build-reuse-fixture.sh` compile the patched `rtl.c`/`rtl-debugger.c`
out-of-tree and link them ahead of the archives, and `WITH_CTOR=1` gives
payload A a constructor. `verify-hooks.gdb` then breakpoints both hooks:

    HOOK LOAD obj=/pay_a.o ctor_run=0     <- flag clear: hook precedes ctors
    HOOK UNLOAD obj=/pay_a.o
    HOOK LOAD obj=/pay_b.o ctor_run=0
    HOOK UNLOAD obj=/pay_b.o

with `pay_a: ctor ran` on the serial console after the load hook — the
per-object identity, full load-path coverage, and pre-constructor timing
that `_rtld_debug_state()` cannot provide. The two fixture configurations
are both one env var away: reuse needs size-identity (no ctor), the
ordering proof needs the ctor.
