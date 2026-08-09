# Coverage of dynamically loaded objects

> **STATUS: PLAN. Nothing described here is implemented.**
>
> This document is a design and roadmap for a feature tcgcov does not have. No
> code in this repository handles dynamically loaded objects today. Sections
> marked **verified** were checked against real source at the versions cited;
> sections marked **unverified** are reasoning that has not been confirmed.
> Treat the proposed interfaces as proposals, not as anything that exists.

---

## 1. The problem

tcgcov symbolizes guest addresses against **one static ELF**, named in the
`.cov` artifact's own metadata. The whole offline pipeline rests on a single
assumption: *the address the plugin observed is the address the DWARF line
table describes.* For a bare-metal image linked to fixed addresses that
assumption is free.

It fails the moment code arrives at runtime.

| | Static image | Dynamically loaded object |
|---|---|---|
| Address the plugin records | runtime vaddr | runtime vaddr |
| Address DWARF describes | link-time vaddr | link-time vaddr (usually 0-based) |
| Relationship | identity | unknown offset, per object, per section |
| Which file explains it | the one ELF | one of *N*, and *N* varies over the run |

Two distinct pieces of information are missing, and they are missing
independently:

1. **Attribution.** Given address `0x8042A118`, which object file does it
   belong to? Without a module map the address is unattributable — it might be
   in the base image, in a loaded module, or in nothing at all.
2. **Translation.** Even once attributed, the runtime address must be mapped
   back to the link-time address that `.debug_line` indexes, so `addr2line`
   can answer. For a shared library that is a single subtraction. For a
   relocatable object placed section by section, it is not (see §4).

The consequence today is silent, not loud: addresses that fall outside the
static ELF simply resolve to nothing and are dropped during normalization. A
system whose interesting logic lives entirely in loadable modules reports
coverage of the loader and nothing else, with no warning that anything was
missed. **Silent under-reporting is the worst failure mode a coverage tool
has**, and it is the strongest argument for doing this work.

A third problem is easy to overlook and turns out to drive the design:
**addresses are only unique within a time window**. If module A is unloaded and
module B is loaded into the same allocator range, one address denotes two
different source lines at two different times. The current `.cov` format
records a deduplicated *set* of addresses with no ordering and no timestamps,
so this ambiguity is not merely unresolved — it is unrepresentable. §7 returns
to this.

---

## 2. How Linux solves the debugger side: the SVR4 rendezvous

Every dynamic-loading system that a debugger can follow has some version of
this protocol. It is worth stating precisely, because the RTEMS discussion
below is entirely a comparison against it.

**Verified** against the SVR4 gABI / glibc `elf/link.h` and `elf/rtld.c`
conventions; GDB's consumer is `gdb/solib-svr4.c` (see `svr4_solib_create_inferior_hook`,
`enable_break`, `solib_event_probe_action`, and `svr4_current_sos`).

### The structures

```c
struct r_debug {
    int r_version;              /* protocol version; 1 for the base protocol */
    struct link_map *r_map;     /* head of the loaded-object chain           */
    ElfW(Addr) r_brk;           /* address the linker calls on every change  */
    enum {
        RT_CONSISTENT,          /* the map is stable and may be read         */
        RT_ADD,                 /* an object is being added                  */
        RT_DELETE               /* an object is being removed                */
    } r_state;
    ElfW(Addr) r_ldbase;        /* load base of the dynamic linker itself    */
};

struct link_map {
    ElfW(Addr)  l_addr;         /* load bias: runtime - link-time            */
    char       *l_name;         /* absolute path of the object               */
    ElfW(Dyn)  *l_ld;           /* the object's dynamic section              */
    struct link_map *l_next, *l_prev;   /* doubly-linked chain               */
};
```

### The bootstrap

The debugger has a chicken-and-egg problem: it must find `r_debug` before any
of the loader's own symbols are necessarily available. The gABI answer is
`DT_DEBUG`. The executable's `.dynamic` section contains a `DT_DEBUG` entry
that the static linker emits with value 0; the dynamic linker fills it in at
startup with `&_r_debug`. The debugger reads the program headers of the
executable it already has on disk, finds `PT_DYNAMIC`, walks it to `DT_DEBUG`,
and reads the pointer out of guest memory. From there everything else follows.
(GDB has fallbacks — locating `_r_debug` by symbol, or `_dl_debug_state` — but
`DT_DEBUG` is the defined path.)

### The handshake

`r_brk` points at a function whose body is deliberately **empty**. It exists
solely as a place to plant a breakpoint. The sequence on a `dlopen()`:

| Step | Loader | Debugger |
|---|---|---|
| 0 | — | breakpoint planted at `r_brk` |
| 1 | `r_state = RT_ADD` | |
| 2 | call `r_brk` | **hit 1**: reads `r_state == RT_ADD`, learns a change is *starting*, does **not** read `r_map` (it is inconsistent), continues |
| 3 | map the object, relocate, link into `r_map` | |
| 4 | `r_state = RT_CONSISTENT` | |
| 5 | call `r_brk` | **hit 2**: reads `r_state == RT_CONSISTENT`, re-walks `r_map`, diffs against its own list, loads symbols for the new entry, continues |

Unload is the mirror image with `RT_DELETE`, and the debugger must drop the
object's symbols on **hit 1**, while the object still exists, rather than after
it is gone.

This **double hit** is the core of the protocol, and the reason it is a
protocol rather than a single callback: the loader announces the boundaries of
a window during which its own data structures must not be trusted. Anything
that reads `r_map` at an arbitrary moment — including a naive plugin polling
guest memory — can observe a half-linked chain.

Two properties matter for what follows:

- **`l_addr` is a single scalar.** It works because a shared object is
  `ET_DYN`: the link editor laid out all its `PT_LOAD` segments at fixed
  relative offsets, and the loader maps that whole layout at one bias. Every
  section shifts by the same amount.
- **The debugger reads everything out of guest memory.** It needs no
  cooperation beyond the loader maintaining the structures and calling `r_brk`.

---

## 3. RTEMS status

**Verified** against `/…/rtems` at commit `81df76877f`
(`build/2026-03-04-155-g81df76877f`), and `rtems-tools` at `16a8293`. All file
paths below are relative to the RTEMS source root. Line numbers are from that
commit and will drift.

### 3.1 The data exists, and it is good data

RTEMS's Runtime Loader (RTL, `cpukit/libdl`) already tracks everything a
coverage tool or a debugger needs.

`struct rtems_rtl_obj` (`cpukit/include/rtems/rtl/rtl-obj.h:206`) holds, per
loaded object:

| Field | Meaning |
|---|---|
| `rtems_chain_control sections` | chain of `rtems_rtl_obj_sect` — the **full per-section map** |
| `text_base` / `text_size` | aggregate base of the text region |
| `const_base`, `eh_base`, `data_base`, `bss_base` (+ sizes) | aggregate bases of the other regions |
| `exec_size`, `entry` | total footprint, entry point |
| `tramp_base` / `tramp_size` | trampoline/veneer area |
| `struct link_map* linkmap` | annotated in the header `/**< For GDB. */` |
| `oname`, `fname`, `aname` | object, file and archive names |

`struct rtems_rtl_obj_sect` (`rtl-obj.h:151`) carries, per section:
`section` (index), `name`, `size`, `offset` (offset *within the object file*),
`alignment`, `link`, `info`, `flags`, **`base`** (the runtime address of that
section), and `load_order`. Public accessors exist:
`rtems_rtl_obj_find_section()` (`:538`), `..._by_index()` (`:550`),
`..._by_mask()` (`:564`).

Symbols are tracked too, and the shell exposes both views —
`cpukit/libdl/rtl-shell.c`, command table at `:1058`, dispatcher
`rtems_rtl_shell_command` at `:1057`:

- `rtl list -m` (`rtems_rtl_shell_list` at `:547`, option string `"anlmsdbt"`)
  prints, per object, via `rtems_rtl_obj_printer` (`:457-468`):
  `exec size`, then `text base`, `const base`, `data base`, `bss base`, each as
  `%p (%zi)`.
  **Note the limitation:** it prints only the four *aggregate* bases. It does
  **not** print the per-section `rtems_rtl_obj_sect.base` values — grep for
  `sect->base` in `rtl-shell.c` returns nothing. The finer map exists in
  `obj->sections` but no shell command surfaces it.
- `rtl sym` (`:589`) prints `<name> = 0xADDR` per global symbol
  (`rtems_rtl_print_symbols`, `:346`). Locals are erased at load
  (`rtl-elf.c:1712`), so only globals appear.

### 3.2 The debugger notification is a non-functional stub

This is the finding that shapes the whole plan, and the original framing —
"the notification does not exist" — is **not quite right**. A vestigial
NetBSD-derived skeleton *does* exist and *is* wired into `dlopen`/`dlclose`.
It simply cannot be consumed by GDB.

What exists, in `cpukit/libdl/rtl-debugger.c`:

- `struct r_debug _rtld_debug;` (`:55`)
- `void _rtld_debug_state(void)` (`:57`) — **the body is empty**, with the
  comment `/* Empty. GDB only needs to hit this location. */`
- `_rtld_linkmap_add()` (`:63`) and `_rtld_linkmap_delete()` (`:92`), which
  maintain the `r_map` chain
- driven from `cpukit/libdl/dlfcn.c`: `r_state = RT_ADD` + call at `:69-70`,
  `RT_CONSISTENT` + call at `:78-79`, `RT_DELETE` at `:100-101`,
  `RT_CONSISTENT` at `:105-106`
- `extern struct r_debug _rtld_debug;` is public at
  `cpukit/include/rtems/rtl/rtl.h:104`

So the *shape* of the SVR4 handshake is there. Why it does not work:

| Requirement | RTEMS reality | Source |
|---|---|---|
| `r_brk` — the address GDB breakpoints | **Does not exist.** A tree-wide grep finds `r_brk` exactly once, *in a comment* at `rtl-debugger.c:15`. Never declared, never assigned. | `cpukit/contrib/include/link_elf.h:59-67` |
| `r_ldbase` | Does not exist | same |
| SVR4 field order | Differs: `r_state` occupies the slot where `r_brk` belongs, so a byte-level read misparses | same |
| Symbol name `_r_debug` | It is `_rtld_debug` | `rtl-debugger.c:55` |
| `link_map.l_addr`, `l_name`, `l_ld` | **None of the three exist.** RTEMS's `link_map` (`link_elf.h:45-54`) has `name`, `sec_num`, `sec_detail`, `sec_addr[]`, `rpathlen`, `rpath`, `l_next`, `l_prev` | `link_elf.h:45-54` |
| `DT_DEBUG` bootstrap | Absent — consistent with §4: no dynamic segment is ever processed | tree-wide grep |
| `_dl_debug_state` | Absent | tree-wide grep |
| Stub-side reporting `qXfer:libraries` | **Not implemented.** `cpukit/libdebugger/` has *zero* references to `rtl`, `libdl`, `link_map`, `r_debug` or `dlopen`. It advertises only `qXfer:features` (`rtems-debugger-server.c:765`) and `qXfer:osdata` (`:766`). | `cpukit/libdebugger/` |
| Any hook/callback registration in libdl | Absent — grep for `hook`/`notify`/`_cb`/`callback` across `rtl.c`, `rtl-obj.c`, `rtl.h`, `rtl-obj.h` returns nothing | — |

`rtems-tools` (`16a8293`) contains no references to `r_debug`, `_rtld_debug`
or `link_map` at all; its `tools/*/gdb/` directories are RSB build patches for
compiling GDB, not module-awareness support.

**The accurate summary:** the per-section address data exists and is even
copied into a GDB-shaped `link_map` by `rtems_rtl_elf_load_linkmap()`
(`rtl-elf.c:1470-1560`), but the debugger handshake is inert — no `r_brk`, two
ABI-incompatible struct layouts, the wrong symbol name, and no stub-side
library reporting. **The information is present; the notification is not
consumable.**

### 3.3 The load sequence

**Verified.** Function names and line numbers from the commit above.

```
dlopen                                              dlfcn.c:62
├─ rtems_rtl_lock()
├─ _rtld_debug.r_state = RT_ADD; _rtld_debug_state()        dlfcn.c:69-70
├─ rtems_rtl_load(name, mode)                               rtl.c:559
│  ├─ rtems_rtl_archives_refresh()
│  ├─ rtems_rtl_load_object()                               rtl.c:489
│  │  ├─ rtems_rtl_find_obj()          already loaded?
│  │  ├─ rtems_rtl_obj_alloc()                              rtl.c:506
│  │  ├─ rtems_rtl_obj_find_file()     resolve search path  rtl.c:518
│  │  └─ rtems_rtl_obj_load(obj)                            rtl-obj.c:1242
│  │     └─ rtems_rtl_elf_file_load()                       rtl-elf.c:1563
│  │        ├─ validate Ehdr; REJECT ET_DYN; REJECT e_phentsize != 0   :1597
│  │        ├─ rtems_rtl_elf_parse_sections()               :1622
│  │        ├─ obj->entry = ehdr.e_entry                    :1629
│  │        ├─ rtems_rtl_obj_load_symbols(elf_common)       :1639
│  │        ├─ rtems_rtl_elf_add_common()                   :1642
│  │        ├─ rtems_rtl_obj_load_symbols(symbols_load)     :1645
│  │        ├─ rtems_rtl_obj_relocate(relocs_parser)        :1653  parse only
│  │        ├─ rtems_rtl_obj_alloc_sections()               :1666  ** sect->base set **
│  │        ├─ rtems_rtl_elf_dependents()                   :1670
│  │        ├─ rtems_rtl_elf_find_trampolines()             :1674
│  │        ├─ rtems_rtl_obj_resize_sections()              :1683
│  │        ├─ rtems_rtl_obj_load_symbols(symbols_locate)   :1688
│  │        ├─ rtems_rtl_obj_load_sections(elf_loader)      :1701  ** bytes copied in **
│  │        ├─ rtems_rtl_obj_relocate(relocs_locator)       :1708  ** real relocation **
│  │        ├─ rtems_rtl_symbol_obj_erase_local()           :1712
│  │        ├─ rtems_rtl_elf_load_linkmap(obj)              :1714
│  │        └─ rtems_rtl_elf_unwind_register()              :1718
│  │     └─ _rtld_linkmap_add(obj)      /* For GDB */       rtl-obj.c:1281
│  ├─ rtems_rtl_unresolved_resolve()                        rtl.c:576
│  └─ for each pending obj:
│        rtems_rtl_obj_synchronize_cache(pobj)              rtl.c:596  I-cache flush
│     ┌─ <<<<<<<<<<<<<<<<  PROPOSED LOAD HOOK GOES HERE  >>>>>>>>>>>>>>>>
│     └─ rtems_rtl_obj_run_ctors(pobj)                      rtl.c:607
├─ _rtld_debug.r_state = RT_CONSISTENT; _rtld_debug_state()  dlfcn.c:78-79
└─ rtems_rtl_unlock()
```

Unload:

```
dlclose                                             dlfcn.c:86
├─ rtems_rtl_lock(); rtems_rtl_check_handle()
├─ _rtld_debug.r_state = RT_DELETE; _rtld_debug_state()     dlfcn.c:100-101
├─ rtems_rtl_unload(obj)                                    rtl.c:649
│  ├─ rtems_rtl_unload_object()   refcounts, --obj->users    rtl.c:617
│  ├─ orphan sweep -> private `unloading` chain
│  ├─ rtems_rtl_obj_run_dtors(uobj)                         rtl.c:700
│  └─ per obj:
│     ┌─ <<<<<<<<<<<<<<  PROPOSED UNLOAD HOOK GOES HERE  >>>>>>>>>>>>>>
│     ├─ rtems_rtl_obj_unload(uobj)                         rtl.c:719
│     │  └─ _rtld_linkmap_delete(obj)                       rtl-obj.c:1294
│     └─ rtems_rtl_obj_free(uobj)      ** memory released ** rtl.c:722
└─ _rtld_debug.r_state = RT_CONSISTENT; _rtld_debug_state()  dlfcn.c:105-106
```

---

## 4. The key structural difference: RTEMS loads ET_REL

**Verified**, `cpukit/libdl/rtl-elf.c:1597-1605`:

```c
  if (ehdr.e_type == ET_DYN) {
    rtems_rtl_set_error(EINVAL, "unsupported ELF file type");
    return false;
  }

  if (ehdr.e_phentsize != 0) {
    rtems_rtl_set_error(EINVAL, "ELF file contains program headers");
    return false;
  }
```

`ET_DYN` is rejected explicitly, and the second check rejects **anything with
program headers**, which excludes `ET_EXEC` too. What survives is `ET_REL`:
plain relocatable objects, the output of `gcc -c` or a `.a` archive member.
This is a design restriction enforced at `rtl-elf.c:1602`, not a size limit —
libdl cannot load a `PT_LOAD` segment at all.

The consequence is decisive for this feature:

| | Linux shared object (`ET_DYN`) | RTEMS libdl object (`ET_REL`) |
|---|---|---|
| Layout fixed at link time? | Yes — segments at fixed relative offsets | **No** — sections are independent |
| Placement | one `mmap` of the whole layout | per-section allocation from RTL's allocator |
| `.text`, `.data`, `.bss` relationship | constant offsets, preserved | **arbitrary**; may be in different memory regions entirely (e.g. text in a fast SRAM pool, bss elsewhere) |
| Bias representable as a scalar? | Yes: `l_addr` | **No** |
| Translation to link-time address | `runtime - l_addr` | `runtime - sect[i].base + sect[i].link_time_addr`, per section |

**This is the single reason RTEMS cannot reuse Linux's `link_map` verbatim.**
A one-scalar `l_addr` is not merely inconvenient here, it is
information-theoretically insufficient: given only `l_addr` there is no
function from a runtime address to a link-time address that is correct for
more than one section.

RTEMS already knows this. `rtems_rtl_elf_load_linkmap()`
(`rtl-elf.c:1470-1560`) builds a `sec_detail[]` array from the section chain
using the masks `SECT_TEXT|LOAD`, `SECT_CONST|LOAD`, `SECT_DATA|LOAD`,
`SECT_BSS` (`:1481-1485`), storing per-section `name`, `size`, `rap_id`, and an
`offset` computed as `sect->base - obj-><region>_base` (`:1539-1551`). The
per-section map is therefore *already materialized* in a GDB-adjacent
structure — it is simply not in a layout GDB parses, and nothing tells GDB it
changed. `obj->obj_num` is hardcoded to 1 for ELF (`:1504`); the multi-object
path exists only for the RAP format (`rtl-rap.c:426`).

For tcgcov's purposes, note also that an `ET_REL` object's DWARF is
**0-based per section**: `.debug_line` describes addresses relative to the
section start, and the `.rela.debug_line` relocations that would resolve them
are applied by RTL into RAM, not back into the file on disk. Offline
`addr2line` against the unmodified `.o` therefore needs the per-section runtime
base subtracted, and cannot be given a single `--adjust-vma`. This is an
implementation cost that §7 has to absorb.

---

## 5. Proposed RTEMS-side hooks

**Proposal, not implemented, not submitted upstream.**

### 5.1 The interface

Two functions, explicitly exported, deliberately trivial:

```c
/* cpukit/include/rtems/rtl/rtl-debugger.h  (proposed) */

/*
 * Called once per object, after the object is fully loaded, relocated,
 * cache-synchronized and published, and BEFORE its constructors run.
 * The object and all its section bases are final and valid.
 */
void rtems_rtl_debugger_load(const rtems_rtl_obj* obj);

/*
 * Called once per object, before any part of it is torn down. The object,
 * its sections and its symbols are still fully valid at this point.
 */
void rtems_rtl_debugger_unload(const rtems_rtl_obj* obj);
```

Both bodies are empty, exactly as `_rtld_debug_state()` already is. They exist
to be *breakpointed*, and secondarily to be *overridden* by an application that
wants to do something in-target (log the map, push it out a UART, write it to a
file).

### 5.2 Why not hook `dlopen()`

Hooking the public `dlopen()` entry point — by breakpointing it, or by wrapping
it — is the obvious idea and it is wrong, for reasons that are worth being
precise about:

1. **At `dlopen()` entry, the object does not exist.** `rtems_rtl_obj_alloc()`
   has not run (`rtl.c:506`), no memory has been allocated, and there are no
   section bases to report. There is nothing to observe.
2. **At `dlopen()` return, the addresses are final but the attribution is
   lost.** `dlopen()` returns one handle, but a single call can load an
   arbitrary number of objects: dependency resolution
   (`rtems_rtl_elf_dependents`, `:1670`) and the unresolved-symbol pass
   (`rtems_rtl_unresolved_resolve`, `rtl.c:576`) can pull in further objects,
   and the loop at `rtl.c:590-610` iterates over a *set* of pending objects.
   A per-`dlopen` notification cannot say which objects those were without the
   consumer diffing the whole object list itself — which is exactly the work
   the hook is supposed to eliminate.
3. **Constructors run before `dlopen()` returns** (`rtems_rtl_obj_run_ctors`,
   `rtl.c:607`). A debugger that only learns about the object at return has
   already missed every line a static constructor executed. For a coverage
   tool that is a systematic, silent under-count of exactly the code that is
   hardest to test.
4. **Objects can be loaded without `dlopen()` at all** — `rtl obj load` from
   the shell (`rtl-shell.c:624`) goes through `rtems_rtl_load_object()`
   directly.

Reason 3 is why the hook is placed *before* `run_ctors` rather than after, and
reason 2 is why it is **per object** rather than per `dlopen()`.

### 5.3 Placement

| Hook | Site | Why exactly there |
|---|---|---|
| `rtems_rtl_debugger_load` | `rtl.c`, between `rtems_rtl_obj_synchronize_cache(pobj)` (`:596`) and `rtems_rtl_obj_run_ctors(pobj)` (`:607`) | Relocation is complete, the I-cache is coherent, the object is on `rtl->objects`, section bases are final — and no code from the object has executed yet. It is the last moment a consumer can prepare before the module runs. |
| `rtems_rtl_debugger_unload` | `rtl.c`, at the top of the final unload loop (`:711-714`), before `rtems_rtl_obj_unload(uobj)` (`:719`) | Destructors have already run, so nothing more will execute; the object, sections, symbols and bases are all still intact; `_rtld_linkmap_delete()` and `rtems_rtl_obj_free()` (`:722`) have not yet torn anything down. |

The load site is the earliest point at which the addresses are *final*, and the
unload site is the latest point at which they are *still valid*. Together they
bracket the object's lifetime exactly.

### 5.4 Why named functions rather than the existing `_rtld_debug_state()`

`_rtld_debug_state()` is per-`dlopen`, carries no argument, and is entangled
with the broken `struct r_debug`. Adding an argument to it would change an
existing (if inert) ABI. Two new, clearly-named, explicitly-exported symbols:

- give the consumer the object pointer directly, so no global chain walk and
  no `RT_CONSISTENT` window reasoning is required — the object handed to the
  hook is already consistent by construction;
- are **stable names to depend on**. Tooling that breakpoints
  `rtems_rtl_obj_load_sections` or reads offsets into internal structs breaks
  on every RTEMS refactor. A documented two-function contract does not.
- do not disturb the existing `_rtld_debug` machinery, so nothing that
  (somehow) depends on it regresses.

They should be compiled with the equivalent of
`__attribute__((noinline, used))` and not be subject to LTO elimination, since
their entire purpose is to have an address.

**Unverified:** whether the RTEMS project would accept such a patch, and
whether they would prefer this to be folded into a proper `r_debug` fix. A
correct SVR4-compatible `r_debug` is arguably the better long-term answer for
GDB specifically — but it cannot express a per-section map (§4), so the hooks
are needed regardless.

---

## 6. Three consumers, one interface

The value of the hook is that it is not a tcgcov feature. Three independent
consumers want the identical event.

### 6.1 GDB

GDB's `add-symbol-file` already accepts per-section addresses, which is exactly
the `ET_REL` shape:

```
(gdb) add-symbol-file module.o -s .text 0x8042A000 -s .data 0x80500100 -s .bss 0x80500400
(gdb) remove-symbol-file -a 0x8042A000
```

A breakpoint on `rtems_rtl_debugger_load` can drive that automatically. Sketch
(**untested — this is illustrative, not working code**):

```python
# rtems-rtl-gdb.py  --  source this, or auto-load it alongside the executable.
import gdb

_SKIP = ("", None)

def _sections(obj):
    """Yield (name, base) for every allocated section of an rtems_rtl_obj."""
    # obj->sections is a rtems_chain_control; nodes are the first member of
    # struct rtems_rtl_obj_sect, so the node pointer casts straight across.
    sect_p = gdb.lookup_type("rtems_rtl_obj_sect").pointer()
    node = obj["sections"]["first"]
    while int(node["next"]) != 0:          # the tail node has next == NULL
        sect = node.cast(sect_p)
        base = int(sect["base"])
        size = int(sect["size"])
        if base and size:                  # skip unallocated / empty sections
            yield sect["name"].string(), base
        node = node["next"]

class RtlLoad(gdb.Breakpoint):
    def __init__(self):
        super().__init__("rtems_rtl_debugger_load", internal=True)

    def stop(self):
        obj = gdb.newest_frame().read_var("obj")
        path = obj["fname"].string()
        args = ["add-symbol-file", path]
        text = None
        for name, base in _sections(obj):
            args += ["-s", name, hex(base)]
            if name == ".text":
                text = base
        gdb.execute(" ".join(args), to_string=True)
        if text is not None:
            _loaded[int(obj)] = text
        return False        # never actually stop the inferior

class RtlUnload(gdb.Breakpoint):
    def __init__(self):
        super().__init__("rtems_rtl_debugger_unload", internal=True)

    def stop(self):
        obj = gdb.newest_frame().read_var("obj")
        text = _loaded.pop(int(obj), None)
        if text is not None:
            gdb.execute("remove-symbol-file -a %s" % hex(text), to_string=True)
        return False

_loaded = {}
RtlLoad()
RtlUnload()
```

`return False` from `stop()` is the important detail: the breakpoint fires, the
Python runs, and the inferior continues without ever presenting a stop to the
user. This is the same technique GDB uses internally for solib events.

This alone — source-level debugging of RTEMS loadable modules, which does not
work today — is arguably worth more to the RTEMS community than the coverage
feature that motivates it, and is the strongest argument for upstreaming the
hooks.

### 6.2 tcgcov

Needs the same event for a different reason: to build the **module map** that
lets it attribute and translate addresses (§7). It does not need to stop the
guest, and in the target design (§7b) it observes the hook from outside the
guest entirely, via the QEMU plugin.

### 6.3 LLDB

**Unverified.** LLDB has `target modules add` / `target modules load --slide`
and section-level load addresses via `target modules load --file X .text ADDR`,
so the same information should map onto it. LLDB's dynamic-loader plugins are
platform classes (`DynamicLoaderPOSIXDYLD` and friends) rather than a Python
breakpoint script, so a first cut would likely be an LLDB Python script rather
than a proper plugin. Nobody has tried this.

---

## 7. What tcgcov needs, and a staged plan

### 7.1 The two artifacts

Independent of the mechanism, tcgcov needs:

**A. A module map.** Enough to attribute and translate:

```json
{
  "version": 1,
  "objects": [
    {
      "name": "sensor.o",
      "path": "/path/to/sensor.o",
      "sections": [
        {"name": ".text", "base": "0x8042a000", "size": 4096},
        {"name": ".rodata", "base": "0x80500000", "size": 512},
        {"name": ".data", "base": "0x80500200", "size": 128},
        {"name": ".bss", "base": "0x80500400", "size": 64}
      ]
    }
  ]
}
```

**B. Per-section symbolization.** `addr2line` cannot be handed a single
`--adjust-vma` for an `ET_REL` object (§4). The plan is to determine the
containing section from the map, compute
`link_time_addr = runtime_addr - sect.base + sect.file_addr` (where
`sect.file_addr` is the section's `sh_addr` in the object file, normally 0),
and call `addr2line` on the object file with that address. The existing
batched-`addr2line` machinery in `tcgcov/symbolize.py` is reusable unchanged;
only address preparation differs, and it should be grouped per object so each
object costs one `addr2line` invocation.

The coverable-line denominator needs the same treatment: `objdump -d` on the
`.o` enumerates instruction addresses in section-relative terms, which is
exactly what the DWARF wants, so **the coverable side is actually easier than
the covered side** — it needs no map at all, only the object file. A useful
consequence: the denominator for a loadable module can be built offline, ahead
of any run, from the `.o` alone.

Path normalization and merge-by-`(source, line)` then work unmodified, which is
the whole point — a module's source lines merge with the same lines built into
a static image, because the identity is the source line, not the address.

### 7.2 The three implementation options

#### (a) Sidecar module map — *recommended first cut*

The test harness dumps the object/section map to JSON (from `rtl list -m`, or
better from a small target-side routine that walks `obj->sections`, since the
shell command prints only the four aggregate bases — §3.1). tcgcov gains a
`--module-map FILE` option; `symbolize` consults it to attribute and translate
addresses that fall outside the main ELF.

| | |
|---|---|
| **QEMU changes** | none |
| **RTEMS changes** | none required (a section-level dumper is nice-to-have) |
| **Plugin/format changes** | none |
| **Works today** | yes |
| **Effort** | small — a JSON reader, an interval lookup, per-section address arithmetic |

**The fatal limitation is that a sidecar map has no time dimension.** It is a
snapshot. If module A is unloaded and module B is subsequently loaded into the
same allocator range — which RTL's allocator makes *likely*, not merely
possible, since it will happily reuse a freed block — then a single address in
the `.cov` file legitimately belongs to two different source lines, and the map
cannot say which. tcgcov would silently attribute it to whichever entry it
looked up.

Adding timestamps does not fix it either, because **the `.cov` format has no
time dimension to correlate against**: it stores a sorted, deduplicated *set*
of addresses (optionally with total counts). The ambiguity is unrepresentable
in the artifact, not merely unresolved in the map. That is a format-level fact
and it is what makes (a) a stepping stone rather than a destination.

Mitigations that make (a) genuinely useful in the meantime: detect overlapping
lifetimes in the map and **fail loudly** rather than guessing; and note that a
very large class of real systems — load all modules at startup, never unload —
has no overlap at all and is fully served by (a).

#### (b) The plugin observes the guest — *the target*

The plugin watches for `rtems_rtl_debugger_load` / `..._unload` being executed
and reads the object metadata out of guest memory, building the map itself,
with correct timeline information because it sees each event at the moment it
happens.

**Verified against `include/qemu/qemu-plugin.h` from QEMU 10.2.4,
`QEMU_PLUGIN_VERSION 5`.** This is the section that most needed checking, since
asserting a nonexistent API would sink the plan.

*What genuinely exists:*

```c
bool  qemu_plugin_read_memory_vaddr(uint64_t addr, GByteArray *data, size_t len);   /* :1024 */
bool  qemu_plugin_write_memory_vaddr(uint64_t addr, GByteArray *data);              /* :1045, new in v5 */
bool  qemu_plugin_translate_vaddr(uint64_t vaddr, uint64_t *hwaddr);                /* :1139, new in v5 */
int   qemu_plugin_read_register(struct qemu_plugin_register *handle, GByteArray *buf);   /* :978 */
int   qemu_plugin_write_register(struct qemu_plugin_register *handle, GByteArray *buf);  /* :1002, new in v5 */
GArray *qemu_plugin_get_registers(void);                                            /* :958 */
void  qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *insn,
          qemu_plugin_vcpu_udata_cb_t cb, enum qemu_plugin_cb_flags flags, void *ud);    /* :485 */
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *insn);               /* :594 */
```

**So yes: a plugin can read guest memory, and can get a callback on a specific
guest address.** The supported idiom is: in the `vcpu_tb_trans` callback, loop
`qemu_plugin_tb_n_insns()` / `qemu_plugin_tb_get_insn()`, compare
`qemu_plugin_insn_vaddr(insn)` against the hook's address (resolved from the
ELF symbol table offline), and register an exec callback on that one
instruction. Inside that callback, read the argument register with
`qemu_plugin_read_register` and then chase the `rtems_rtl_obj` and its section
chain with `qemu_plugin_read_memory_vaddr`.

*Constraints that are real and must be designed around:*

| Constraint | Consequence |
|---|---|
| `qemu_plugin_read_register` requires `QEMU_PLUGIN_CB_R_REGS`, and registers are unavailable in `atexit`/`flush` callbacks | fine — the read happens in the insn-exec callback |
| `qemu_plugin_get_registers()` must be called from a `vcpu_init` callback | cache the handle at init |
| **`qemu_plugin_find_register` does not exist** | must be reimplemented: walk `qemu_plugin_get_registers()` and `strcmp` the name, as `contrib/plugins/uftrace.c:466` does with a private static helper |
| Instrumentation attaches **at translation time only**, and TBs are cached | code translated before the plugin knew the target address carries no callback |
| **There is no API to force a `tb_flush`**; `qemu_plugin_register_flush_cb` (`:848`) is notification-only | the hook address must be known at `qemu_plugin_install()` time, before anything is translated — which is fine, since it comes from the static ELF's symbol table. For runtime arm/disarm, use `qemu_plugin_register_vcpu_insn_exec_cond_cb` (`:508`) with a `qemu_plugin_u64` scoreboard, which installs unconditionally and toggles cheaply |
| Insn callbacks fire **before** the instruction executes, and it may fault and never retire | irrelevant here: the hook body is empty and the object is already consistent on entry |
| `qemu_plugin_translate_vaddr` is softmmu-only and vCPU-context-only | acceptable; system emulation is the target |
| Reading the guest requires knowing struct offsets | see Open Questions — this is the real cost of (b) |

*What does not exist:* any guest→plugin communication primitive. There is no
magic-instruction hook, no hypercall entry point, no semihosting notification.
The closest is `QEMU_PLUGIN_DISCON_HOSTCALL` via
`qemu_plugin_register_vcpu_discon_cb` (`:295`), which lets a plugin **observe
but not intercept or reply to** a hypercall/semihosting trap, yielding only
`type`, `from_pc` and `to_pc`.

| | |
|---|---|
| **QEMU changes** | none — stock plugin API, v5 |
| **RTEMS changes** | the two hooks from §5 |
| **Plugin/format changes** | **yes, both.** The plugin must record module load/unload events *and* the `.cov` format must gain a module dimension, so an address can be tagged with the object generation that was live when it executed |
| **Effort** | moderate-to-large, and the struct-offset problem is the hard part |

#### (c) Guest cooperation

The guest itself emits a module-load event over a channel the plugin observes —
writing a record to a magic MMIO address the plugin watches, or filling a
known buffer and hitting a known instruction.

This inverts the offset problem: instead of the plugin knowing RTEMS's struct
layout, the *guest* serializes a stable, versioned record and the plugin just
reads it. That is a genuinely attractive property, and it also generalizes
beyond RTEMS: any OS could emit the same record.

The cost is that it is **intrusive**, which is the property the entire project
is named for. It requires target code, a target-side serializer, and a
convention about the channel. There is no QEMU API for a guest→plugin channel
(above), so it would be built by watching a memory address via
`qemu_plugin_register_vcpu_mem_cb` (`:742`) or an instruction address.

Worth keeping as a fallback for targets whose loader is not RTEMS's and whose
structures the plugin cannot reasonably parse.

### 7.3 Recommendation and staging

**Do (a) first. Aim for (b).**

The justification is not that (a) is good — it is that (a) is *decoupled*. It
requires nothing from RTEMS and nothing from QEMU, so it can ship while the
RTEMS hook patch is still in review, and it forces tcgcov to grow the parts
that (b) also needs anyway: the module-map data model, per-section address
translation, per-object `addr2line` batching, and merge behaviour for module
source lines. When (b) arrives, it replaces only the *source* of the map, not
its consumer. That is the smallest amount of work thrown away.

And (a) is not sufficient long-term for one specific reason worth restating
plainly: **a snapshot map cannot describe an address range that two objects
occupied at different times**, and the `.cov` format cannot represent the
distinction even if the map could. Any system that unloads and reloads modules
will be silently mis-attributed. That is precisely the failure mode §1 called
the worst one a coverage tool has, so (a) must fail loudly on overlap rather
than guess, and must be understood as temporary.

| Stage | Deliverable | Depends on |
|---|---|---|
| 0 | Detect and **report** out-of-ELF addresses instead of silently dropping them. A one-line warning — "1,284 covered addresses fell outside the ELF and were ignored" — removes the silent-failure problem immediately and is worth doing regardless of everything else. | nothing |
| 1 | `--module-map FILE`: module map data model, interval lookup, per-section translation, per-object `addr2line`. Coverable inventories built directly from `.o` files. Loud failure on overlapping lifetimes. | nothing |
| 2 | A target-side section-level map dumper for RTEMS (`rtl list` does not print per-section bases today), and harness glue to capture it. | RTEMS patch (small, additive) |
| 3 | The §5 hooks upstream in RTEMS, plus the GDB Python script of §6.1 — useful on its own, and it validates the hook design with a second consumer before tcgcov depends on it. | RTEMS patch |
| 4 | Plugin-side observation (b): watch the hook, read the object, emit load/unload events. | stage 3 |
| 5 | `.cov` format v3: a module table and a per-address module reference, so the timeline ambiguity becomes representable. | stage 4 |

Stages 0 and 1 are useful in isolation. Stage 3 is useful to people who do not
care about coverage at all. Nothing here requires the whole plan to land to be
worth doing, which is deliberate.

---

## 8. Open questions

These are genuinely unresolved. They are the reason this is a plan and not a
patch.

1. **How does the plugin learn RTEMS's struct offsets?** Option (b) requires
   the plugin to walk `rtems_rtl_obj` and its section chain in guest memory,
   and those offsets change with RTEMS version and build configuration.
   Candidate answers, none obviously right: parse the DWARF of the base image
   offline and hand offsets to the plugin as arguments (robust, but requires
   the base image to have DWARF and adds an offline step); emit a versioned
   `struct` layout blob from RTEMS itself (clean, but is a bigger RTEMS patch
   than the hooks); or make the hook pass a small flat descriptor instead of
   the raw `rtems_rtl_obj*`, which collapses this question entirely but makes
   the hook signature less useful to GDB. **The last option may be the right
   answer and it conflicts with §5.1 as written.** Unresolved.

2. **Does `.cov` v3 tag every address, or record generations?** Tagging each
   address with a module id is simple but inflates the file and breaks the
   "size tracks unique code covered" property. Recording load/unload *events*
   with a monotonic generation counter, and tagging addresses with a
   generation, is smaller but requires the dedup logic to become
   generation-aware. Unmeasured either way.

3. **What is the actual frequency of address reuse in practice?** The whole
   argument for (b) over (a) rests on it happening. RTL's allocator behaviour
   under load/unload cycles has not been measured. If reuse turns out to be
   rare and detectable, (a) plus loud failure might serve for a long time.

4. **How should a module's coverage merge with the same source built
   statically?** By `(source, line)` the two are identical, which is arguably
   correct — the same line was tested — and arguably misleading, since the
   relocated and the statically-linked instances are different machine code
   with different failure modes. Should the module map contribute a distinct
   report dimension? LCOV has no natural place to put it.

5. **Linux shared libraries: worth supporting, and by which route?** The
   `ET_DYN` case is *easier* (one `l_addr`) and there is a working SVR4
   rendezvous to read. But under QEMU **user-mode** emulation, and under system
   emulation with a full Linux guest, the useful mechanisms differ, and the
   plugin's view of a multi-process guest raises attribution questions this
   document has not touched at all. Possibly a separate design.

6. **Does the RTEMS project want the hooks, or a real `r_debug`?** §3.2 shows
   the existing handshake is inert. A maintainer could reasonably prefer fixing
   `struct r_debug` to be SVR4-compatible over adding two new symbols. That
   fix would help GDB but **still cannot express a per-section map** (§4), so
   the honest answer is probably "both" — which is a larger patch and a longer
   review. Unverified: no RFC has been posted, and no maintainer has been
   asked.

7. **Trampolines.** `obj->tramp_base` / `tramp_size` is a separate allocation
   holding generated veneers with no source line at all. Should addresses
   landing there be dropped, attributed to the branching call site, or reported
   as a distinct category? Currently unconsidered.

8. **Overlays and XIP.** Some targets place module text in memory that is
   itself banked or executed in place from flash. Whether the map's
   `(base, size)` interval model survives that has not been thought about.

---

## References

| | |
|---|---|
| SVR4 dynamic-linking rendezvous | System V gABI, `struct r_debug` / `struct link_map`; glibc `elf/link.h` |
| GDB's consumer | `gdb/solib-svr4.c` — `svr4_solib_create_inferior_hook`, `enable_break`, `svr4_current_sos` |
| GDB commands | `add-symbol-file … -s SECT ADDR`, `remove-symbol-file -a ADDR`, `gdb.Breakpoint.stop()` in the GDB Python API |
| RTEMS RTL | `cpukit/libdl/` — `rtl.c`, `rtl-obj.c`, `rtl-elf.c`, `rtl-debugger.c`, `rtl-shell.c`, `dlfcn.c`; headers `cpukit/include/rtems/rtl/`; `struct link_map` / `struct r_debug` in `cpukit/contrib/include/link_elf.h`. Verified at `81df76877f` (`build/2026-03-04-155-g81df76877f`). |
| RTEMS debug stub | `cpukit/libdebugger/` — verified to have no libdl awareness |
| QEMU plugin API | `include/qemu/qemu-plugin.h`, QEMU 10.2.4, `QEMU_PLUGIN_VERSION 5`; register-lookup idiom in `contrib/plugins/uftrace.c` |
| tcgcov's static pipeline | [`../README.md`](../README.md), [`FORMAT.md`](FORMAT.md) |
