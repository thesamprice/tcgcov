/*
 * tcgcov internal state, shared between the generic core (tcgcov.c) and
 * the guest-OS-specific modules (tcgcov-rtems.c). Nothing here is public
 * API: the only external contract is the plugin's argument list and the
 * artifact format (docs/FORMAT.md).
 *
 * License: GNU GPL, version 2 or later.
 */
#ifndef TCGCOV_INTERNAL_H
#define TCGCOV_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glib.h>

#include <qemu-plugin.h>

/*
 * Feature gate for discontinuity callbacks (interrupt/exception notification),
 * which let the plugin invalidate a pending edge source when an asynchronous
 * event steals control between two translation blocks.
 *
 * This CANNOT be gated on QEMU_PLUGIN_VERSION. The API was added part-way
 * through version 5 without a version bump: QEMU v10.1.0 declares
 * QEMU_PLUGIN_VERSION 5 and has no qemu_plugin_register_vcpu_discon_cb, while
 * later version-5 headers do. Gating on the macro therefore breaks the build
 * against any v10.1.0-era header.
 *
 * The Makefile probes the actual header and passes -DTCGCOV_HAVE_DISCON=0/1.
 * When it is built some other way the default is 0 -- losing a refinement is
 * acceptable, failing to compile is not.
 */
#ifndef TCGCOV_HAVE_DISCON
#define TCGCOV_HAVE_DISCON 0
#endif

/*
 * Context-visibility API (qemu_plugin_vcpu_ctx_id and the ctx-changed
 * callback): a proposed QEMU addition, present only in trees carrying the
 * tcgcov context patches (see docs/QEMU-RFC-context.md). Probed by the
 * Makefile the same way as the discon callbacks; ctx=on is refused at
 * install time when this is 0, because per-context coverage without the
 * API would silently attribute everything to one context.
 */
#ifndef TCGCOV_HAVE_CTX
#define TCGCOV_HAVE_CTX 0
#endif

/*
 * qemu_plugin_translate_vaddr (upstream since part-way through plugin API
 * version 5): a debug MMU walk from vCPU context, which translation-time
 * callbacks are. phys=on rests on it entirely -- no QEMU modification is
 * involved -- and is refused at install when the build lacked it.
 */
#ifndef TCGCOV_HAVE_XLATE
#define TCGCOV_HAVE_XLATE 0
#endif

/*
 * qemu_plugin_read_memory_vaddr (upstream since plugin API v4): the RTEMS
 * loader-generation mode (rtl_state=/rtl_debug=) reads the run-time
 * loader's r_debug and link_map chain out of guest memory with it.
 */
#ifndef TCGCOV_HAVE_RDMEM
#define TCGCOV_HAVE_RDMEM 0
#endif

typedef enum {
    TCGCOV_MODE_TB = 0,            /* mode=tb           - TB starts only */
    TCGCOV_MODE_TB_INSN,           /* mode=tb-insn      - exact, per insn */
    TCGCOV_MODE_TB_INSN_FAST,      /* mode=tb-insn-fast - TB cb, approximate */
} CovMode;

#define TCGCOV_CACHELINE 64

/*
 * Per-vCPU edge-tracking state.
 *
 * Every field is written *only* by the vCPU thread whose cpu_index selects the
 * slot, and read by anyone else only from plugin_exit, when all vCPUs are
 * quiescent. That is what makes the execution fast path lock-free and
 * atomic-free: there is no cross-thread access to synchronise.
 *
 * prev_valid is false when there is no usable predecessor, which covers three
 * cases that all mean "emit nothing": (a) this is the first TB executed on the
 * vCPU, (b) the previous TB never reached its last instruction (it aborted, or
 * that instruction fell outside every filter range), and (c) the pending source
 * was invalidated by an interrupt or exception (API >= 5 only).
 *
 * The slot is padded and the array is cache-line aligned so that two vCPUs
 * updating adjacent slots do not ping-pong a shared line between cores.
 */
typedef struct {
    uint64_t prev_src;
    GHashTable *edges;         /* CtxEdge* -> same, keyed on (ctx,src,dst) */
    /*
     * ctx=on state. cur_ctx is written by the ctx-changed callback and read
     * by the execution callbacks - both run on this vCPU's thread, so the
     * slot ownership rule covers them. It stays 0 with ctx off, which is
     * what lets record_edge() use it unconditionally.
     */
    uint64_t cur_ctx;
    GHashTable *ctx_tbs;       /* CtxTbCount* -> same, keyed on (ctx,tb) */
    bool prev_valid;
    char pad[TCGCOV_CACHELINE - 2 * sizeof(uint64_t) - 2 * sizeof(void *)
             - sizeof(bool)];
} VcpuState;

G_STATIC_ASSERT(sizeof(VcpuState) == TCGCOV_CACHELINE);

/*
 * Slot count used when the vCPU count cannot be queried, i.e. under user-mode
 * emulation, where each guest thread is a vCPU. Sized generously because the
 * table is allocated exactly once and never grown: 1024 slots is 64 KiB, which
 * is noise next to a QEMU process, and going out of bounds only costs edges
 * (never memory safety - see vcpu_slot()).
 */
#define TCGCOV_VCPU_FALLBACK 1024

typedef struct {
    uint64_t start;
    uint64_t end;                  /* exclusive */
} Range;

typedef struct InsnSlab InsnSlab;

typedef struct {
    /*
     * Guards translation-time bookkeeping only: `blocks`, `insn_slabs`.
     * Nothing on the execution fast path takes it.
     */
    GMutex lock;
    GPtrArray *blocks;             /* of CovTb* */
    InsnSlab *insn_slabs;          /* bump allocator for CovInsn */

    char *out_path;
    char *test_id;
    char *bsp;
    char *elf_path;
    char *target_name;
    bool system_emulation;

    CovMode mode;
    bool edges;                    /* edges=off disables the edge section */
    bool ctx;                      /* ctx=on records per-context (TCGCOV2) */
    bool phys;                     /* phys=on records physical addresses */
    bool verbose;

    /*
     * phys=on: translations that failed the debug MMU walk and fell back to
     * recording the virtual address. Incremented under `lock` (translation
     * time only) and reported in the metadata, because an artifact silently
     * mixing address kinds would be worse than one that says it did.
     */
    uint64_t phys_fail;

    /*
     * ctx=on bookkeeping, updated from the (rare) ctx-changed callback.
     * ctx_entries maps context ID -> times switched into, guarded by `lock`
     * because several vCPUs can switch concurrently; ctx_switches is a
     * relaxed atomic counter.
     */
    GHashTable *ctx_entries;       /* uint64* key -> uint64 count in value */
    uint64_t ctx_switches;

    /*
     * RTEMS loader-generation mode (rtl_state= + rtl_debug=): watch the
     * run-time loader's _rtld_debug_state() notification and tag records
     * with a generation that bumps on every completed load/unload, so the
     * same address occupied by two objects at different times stays two
     * records. Uses the same per-record tag as ctx=on ("ctx_kind" in the
     * metadata says which semantics apply); needs no QEMU context API.
     */
    bool rtl;
    uint64_t rtl_state_addr;       /* &_rtld_debug_state, from the base ELF */
    uint64_t rtl_debug_addr;       /* &_rtld_debug */
    uint64_t rtl_generation;       /* current generation, starts at 0 */
    uint64_t rtl_events;           /* notification hits observed */
    GString *rtl_snaps;            /* metadata JSON fragments, under lock */

    /*
     * Per-vCPU edge state, indexed by cpu_index. Allocated once at install
     * from a fixed cap so that it is never reallocated - a reader can therefore
     * never race a g_realloc() that frees the base pointer under it, and no
     * lock is needed to reach a slot. `vcpu_raw` is the malloc'd block;
     * `vcpu` is the cache-line aligned view into it.
     */
    void *vcpu_raw;
    VcpuState *vcpu;
    size_t vcpu_cap;

    Range *ranges;
    size_t range_count;
} CovState;



extern CovState g_state;

/* tcgcov.c */
VcpuState *vcpu_slot(CovState *s, unsigned int cpu_index);
void json_escape_append(GString *out, const char *s);

/*
 * tcgcov-rtems.c: the RTEMS loader-generation mode. watch_tb registers the
 * notification callback when the TB contains the watched address; it is a
 * no-op stub when the QEMU headers lack guest-memory reads.
 */
void tcgcov_rtems_watch_tb(CovState *s, struct qemu_plugin_tb *tb, size_t n);

/*
 * tcgcov-linux.c: the MMU/ASID context mode (ctx=on). register_ subscribes
 * to the QEMU context-visibility callback; vcpu_init seeds a vcpu's tag.
 * Both are no-op stubs when the QEMU headers lack the context API.
 */
void tcgcov_linux_register(qemu_plugin_id_t id);
void tcgcov_linux_vcpu_init(CovState *s, unsigned int cpu_index);

#endif /* TCGCOV_INTERNAL_H */
