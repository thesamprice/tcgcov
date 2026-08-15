/*
 * tcgcov - non-intrusive translation-block coverage for QEMU TCG.
 *
 * Observes executed guest code, deduplicates covered guest code addresses in
 * memory, and writes one compact "TCGCOV1" binary artifact at QEMU exit.
 * Symbolization (addr2line/LCOV) is done offline by a host tool.
 *
 * Every address record carries an execution count. That is not an option: it
 * used to be `counts=1`, but maintaining the count unconditionally SUBSUMES the
 * separate "was this executed" flag - `count != 0` IS executed - so removing
 * the option removed a field and two branches from the per-instruction hot
 * path rather than adding work to it. `counts=` is now rejected outright.
 *
 * It also records the directed control-flow edges taken between translation
 * blocks, so that branch coverage can be computed offline. That one IS still an
 * option (`edges=off`) because it cannot be folded away the same manner: it
 * costs an extra per-TB callback and a hash-table insert per block execution,
 * which a long-running system run may reasonably decline. It defaults to on.
 *
 * Fidelity of the address records depends on the mode:
 *
 *   mode=tb            one record per executed TB *start* address. Reaching
 *                      the TB proves its first instruction was reached, so the
 *                      record is exact for what it claims.
 *   mode=tb-insn       (default) one record per *individually observed*
 *                      instruction. A per-instruction execution callback is
 *                      registered on every in-range instruction, so an
 *                      instruction after an abort point (exception, interrupt,
 *                      MMIO write that stops the machine) is never reported.
 *   mode=tb-insn-fast  one TB-level callback expands to every instruction the
 *                      TB was translated with. Cheap, but it OVER-REPORTS: a
 *                      block that aborts part way through still reports all of
 *                      its instructions as covered.
 *
 * The QEMU translation callback carries no userdata, so plugin state lives in a
 * single global object. Retranslated TBs simply produce duplicate per-TB or
 * per-instruction records; that is harmless because addresses are sorted and
 * de-duplicated (counts summed) at exit.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

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

/* ------------------------------------------------------------------ */
/* Raw file format (TCGCOV1).                                          */
/* ------------------------------------------------------------------ */

#define TCGCOV_MAGIC "TCGCOV1\0"   /* 8 bytes including the NUL */

enum {
    TCGCOV_REC_TB_ADDR   = 1,      /* records are TB start addresses */
    TCGCOV_REC_INSN_ADDR = 2,      /* records are instruction addresses */
};

/* Header flags. */
enum {
    /*
     * When set, each *address* record is a 16-byte { uint64 addr;
     * uint64 count; } pair (execution count) instead of a bare 8-byte
     * address. record_type still indicates the address granularity
     * (TB vs instruction).
     */
    TCGCOV_FLAG_HAS_COUNTS  = 0x1,
    /*
     * When set, an edge section follows the address records: edge_count
     * records at edges_offset describing the directed control-flow edges
     * observed between translation blocks.
     */
    TCGCOV_FLAG_HAS_EDGES   = 0x2,
    /*
     * When set, each edge record is 24 bytes { uint64 src; uint64 dst;
     * uint64 count; } instead of 16 bytes { uint64 src; uint64 dst; }.
     * Only meaningful together with TCGCOV_FLAG_HAS_EDGES.
     */
    TCGCOV_FLAG_EDGE_COUNTS = 0x4,
    /*
     * Version 2 only: every address record is prefixed with a uint64 ctx
     * (address-space context ID) and every edge record likewise; records
     * sort by (ctx, addr), edges by (ctx, src, dst). Never set in a
     * version-1 file, whose reader would mis-stride the sections.
     */
    TCGCOV_FLAG_HAS_CTX     = 0x8,
};

/* All multi-byte header fields are little-endian on disk. */
typedef struct tcgcov_header {
    char     magic[8];             /* "TCGCOV1\0" */
    uint16_t version;              /* 1 */
    uint16_t endian;               /* 1 = little, 2 = big */
    uint32_t header_size;          /* 88 */
    uint32_t record_type;          /* 1 = TB_ADDR, 2 = INSN_ADDR */
    uint32_t flags;                /* bit0 HAS_COUNTS, bit1 HAS_EDGES,
                                      bit2 EDGE_COUNTS */
    uint64_t record_count;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t records_offset;
    uint64_t records_size;
    uint64_t edge_count;
    uint64_t edges_offset;
    uint64_t edges_size;
} tcgcov_header;

/*
 * The on-disk header is the wire contract with the offline reader; it must be
 * exactly 88 bytes with no interior or trailing padding. Every field is
 * naturally aligned at its declared offset on any LP64 ABI, so no packing
 * attribute is needed - but assert it so a hostile ABI fails the build rather
 * than silently emitting an unreadable file.
 */
G_STATIC_ASSERT(sizeof(tcgcov_header) == 88);

/*
 * The total size only proves the struct as a whole is 88 bytes; it would still
 * hold if a field moved and the padding moved with it. The reader addresses
 * every field by a hardcoded offset (FORMAT.md section 2), so pin the interior
 * layout too.
 */
G_STATIC_ASSERT(offsetof(tcgcov_header, magic)           ==  0);
G_STATIC_ASSERT(offsetof(tcgcov_header, version)         ==  8);
G_STATIC_ASSERT(offsetof(tcgcov_header, endian)          == 10);
G_STATIC_ASSERT(offsetof(tcgcov_header, header_size)     == 12);
G_STATIC_ASSERT(offsetof(tcgcov_header, record_type)     == 16);
G_STATIC_ASSERT(offsetof(tcgcov_header, flags)           == 20);
G_STATIC_ASSERT(offsetof(tcgcov_header, record_count)    == 24);
G_STATIC_ASSERT(offsetof(tcgcov_header, metadata_offset) == 32);
G_STATIC_ASSERT(offsetof(tcgcov_header, metadata_size)   == 40);
G_STATIC_ASSERT(offsetof(tcgcov_header, records_offset)  == 48);
G_STATIC_ASSERT(offsetof(tcgcov_header, records_size)    == 56);
G_STATIC_ASSERT(offsetof(tcgcov_header, edge_count)      == 64);
G_STATIC_ASSERT(offsetof(tcgcov_header, edges_offset)    == 72);
G_STATIC_ASSERT(offsetof(tcgcov_header, edges_size)      == 80);

/* ------------------------------------------------------------------ */
/* Internal data structures.                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    TCGCOV_MODE_TB = 0,            /* mode=tb           - TB starts only */
    TCGCOV_MODE_TB_INSN,           /* mode=tb-insn      - exact, per insn */
    TCGCOV_MODE_TB_INSN_FAST,      /* mode=tb-insn-fast - TB cb, approximate */
} CovMode;

typedef struct {
    uint64_t *items;
    size_t count;
    size_t cap;
} U64Vec;

/*
 * Per-translation-block state. Allocated at translation time whenever a
 * TB-level callback is needed, i.e. for mode=tb / mode=tb-insn-fast (where the
 * TB callback is what records coverage) and for edges=on in any mode (where it
 * is what records the incoming edge).
 *
 * `count` is only meaningful in the two TB-level modes; in mode=tb-insn the
 * address records come from CovInsn instead and this stays zero. A non-zero
 * count is also the "this block executed" predicate - there is no separate
 * flag, because a maintained count already answers that question.
 */
typedef struct {
    uint64_t tb_vaddr;
    U64Vec insns;                  /* in-range insn vaddrs (tb-insn-fast) */
    uint64_t count;                /* execution count, 64-bit */

    /*
     * Edge support: the vaddr of the LAST instruction of this TB. Using the
     * last instruction rather than the TB start as the edge source is
     * deliberate - on delay-slot architectures (MicroBlaze, SPARC, MIPS) the
     * branch is followed by a delay-slot instruction before control actually
     * transfers, and the last instruction is the one an offline tool can
     * attribute the branch to. It is computed at translation time so the
     * execution fast path never has to walk the filter ranges.
     */
    uint64_t last_insn_vaddr;
} CovTb;

/*
 * Per-instruction state for the exact mode. One of these exists for every
 * in-range instruction of every translation, and its address is the userdata of
 * that instruction's execution callback - so it must never move. They are
 * therefore bump-allocated out of slabs rather than held in a growable array.
 */
typedef struct {
    uint64_t vaddr;
    uint64_t count;                /* execution count; non-zero == executed */
} CovInsn;

#define TCGCOV_INSN_SLAB_ITEMS 1024

typedef struct InsnSlab {
    struct InsnSlab *next;
    size_t used;
    CovInsn items[TCGCOV_INSN_SLAB_ITEMS];
} InsnSlab;

/*
 * { address, execution count } address record. This struct IS the on-disk
 * record, and its size is what records_size is computed from, so it carries the
 * same size assertion as the other on-disk structs. The format also defines an
 * 8-byte count-less form (HAS_COUNTS clear); this producer never emits it, but
 * a reader must still accept it.
 */
typedef struct {
    uint64_t addr;
    uint64_t count;
} AddrCount;

G_STATIC_ASSERT(sizeof(AddrCount) == 16);
G_STATIC_ASSERT(offsetof(AddrCount, count) == 8);

/*
 * A directed control-flow edge, written to disk in this field order. The struct
 * is three uint64_t with no padding on any supported ABI, so it can be written
 * directly. The format also defines a 16-byte count-less form (EDGE_COUNTS
 * clear); this producer never emits it, but a reader must still accept it.
 */
typedef struct {
    uint64_t src;                  /* last insn vaddr of the source TB */
    uint64_t dst;                  /* start vaddr of the destination TB */
    uint64_t count;                /* traversals */
} Edge;

G_STATIC_ASSERT(sizeof(Edge) == 24);

/*
 * Context-bearing forms of the two record types, written to disk in this
 * field order when ctx=on (TCGCOV2, TCGCOV_FLAG_HAS_CTX). CtxEdge doubles
 * as the plugin's internal edge representation in every mode: with ctx off
 * the ctx field is always 0 and the v1 writer emits the {src, dst, count}
 * tail only, which the layout below makes contiguous by construction.
 */
typedef struct {
    uint64_t ctx;                  /* address-space context ID */
    uint64_t addr;
    uint64_t count;
} CtxAddrCount;

G_STATIC_ASSERT(sizeof(CtxAddrCount) == 24);
G_STATIC_ASSERT(offsetof(CtxAddrCount, addr) == 8);

typedef struct {
    uint64_t ctx;                  /* address-space context ID */
    uint64_t src;
    uint64_t dst;
    uint64_t count;
} CtxEdge;

G_STATIC_ASSERT(sizeof(CtxEdge) == 32);
G_STATIC_ASSERT(offsetof(CtxEdge, src) == 8);

/*
 * Per-(context, block) execution count for ctx=on, accumulated in a per-vCPU
 * hash table (same ownership discipline as the per-vCPU edge tables: only
 * the owning vCPU thread touches it, plugin_exit reads it quiescent). The
 * CovTb pointer rather than the address is the key so that tb-insn-fast can
 * expand the block's instruction list at collection time.
 */
typedef struct {
    uint64_t ctx;
    const CovTb *tb;
    uint64_t count;
} CtxTbCount;

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

static CovState g_state;

/* One-shot latch for the "cpu_index out of range" diagnostic. */
static gint g_vcpu_overflow_warned;

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

static const char *mode_name(CovMode m)
{
    switch (m) {
    case TCGCOV_MODE_TB:
        return "tb";
    case TCGCOV_MODE_TB_INSN:
        return "tb-insn";
    case TCGCOV_MODE_TB_INSN_FAST:
        return "tb-insn-fast";
    default:
        return "unknown";
    }
}

/*
 * What the address records actually promise. "exact" means every emitted
 * address provably reached the CPU; "tb-approx" means addresses were inferred
 * from block entry and a block that aborted part way through contributes
 * instructions that never ran.
 */
static const char *fidelity_name(CovMode m)
{
    return m == TCGCOV_MODE_TB_INSN_FAST ? "tb-approx" : "exact";
}

static bool mode_is_insn_granular(CovMode m)
{
    return m != TCGCOV_MODE_TB;
}

static void u64vec_push(U64Vec *v, uint64_t x)
{
    if (v->count == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->items = g_realloc(v->items, v->cap * sizeof(uint64_t));
    }
    v->items[v->count++] = x;
}

static bool range_contains(CovState *s, uint64_t addr)
{
    if (s->range_count == 0) {
        return true;
    }
    for (size_t i = 0; i < s->range_count; i++) {
        if (addr >= s->ranges[i].start && addr < s->ranges[i].end) {
            return true;
        }
    }
    return false;
}

static gint addrcount_compare(gconstpointer a, gconstpointer b)
{
    uint64_t av = ((const AddrCount *)a)->addr;
    uint64_t bv = ((const AddrCount *)b)->addr;
    return (av > bv) - (av < bv);
}

/* Sort ctx address records ascending by (ctx, addr), per the v2 format. */
static gint ctxaddr_compare(gconstpointer a, gconstpointer b)
{
    const CtxAddrCount *ca = a;
    const CtxAddrCount *cb = b;

    if (ca->ctx != cb->ctx) {
        return (ca->ctx > cb->ctx) - (ca->ctx < cb->ctx);
    }
    return (ca->addr > cb->addr) - (ca->addr < cb->addr);
}

/*
 * Sort edges ascending by (ctx, src, dst), as the file format requires.
 * With ctx off every ctx is 0 and this degenerates to the v1 (src, dst)
 * order.
 */
static gint edge_compare(gconstpointer a, gconstpointer b)
{
    const CtxEdge *ea = a;
    const CtxEdge *eb = b;

    if (ea->ctx != eb->ctx) {
        return (ea->ctx > eb->ctx) - (ea->ctx < eb->ctx);
    }
    if (ea->src != eb->src) {
        return (ea->src > eb->src) - (ea->src < eb->src);
    }
    return (ea->dst > eb->dst) - (ea->dst < eb->dst);
}

static guint edge_hash(gconstpointer p)
{
    const CtxEdge *e = p;
    uint64_t h = e->src * 0x9E3779B97F4A7C15ULL;

    h ^= e->dst + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    h ^= e->ctx + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    return (guint)(h ^ (h >> 32));
}

static gboolean edge_equal(gconstpointer a, gconstpointer b)
{
    const CtxEdge *ea = a;
    const CtxEdge *eb = b;

    return ea->ctx == eb->ctx && ea->src == eb->src && ea->dst == eb->dst;
}

static guint ctxtb_hash(gconstpointer p)
{
    const CtxTbCount *c = p;
    uint64_t h = (uint64_t)(uintptr_t)c->tb * 0x9E3779B97F4A7C15ULL;

    h ^= c->ctx + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    return (guint)(h ^ (h >> 32));
}

static gboolean ctxtb_equal(gconstpointer a, gconstpointer b)
{
    const CtxTbCount *ca = a;
    const CtxTbCount *cb = b;

    return ca->ctx == cb->ctx && ca->tb == cb->tb;
}

/*
 * Resolve a vCPU's slot. The table is fixed-size, so an unexpectedly large
 * cpu_index (hot-plug beyond max_vcpus, or a user-mode guest with more live
 * threads than the fallback cap) must degrade rather than scribble past the
 * end. Returns NULL in that case; the caller then simply records no edge.
 */
static VcpuState *vcpu_slot(CovState *s, unsigned int cpu_index)
{
    if (G_UNLIKELY(cpu_index >= s->vcpu_cap)) {
        if (g_atomic_int_compare_and_exchange(&g_vcpu_overflow_warned, 0, 1)) {
            g_printerr("tcgcov: cpu_index %u is outside the %zu-slot per-vCPU "
                       "edge table; edges for this vCPU are dropped\n",
                       cpu_index, s->vcpu_cap);
        }
        return NULL;
    }
    return &s->vcpu[cpu_index];
}

/* Bump-allocate a CovInsn with a stable address. Call with s->lock held. */
static CovInsn *insn_alloc(CovState *s, uint64_t vaddr)
{
    InsnSlab *slab = s->insn_slabs;
    CovInsn *ci;

    if (slab == NULL || slab->used == TCGCOV_INSN_SLAB_ITEMS) {
        slab = g_new0(InsnSlab, 1);
        slab->next = s->insn_slabs;
        s->insn_slabs = slab;
    }
    ci = &slab->items[slab->used++];
    ci->vaddr = vaddr;
    return ci;
}

/*
 * Portability note for the 64-bit atomics below (`count` fields, incremented
 * with __atomic_fetch_add on a uint64_t).
 *
 * On a 32-bit host there is no native 64-bit read-modify-write, so the
 * compiler may emit a call to __atomic_fetch_add_8 in libatomic instead of an
 * inline instruction sequence. This file is built as a standalone shared
 * object by plugin/Makefile, which does not link -latomic, so such a build
 * would fail to link (or, worse, load with an unresolved symbol). It has not
 * been addressed here because it cannot be fixed inside this file: the
 * remedies are a link flag (-latomic) or dropping to a 32-bit-safe counter
 * type, and both belong to the build/format contract rather than the source.
 *
 * This used to apply only to counts=1 runs, because coverage itself was a
 * separate `unsigned int` flag that is lock-free everywhere. The count is now
 * the only coverage state there is, so a 32-bit host has to solve this to get
 * any coverage at all rather than merely losing hit counts.
 *
 * The increments are RELAXED. Nothing orders them against other memory: each
 * counter is read exactly once, from plugin_exit, after every vCPU has stopped,
 * so the only property required is that concurrent increments do not lose each
 * other. Relaxed atomic read-modify-write gives exactly that and no barrier.
 */

/* ------------------------------------------------------------------ */
/* TCG callbacks.                                                     */
/* ------------------------------------------------------------------ */

/*
 * Record the edge (pending source on this vCPU -> this TB's start), then
 * consume the pending source.
 *
 * Consuming it is what keeps edges honest. The source is published by a
 * callback on the *last* instruction of the predecessor block (see
 * vcpu_last_insn_exec), so it exists only if that block really ran to its end.
 * Clearing it here means that if this block aborts part way through - taking an
 * exception into a handler, say - the handler's entry does not get attributed
 * to a branch that was never reached.
 *
 * Both endpoints already satisfy the filter: dst is a TB start, and TBs whose
 * start is out of range are never instrumented at all; src was range-checked at
 * translation time. Note the consequence of that filtering - if execution
 * passes through an un-instrumented (out-of-range) TB, the next recorded edge
 * jumps over it rather than being split in two. That is inherent to filtering
 * and is the same trade-off the address records already make.
 *
 * No lock and no atomics: only this vCPU's thread touches this slot.
 */
static void record_edge(CovState *s, unsigned int cpu_index, uint64_t dst)
{
    VcpuState *v = vcpu_slot(s, cpu_index);
    CtxEdge key;
    CtxEdge *e;

    if (G_UNLIKELY(v == NULL) || !v->prev_valid) {
        return;
    }
    v->prev_valid = false;

    /* cur_ctx is 0 with ctx off, so no mode branch is needed here. */
    key.ctx = v->cur_ctx;
    key.src = v->prev_src;
    key.dst = dst;
    key.count = 0;

    if (G_UNLIKELY(v->edges == NULL)) {
        /*
         * Created on first use rather than for all vcpu_cap slots up front:
         * most runs use one or two vCPUs out of a large cap.
         */
        v->edges = g_hash_table_new_full(edge_hash, edge_equal, g_free, NULL);
    }

    e = g_hash_table_lookup(v->edges, &key);
    if (!e) {
        e = g_new0(CtxEdge, 1);
        e->ctx = key.ctx;
        e->src = key.src;
        e->dst = key.dst;
        g_hash_table_insert(v->edges, e, e);
    }
    e->count++;
}

/*
 * TB-entry callback for the TB-level address modes (tb, tb-insn-fast).
 * Reaching this point proves the TB's first instruction was reached; in
 * tb-insn-fast it is also taken as proof for every instruction of the block,
 * which is the documented approximation.
 */
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    CovTb *ctb = (CovTb *)udata;

    /* 64-bit atomic add (GLib has no portable g_atomic_int64_add). */
    __atomic_fetch_add(&ctb->count, 1, __ATOMIC_RELAXED);

    if (g_state.edges) {
        record_edge(&g_state, cpu_index, ctb->tb_vaddr);
    }
}

/*
 * TB-entry callback for the TB-level address modes when ctx=on: the count
 * lives in a per-(context, block) record in this vCPU's table instead of in
 * the CovTb, so the same block executed by two processes stays two records.
 * One hash lookup per block execution instead of one atomic add - that is
 * the documented cost of ctx mode, and it is per-vCPU state, so the fast
 * path stays lock-free and atomic-free.
 */
static void vcpu_tb_exec_ctx(unsigned int cpu_index, void *udata)
{
    CovTb *ctb = (CovTb *)udata;
    CovState *s = &g_state;
    VcpuState *v = vcpu_slot(s, cpu_index);
    CtxTbCount key;
    CtxTbCount *e;

    if (G_UNLIKELY(v == NULL)) {
        return;
    }
    if (G_UNLIKELY(v->ctx_tbs == NULL)) {
        v->ctx_tbs = g_hash_table_new_full(ctxtb_hash, ctxtb_equal,
                                           g_free, NULL);
    }

    key.ctx = v->cur_ctx;
    key.tb = ctb;
    e = g_hash_table_lookup(v->ctx_tbs, &key);
    if (!e) {
        e = g_new0(CtxTbCount, 1);
        e->ctx = key.ctx;
        e->tb = ctb;
        g_hash_table_insert(v->ctx_tbs, e, e);
    }
    e->count++;

    if (s->edges) {
        record_edge(s, cpu_index, ctb->tb_vaddr);
    }
}

/*
 * TB-entry callback for mode=tb-insn with edges on: coverage is recorded by the
 * per-instruction callbacks, so all this does is close out the incoming edge.
 */
static void vcpu_tb_edge_entry(unsigned int cpu_index, void *udata)
{
    CovTb *ctb = (CovTb *)udata;

    record_edge(&g_state, cpu_index, ctb->tb_vaddr);
}

/*
 * Per-instruction execution callback (mode=tb-insn). QEMU emits this
 * immediately before the instruction's own translated code, so it fires if and
 * only if the CPU reached this instruction - which is exactly the coverage
 * question being asked.
 *
 * This is the hottest code in the plugin - it runs once per in-range guest
 * instruction - and it is deliberately one relaxed atomic increment with no
 * load of plugin state, no branch and no separate coverage flag to maintain.
 */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    CovInsn *ci = (CovInsn *)udata;

    (void)cpu_index;

    __atomic_fetch_add(&ci->count, 1, __ATOMIC_RELAXED);
}

/*
 * Publish this TB's last instruction as the pending edge source, but only once
 * that instruction has actually been reached. Registered on the last
 * instruction of every instrumented TB when edges are on - one extra callback
 * per TB, in every mode, not one per instruction.
 *
 * Ordering within a TB is: TB-entry callback (consumes the predecessor's
 * pending source and emits the edge), then the block's instructions, then this.
 * A single-instruction TB is the same sequence with one instruction in the
 * middle: entry consumes, this publishes, and the two never collide because the
 * entry callback of the *next* TB is what consumes what this publishes.
 */
static void vcpu_last_insn_exec(unsigned int cpu_index, void *udata)
{
    CovTb *ctb = (CovTb *)udata;
    VcpuState *v = vcpu_slot(&g_state, cpu_index);

    if (G_LIKELY(v != NULL)) {
        v->prev_src = ctb->last_insn_vaddr;
        v->prev_valid = true;
    }
}

#if TCGCOV_HAVE_DISCON
/*
 * Interrupt/exception notification (plugin API >= 5). Fires after the PC has
 * been redirected to the handler.
 *
 * This closes the one window the last-instruction callback cannot: an
 * asynchronous event taken *between* two translation blocks, after the
 * predecessor published its pending source. Without this, the handler's first
 * block would be recorded as the branch target of an instruction that never
 * branched there.
 *
 * HOSTCALL is deliberately not subscribed: a semihosting call returns to the
 * following instruction, so the block sequencing across it is genuine.
 */
static void vcpu_discon(qemu_plugin_id_t id, unsigned int cpu_index,
                        enum qemu_plugin_discon_type type,
                        uint64_t from_pc, uint64_t to_pc)
{
    VcpuState *v = vcpu_slot(&g_state, cpu_index);

    (void)id;
    (void)type;
    (void)from_pc;
    (void)to_pc;

    if (G_LIKELY(v != NULL)) {
        v->prev_valid = false;
    }
}
#endif

#if TCGCOV_HAVE_CTX
/*
 * Count a switch into `ctx` in the metadata table. Rare (context-switch
 * rate, not execution rate), so a mutex is fine; several vCPUs can switch
 * concurrently and the table is shared.
 */
static void ctx_note_entry(CovState *s, uint64_t ctx)
{
    uint64_t *entry;

    g_mutex_lock(&s->lock);
    if (G_UNLIKELY(s->ctx_entries == NULL)) {
        s->ctx_entries = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                               NULL, g_free);
    }
    /* entry[0] is the ctx (and the key storage), entry[1] the tally. */
    entry = g_hash_table_lookup(s->ctx_entries, &ctx);
    if (entry == NULL) {
        entry = g_new0(uint64_t, 2);
        entry[0] = ctx;
        g_hash_table_insert(s->ctx_entries, entry, entry);
    }
    entry[1]++;
    g_mutex_unlock(&s->lock);
}

/*
 * The guest switched address spaces on this vCPU. Runs on the vCPU's own
 * thread (QEMU delivers it from the MMU write in translated code), so
 * writing the slot needs no synchronisation. The pending edge source is
 * invalidated: an edge from the old process's block to the new process's
 * block is not a control-flow fact about either program.
 */
static void vcpu_ctx_changed(qemu_plugin_id_t id, unsigned int cpu_index,
                             uint64_t ctx_id)
{
    CovState *s = &g_state;
    VcpuState *v = vcpu_slot(s, cpu_index);

    (void)id;

    if (G_LIKELY(v != NULL)) {
        v->cur_ctx = ctx_id;
        v->prev_valid = false;
    }
    __atomic_fetch_add(&s->ctx_switches, 1, __ATOMIC_RELAXED);
    ctx_note_entry(s, ctx_id);
}
#endif /* TCGCOV_HAVE_CTX */

/*
 * vCPU initialization. Surfaces an undersized slot table at startup - when
 * the guest brings the vCPU online - instead of silently at the first edge
 * that vCPU would have recorded, and with ctx=on seeds the slot's current
 * context so records before the first switch are attributed correctly.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int cpu_index)
{
    VcpuState *v = vcpu_slot(&g_state, cpu_index);

    (void)id;
    (void)v;
#if TCGCOV_HAVE_CTX
    /* rtl mode owns the tag itself; its generations start at 0. */
    if (g_state.ctx && !g_state.rtl && v != NULL) {
        v->cur_ctx = qemu_plugin_vcpu_ctx_id(cpu_index);
        ctx_note_entry(&g_state, v->cur_ctx);
    }
#endif
}

#if TCGCOV_HAVE_RDMEM
/* ------------------------------------------------------------------ */
/* RTEMS loader-generation mode.                                      */
/* ------------------------------------------------------------------ */

static void json_escape_append(GString *out, const char *s);

/*
 * Guest struct offsets for RTEMS's <link_elf.h> on an ILP32 target
 * (riscv32, microblaze): struct r_debug { int r_version; struct link_map
 * *r_map; enum r_state; } and the RTEMS link_map/section_detail layouts.
 * These are fixed by that header for 32-bit targets; a 64-bit target or a
 * changed RTEMS header needs different values (future: extract them from
 * the base image's DWARF offline and pass them as arguments).
 */
#define RTL_RD_RMAP      4         /* r_debug.r_map */
#define RTL_RD_RSTATE    8         /* r_debug.r_state */
#define RTL_RT_CONSISTENT 0
#define RTL_LM_NAME      0         /* link_map.name (char*) */
#define RTL_LM_SECNUM    4         /* link_map.sec_num */
#define RTL_LM_SECDETAIL 8         /* link_map.sec_detail (section_detail*) */
#define RTL_LM_SECADDR   12        /* link_map.sec_addr[6] (rap regions) */
#define RTL_LM_NEXT      44        /* link_map.l_next */
#define RTL_SD_NAME      0         /* section_detail.name (char*) */
#define RTL_SD_SIZE      8         /* section_detail.size */
#define RTL_SD_RAPID     12        /* section_detail.rap_id */
#define RTL_SD_STRIDE    16
#define RTL_MAX_OBJS     64        /* chain-walk bound: a corrupt guest    */
#define RTL_MAX_SECS     128       /*   pointer must not hang the plugin  */
#define RTL_MAX_NAME     128

static bool rtl_read(uint64_t addr, void *out, size_t len)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();

    if (!addr || !qemu_plugin_read_memory_vaddr(addr, buf, len) ||
        buf->len < len) {
        return false;
    }
    memcpy(out, buf->data, len);
    return true;
}

static uint32_t rtl_read_u32(uint64_t addr, bool *ok)
{
    uint32_t v = 0;

    if (!rtl_read(addr, &v, sizeof(v))) {
        *ok = false;
    }
    return v;                      /* guest and host are both little-endian */
}

static void rtl_read_str(uint64_t addr, char *out, size_t cap)
{
    size_t i;

    out[0] = '\0';
    for (i = 0; i + 1 < cap; i++) {
        if (!rtl_read(addr + i, &out[i], 1) || out[i] == '\0') {
            break;
        }
    }
    out[i] = '\0';
}

/*
 * Append a JSON snapshot of the loader's current link_map chain for
 * generation `gen`. Called under s->lock from the notification callback --
 * a context-switch-rate event, not an execution-rate one.
 */
static void rtl_snapshot(CovState *s, uint64_t gen)
{
    static const char *rap_names[] = { "text", "const", "ctor", "dtor",
                                       "data", "bss" };
    bool ok = true;
    char name[RTL_MAX_NAME];
    uint64_t lm;
    int objs = 0;

    if (s->rtl_snaps->len) {
        g_string_append(s->rtl_snaps, ", ");
    }
    g_string_append_printf(s->rtl_snaps, "\"%" PRIu64 "\": [", gen);

    lm = rtl_read_u32(s->rtl_debug_addr + RTL_RD_RMAP, &ok);
    while (ok && lm && objs < RTL_MAX_OBJS) {
        uint32_t sec_num = rtl_read_u32(lm + RTL_LM_SECNUM, &ok);
        uint64_t detail = rtl_read_u32(lm + RTL_LM_SECDETAIL, &ok);
        unsigned i;

        rtl_read_str(rtl_read_u32(lm + RTL_LM_NAME, &ok), name, sizeof(name));
        if (objs) {
            g_string_append(s->rtl_snaps, ", ");
        }
        g_string_append(s->rtl_snaps, "{\"object\": \"");
        json_escape_append(s->rtl_snaps, name);
        g_string_append(s->rtl_snaps, "\"");
        for (i = 0; i < 6; i++) {
            uint32_t base = rtl_read_u32(lm + RTL_LM_SECADDR + 4 * i, &ok);

            if (base) {
                g_string_append_printf(s->rtl_snaps,
                                       ", \"%s\": \"0x%" PRIx32 "\"",
                                       rap_names[i], base);
            }
        }
        g_string_append(s->rtl_snaps, ", \"sections\": [");
        if (sec_num > RTL_MAX_SECS) {
            sec_num = RTL_MAX_SECS;
        }
        for (i = 0; ok && i < sec_num; i++) {
            uint64_t sd = detail + (uint64_t)i * RTL_SD_STRIDE;

            rtl_read_str(rtl_read_u32(sd + RTL_SD_NAME, &ok), name,
                         sizeof(name));
            if (i) {
                g_string_append(s->rtl_snaps, ", ");
            }
            g_string_append(s->rtl_snaps, "{\"name\": \"");
            json_escape_append(s->rtl_snaps, name);
            g_string_append_printf(s->rtl_snaps,
                                   "\", \"size\": %" PRIu32
                                   ", \"rap\": %" PRIu32 "}",
                                   rtl_read_u32(sd + RTL_SD_SIZE, &ok),
                                   rtl_read_u32(sd + RTL_SD_RAPID, &ok));
        }
        g_string_append(s->rtl_snaps, "]}");
        lm = rtl_read_u32(lm + RTL_LM_NEXT, &ok);
        objs++;
    }
    g_string_append(s->rtl_snaps, "]");
    if (!ok) {
        g_printerr("tcgcov: rtl: truncated guest link_map walk at "
                   "generation %" PRIu64 "\n", gen);
    }
}

/*
 * Execution callback on the first instruction of _rtld_debug_state(). The
 * loader sets r_state and THEN calls it, so reading r_state at function
 * entry observes the completed transition. The generation bumps only on
 * RT_CONSISTENT -- i.e. once per completed load or unload -- so records
 * tagged N were executed while snapshot N's map was live. (Constructors
 * run before the post-load RT_CONSISTENT and are tagged N-1: loudly
 * unattributed rather than silently misattributed; the R2 hooks close
 * that window.)
 */
static void vcpu_rtl_state(unsigned int cpu_index, void *udata)
{
    CovState *s = &g_state;
    VcpuState *v = vcpu_slot(s, cpu_index);
    bool ok = true;
    uint32_t state;

    (void)udata;

    state = rtl_read_u32(s->rtl_debug_addr + RTL_RD_RSTATE, &ok);
    g_mutex_lock(&s->lock);
    s->rtl_events++;
    if (ok && state == RTL_RT_CONSISTENT) {
        s->rtl_generation++;
        rtl_snapshot(s, s->rtl_generation);
    }
    g_mutex_unlock(&s->lock);

    if (G_LIKELY(v != NULL)) {
        v->cur_ctx = s->rtl_generation;
        v->prev_valid = false;     /* loader event = control discontinuity */
    }
}
#endif /* TCGCOV_HAVE_RDMEM */

/*
 * The address that actually goes into a record: the vaddr itself, or with
 * phys=on its physical translation. Called only at translation time (under
 * s->lock), where the code's page is necessarily mapped -- the CPU just
 * fetched it -- so failure is rare (e.g. the mapping vanished between fetch
 * and callback); it degrades to the vaddr and is counted, never dropped.
 *
 * Filter ranges are always applied to the VIRTUAL address, before this
 * substitution: filters describe the guest's memory map as the user sees it.
 */
static uint64_t cov_addr(CovState *s, uint64_t vaddr)
{
#if TCGCOV_HAVE_XLATE
    uint64_t hw;

    if (!s->phys) {
        return vaddr;
    }
    if (qemu_plugin_translate_vaddr(vaddr, &hw)) {
        return hw;
    }
    s->phys_fail++;
#endif
    return vaddr;
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    CovState *s = &g_state;
    uint64_t tb_vaddr = qemu_plugin_tb_vaddr(tb);
    struct qemu_plugin_insn *last_insn = NULL;
    bool last_in_range = false;
    size_t n;
    CovTb *ctb = NULL;

    (void)id;

    n = qemu_plugin_tb_n_insns(tb);

#if TCGCOV_HAVE_RDMEM
    /*
     * The loader watch is registered before the filter check: coverage
     * filters must not be able to blind the generation tracking.
     */
    if (s->rtl) {
        for (size_t k = 0; k < n; k++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, k);

            if (qemu_plugin_insn_vaddr(insn) == s->rtl_state_addr) {
                qemu_plugin_register_vcpu_insn_exec_cb(
                    insn, vcpu_rtl_state, QEMU_PLUGIN_CB_NO_REGS, NULL);
            }
        }
    }
#endif

    /* If the TB start is outside every filter range, ignore it entirely. */
    if (!range_contains(s, tb_vaddr)) {
        return;
    }

    if (s->edges && n > 0) {
        last_insn = qemu_plugin_tb_get_insn(tb, n - 1);
    }

    g_mutex_lock(&s->lock);

    /*
     * A CovTb is needed when a TB-level callback will be registered: for the
     * TB-level address modes it carries the coverage count, and for edges it
     * carries the block's start and last-instruction addresses. In exact mode
     * with edges off, nothing at TB granularity is recorded, so none is made.
     */
    if (s->mode != TCGCOV_MODE_TB_INSN || s->edges) {
        ctb = g_new0(CovTb, 1);
        ctb->tb_vaddr = cov_addr(s, tb_vaddr);
        g_ptr_array_add(s->blocks, ctb);
    }

    /* last_insn is non-NULL only when edges are on, which guarantees ctb. */
    if (last_insn != NULL && ctb != NULL) {
        uint64_t last_vaddr = qemu_plugin_insn_vaddr(last_insn);

        last_in_range = range_contains(s, last_vaddr);
        ctb->last_insn_vaddr = cov_addr(s, last_vaddr);
    }

    switch (s->mode) {
    case TCGCOV_MODE_TB_INSN:
        /*
         * Exact: one execution callback per in-range instruction. This is the
         * expensive path by design - a coverage tool that over-reports is
         * worse than a slow one.
         */
        for (size_t i = 0; i < n; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

            if (range_contains(s, vaddr)) {
                CovInsn *ci = insn_alloc(s, cov_addr(s, vaddr));

                qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                                       QEMU_PLUGIN_CB_NO_REGS,
                                                       ci);
            }
        }
        if (s->edges) {
            qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_edge_entry,
                                                 QEMU_PLUGIN_CB_NO_REGS, ctb);
        }
        break;

    case TCGCOV_MODE_TB_INSN_FAST:
        /* Approximate: remember the block's instructions, gate them on entry. */
        for (size_t i = 0; i < n; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            uint64_t vaddr = qemu_plugin_insn_vaddr(insn);

            if (range_contains(s, vaddr)) {
                u64vec_push(&ctb->insns, cov_addr(s, vaddr));
            }
        }
        qemu_plugin_register_vcpu_tb_exec_cb(tb,
                                             s->ctx ? vcpu_tb_exec_ctx
                                                    : vcpu_tb_exec,
                                             QEMU_PLUGIN_CB_NO_REGS, ctb);
        break;

    case TCGCOV_MODE_TB:
    default:
        qemu_plugin_register_vcpu_tb_exec_cb(tb,
                                             s->ctx ? vcpu_tb_exec_ctx
                                                    : vcpu_tb_exec,
                                             QEMU_PLUGIN_CB_NO_REGS, ctb);
        break;
    }

    /*
     * The edge source is published from the last instruction, never from TB
     * entry - entry only proves the block started. When that instruction is
     * out of range there is nothing to publish, so the callback is not
     * registered at all and the pending source simply stays consumed.
     */
    if (s->edges && last_in_range) {
        qemu_plugin_register_vcpu_insn_exec_cb(last_insn, vcpu_last_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, ctb);
    }

    g_mutex_unlock(&s->lock);
}

/* ------------------------------------------------------------------ */
/* Output.                                                            */
/* ------------------------------------------------------------------ */

/*
 * Append `s` to `out` as the body of a JSON string (the caller supplies the
 * quotes), escaping everything RFC 8259 requires: the two mandatory escapes
 * (" and \) and every C0 control character.
 *
 * This is not cosmetic. test_id=, bsp= and elf= are free-form strings handed
 * to the plugin from a shell script - elf= is a filesystem path, which may
 * legally contain a quote or a backslash - and an unescaped one used to make
 * the metadata invalid JSON. The reader then throws on json.loads and the
 * WHOLE artifact is lost, every perfectly good binary record with it, at read
 * time and far from the cause. Escaping here is what makes the "metadata is
 * valid JSON" guarantee in FORMAT.md section 6 unconditional.
 *
 * Non-ASCII input is passed through byte-for-byte when it is well-formed
 * UTF-8, because the reader decodes this section as UTF-8. A byte that is not
 * part of a valid UTF-8 sequence - which a POSIX path may well contain, since
 * a path is a byte string with no encoding attached - cannot be passed through
 * without making the whole artifact undecodable, so it is emitted as the
 * escape \u00XX of its own value. The result is always valid UTF-8 and always
 * valid JSON; a byte-exact path is not recoverable in that case, but the
 * alternative is losing the entire file.
 *
 * Deliberately hand-rolled rather than pulling in a JSON library: this is the
 * only string the plugin ever emits, and a QEMU plugin should not acquire a
 * dependency for eight lines of escaping.
 */
static void json_escape_append(GString *out, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");

    while (*p) {
        unsigned char c = *p;

        if (c == '"' || c == '\\') {
            g_string_append_c(out, '\\');
            g_string_append_c(out, (gchar)c);
            p++;
        } else if (c < 0x20 || c == 0x7f) {
            switch (c) {
            case '\b': g_string_append(out, "\\b"); break;
            case '\f': g_string_append(out, "\\f"); break;
            case '\n': g_string_append(out, "\\n"); break;
            case '\r': g_string_append(out, "\\r"); break;
            case '\t': g_string_append(out, "\\t"); break;
            default:   g_string_append_printf(out, "\\u%04x", c); break;
            }
            p++;
        } else if (c < 0x80) {
            g_string_append_c(out, (gchar)c);
            p++;
        } else {
            gunichar u = g_utf8_get_char_validated((const char *)p, -1);

            /* (gunichar)-1 = invalid sequence, (gunichar)-2 = truncated. */
            if (u == (gunichar)-1 || u == (gunichar)-2) {
                g_string_append_printf(out, "\\u%04x", c);
                p++;
            } else {
                const unsigned char *next =
                    (const unsigned char *)g_utf8_next_char(p);

                g_string_append_len(out, (const char *)p, next - p);
                p = next;
            }
        }
    }
}

/* Emit one `"key": "value",` line with the value escaped. Keys are literals. */
static void json_append_str(GString *m, const char *key, const char *val)
{
    g_string_append_printf(m, "  \"%s\": \"", key);
    json_escape_append(m, val);
    g_string_append(m, "\",\n");
}

static char *build_metadata_json(CovState *s, uint64_t record_count,
                                 uint64_t edge_count)
{
    GString *m = g_string_new(NULL);

    g_string_append(m, "{\n");
    g_string_append(m, "  \"format\": \"tcgcov\",\n");
    g_string_append(m, "  \"version\": 1,\n");
    json_append_str(m, "mode", mode_name(s->mode));
    json_append_str(m, "target_name", s->target_name);
    g_string_append_printf(m, "  \"system_emulation\": %s,\n",
                           s->system_emulation ? "true" : "false");
    json_append_str(m, "test_id", s->test_id);
    json_append_str(m, "bsp", s->bsp);
    json_append_str(m, "elf", s->elf_path);
    json_append_str(m, "address_kind", s->phys ? "paddr" : "vaddr");
    if (s->phys) {
        g_string_append_printf(m, "  \"phys_translate_failures\": %" PRIu64
                               ",\n", s->phys_fail);
    }
    /* Counts and edges are unconditional in this producer; see FORMAT.md 10. */
    g_string_append(m, "  \"counts_enabled\": true,\n");
    g_string_append_printf(m, "  \"record_count\": %" PRIu64 ",\n",
                           record_count);
    g_string_append_printf(m, "  \"edges_enabled\": %s,\n",
                           s->edges ? "true" : "false");
    g_string_append_printf(m, "  \"edge_count\": %" PRIu64 ",\n", edge_count);
    /*
     * Fidelity keys. Added after the version-1 key set; readers that predate
     * them must ignore unknown keys (as JSON readers should), and readers that
     * want them must tolerate their absence in older files.
     */
    json_append_str(m, "insn_fidelity", fidelity_name(s->mode));
    g_string_append_printf(m, "  \"discon_tracking\": %s,\n",
                           (s->edges && TCGCOV_HAVE_DISCON) ? "true" : "false");
    g_string_append_printf(m, "  \"ctx_enabled\": %s,\n",
                           s->ctx ? "true" : "false");
    if (s->ctx) {
        json_append_str(m, "ctx_kind",
                        s->rtl ? "loader-generation" : "asid");
    }
    if (s->rtl) {
        g_string_append_printf(m, "  \"rtl_events\": %" PRIu64 ",\n",
                               s->rtl_events);
        g_string_append_printf(m, "  \"rtl_generations\": {%s},\n",
                               s->rtl_snaps ? s->rtl_snaps->str : "");
    }
    if (s->ctx) {
        GHashTableIter it;
        gpointer k, v;
        bool first = true;

        g_string_append_printf(m, "  \"ctx_switches\": %" PRIu64 ",\n",
                               s->ctx_switches);
        g_string_append(m, "  \"contexts\": {");
        if (s->ctx_entries != NULL) {
            g_hash_table_iter_init(&it, s->ctx_entries);
            while (g_hash_table_iter_next(&it, &k, &v)) {
                const uint64_t *entry = v;

                g_string_append_printf(m,
                                       "%s\"%" PRIu64 "\": {\"entries\": %"
                                       PRIu64 "}",
                                       first ? "" : ", ",
                                       entry[0], entry[1]);
                first = false;
            }
        }
        g_string_append(m, "},\n");
    }

    g_string_append(m, "  \"filters\": [");
    for (size_t i = 0; i < s->range_count; i++) {
        g_string_append_printf(m, "%s{\"start\": \"0x%" PRIx64 "\", "
                               "\"end\": \"0x%" PRIx64 "\"}",
                               i ? ", " : "",
                               s->ranges[i].start, s->ranges[i].end);
    }
    g_string_append(m, "]\n");
    g_string_append(m, "}\n");

    return g_string_free(m, FALSE);
}

/*
 * Snapshot every covered address, with its execution count, into a flat
 * unsorted array. Duplicates (retranslated or overlapping blocks) are expected
 * and merged by the caller.
 *
 * A non-zero count is the coverage predicate. There is no separate `executed`
 * flag any more: the count is maintained on every execution, so `count != 0`
 * answers the same question with one fewer field to keep hot. The only way the
 * two could disagree is a counter wrapping to exactly 2^64 executions of one
 * address, which no run reaches.
 *
 * Must be called with s->lock held.
 */
static GArray *collect_addrs(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(AddrCount));

    if (s->mode == TCGCOV_MODE_TB_INSN) {
        for (InsnSlab *slab = s->insn_slabs; slab; slab = slab->next) {
            for (size_t i = 0; i < slab->used; i++) {
                CovInsn *ci = &slab->items[i];
                uint64_t c = __atomic_load_n(&ci->count, __ATOMIC_RELAXED);

                if (c == 0) {
                    continue;
                }
                AddrCount ac = { ci->vaddr, c };
                g_array_append_val(out, ac);
            }
        }
        return out;
    }

    for (guint i = 0; i < s->blocks->len; i++) {
        CovTb *ctb = g_ptr_array_index(s->blocks, i);
        uint64_t c = __atomic_load_n(&ctb->count, __ATOMIC_RELAXED);

        if (c == 0) {
            continue;
        }

        if (s->mode == TCGCOV_MODE_TB_INSN_FAST && ctb->insns.count > 0) {
            for (size_t j = 0; j < ctb->insns.count; j++) {
                AddrCount ac = { ctb->insns.items[j], c };
                g_array_append_val(out, ac);
            }
        } else {
            AddrCount ac = { ctb->tb_vaddr, c };
            g_array_append_val(out, ac);
        }
    }

    return out;
}

/*
 * Snapshot every vCPU's edge table into one flat unsorted array. Safe without
 * locking because plugin_exit runs when all vCPUs are quiescent; that is also
 * why the per-vCPU tables never need a lock on the fast path. Returns an empty
 * array when edges are off, since the slot table is then never allocated.
 */
static GArray *collect_edges(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(CtxEdge));

    for (size_t i = 0; i < s->vcpu_cap; i++) {
        GHashTable *t = s->vcpu[i].edges;
        GHashTableIter it;
        gpointer k, v;

        if (t == NULL) {
            continue;
        }
        g_hash_table_iter_init(&it, t);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            CtxEdge e = *(CtxEdge *)v;
            g_array_append_val(out, e);
        }
    }

    return out;
}

/*
 * ctx=on version of collect_addrs: walk every vCPU's (context, block) table
 * and emit CtxAddrCount records, expanding a block's instruction list in
 * tb-insn-fast exactly as collect_addrs does from the CovTb count. Called
 * with s->lock held, vCPUs quiescent.
 */
static GArray *collect_ctx_addrs(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(CtxAddrCount));

    for (size_t i = 0; i < s->vcpu_cap; i++) {
        GHashTable *t = s->vcpu[i].ctx_tbs;
        GHashTableIter it;
        gpointer k, v;

        if (t == NULL) {
            continue;
        }
        g_hash_table_iter_init(&it, t);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            const CtxTbCount *ctc = v;
            const CovTb *ctb = ctc->tb;

            if (ctc->count == 0) {
                continue;
            }
            if (s->mode == TCGCOV_MODE_TB_INSN_FAST && ctb->insns.count > 0) {
                for (size_t j = 0; j < ctb->insns.count; j++) {
                    CtxAddrCount ac = { ctc->ctx, ctb->insns.items[j],
                                        ctc->count };
                    g_array_append_val(out, ac);
                }
            } else {
                CtxAddrCount ac = { ctc->ctx, ctb->tb_vaddr, ctc->count };
                g_array_append_val(out, ac);
            }
        }
    }

    return out;
}

/*
 * Sort by (src, dst) and merge duplicates in place, summing traversal counts.
 * Duplicates arise whenever the same edge was taken on more than one vCPU.
 * Returns the number of unique edges left at the front of the array.
 */
static guint merge_edges(GArray *edges)
{
    guint unique = 0;

    g_array_sort(edges, edge_compare);

    for (guint i = 0; i < edges->len; i++) {
        CtxEdge cur = g_array_index(edges, CtxEdge, i);

        if (unique > 0 &&
            edge_equal(&cur, &g_array_index(edges, CtxEdge, unique - 1))) {
            g_array_index(edges, CtxEdge, unique - 1).count += cur.count;
        } else {
            g_array_index(edges, CtxEdge, unique) = cur;
            unique++;
        }
    }
    return unique;
}

/*
 * ctx=on version of merge_addrs: sort by (ctx, addr) and merge duplicates,
 * which arise when the same (context, address) was executed on more than one
 * vCPU or reached through retranslated blocks.
 */
static guint merge_ctx_addrs(GArray *pairs)
{
    guint unique = 0;

    g_array_sort(pairs, ctxaddr_compare);

    for (guint i = 0; i < pairs->len; i++) {
        CtxAddrCount cur = g_array_index(pairs, CtxAddrCount, i);
        CtxAddrCount *prev;

        if (unique > 0) {
            prev = &g_array_index(pairs, CtxAddrCount, unique - 1);
            if (prev->ctx == cur.ctx && prev->addr == cur.addr) {
                prev->count += cur.count;
                continue;
            }
        }
        g_array_index(pairs, CtxAddrCount, unique) = cur;
        unique++;
    }
    return unique;
}

/*
 * Sort by address and merge duplicates in place, summing execution counts.
 * Returns the number of unique addresses left at the front of the array.
 */
static guint merge_addrs(GArray *pairs)
{
    guint unique = 0;

    g_array_sort(pairs, addrcount_compare);

    for (guint i = 0; i < pairs->len; i++) {
        AddrCount cur = g_array_index(pairs, AddrCount, i);

        if (unique > 0 &&
            cur.addr == g_array_index(pairs, AddrCount, unique - 1).addr) {
            g_array_index(pairs, AddrCount, unique - 1).count += cur.count;
        } else {
            g_array_index(pairs, AddrCount, unique) = cur;
            unique++;
        }
    }
    return unique;
}

/*
 * Fill in the edge-section fields of the header. records_offset and
 * records_size must already be set. When edges are disabled all three edge
 * fields are zero and flag bit1 stays clear.
 */
static void fill_edge_header(CovState *s, tcgcov_header *h, uint64_t n_edges)
{
    if (!s->edges) {
        h->edge_count = 0;
        h->edges_offset = 0;
        h->edges_size = 0;
        return;
    }

    /*
     * EDGE_COUNTS is always set alongside HAS_EDGES because counts are
     * unconditional; the 16-byte count-less edge record remains legal in the
     * format for other producers, but this one never writes it.
     */
    h->flags |= TCGCOV_FLAG_HAS_EDGES | TCGCOV_FLAG_EDGE_COUNTS;
    h->edge_count = n_edges;
    h->edges_offset = h->records_offset + h->records_size;
    h->edges_size = n_edges * (uint64_t)(s->ctx ? sizeof(CtxEdge)
                                                : sizeof(Edge));
}

/*
 * Write exactly `len` bytes, reporting a short write as failure.
 *
 * A true return does NOT mean the bytes are in the file - stdio buffers, so
 * for an artifact smaller than the buffer the underlying write(2) has not even
 * been attempted yet. Only close_out() can answer that.
 */
static bool write_all(FILE *f, const void *buf, size_t len)
{
    return len == 0 || fwrite(buf, 1, len, f) == len;
}

static bool write_edges(CovState *s, FILE *f, GArray *edges, guint n)
{
    if (!s->edges) {
        return true;
    }
    for (guint i = 0; i < n; i++) {
        const CtxEdge *e = &g_array_index(edges, CtxEdge, i);

        if (s->ctx) {
            /* CtxEdge is exactly the on-disk v2 record. */
            if (!write_all(f, e, sizeof(*e))) {
                return false;
            }
        } else {
            /*
             * The v1 record is the { src, dst, count } tail of CtxEdge:
             * three contiguous uint64_t starting at offset 8 (asserted at
             * the definition), so the leading ctx (always 0 here) is simply
             * not written.
             */
            if (!write_all(f, &e->src, sizeof(Edge))) {
                return false;
            }
        }
    }
    return true;
}

/*
 * Permissions to give the artifact.
 *
 * mkstemp() creates its file 0600, but the fopen() this replaced created it
 * 0666 & ~umask, and an artifact is routinely read back by a different user
 * than the one QEMU ran as (CI collector, a shared results directory). Match
 * whatever the file being replaced had, so repeatedly overwriting an artifact
 * never quietly changes who can read it, and fall back to the umask default
 * when there is nothing to match.
 */
static mode_t artifact_mode(const char *dest)
{
    struct stat st;
    mode_t um;

    if (stat(dest, &st) == 0) {
        return st.st_mode & 0777;
    }
    /* There is no reader for the umask; it has to be set to be read. */
    um = umask(0);
    umask(um);
    return 0666 & ~um;
}

/*
 * Create the temporary file the artifact is assembled in and return a stdio
 * stream on it, storing its path in *tmp_path_out for the caller to rename or
 * unlink. Returns NULL (having reported why) on failure.
 *
 * Two properties matter here.
 *
 * Same directory as the destination: rename(2) is only atomic within a
 * filesystem, and fails outright across one, so the temporary cannot live in
 * /tmp.
 *
 * Unique per writer: the name used to be a fixed "<out>.tmp", which is not a
 * private name at all. Two QEMU processes launched with the same out= - an
 * easy mistake when a test suite runs in parallel - both opened that one file
 * with O_TRUNC and interleaved their writes into it, so each renamed a file
 * containing a blend of two runs' bytes into place. mkstemp() gives every
 * writer its own file; concurrent runs then simply race to rename, the last
 * one wins, and every artifact that is ever visible under the destination name
 * is the complete output of exactly one run.
 */
static FILE *open_tmp(const char *dest, char **tmp_path_out)
{
    g_autofree char *dir = g_path_get_dirname(dest);
    g_autofree char *base = g_path_get_basename(dest);
    g_autofree char *leaf = g_strdup_printf(".%s.XXXXXX", base);
    char *tmp = g_build_filename(dir, leaf, NULL);
    int fd = mkstemp(tmp);
    FILE *f;

    if (fd < 0) {
        g_printerr("tcgcov: cannot create a temporary file for %s: %s\n",
                   dest, g_strerror(errno));
        g_free(tmp);
        return NULL;
    }
    if (fchmod(fd, artifact_mode(dest)) != 0) {
        /* Not fatal: the artifact is still correct, just more private. */
        g_printerr("tcgcov: warning: cannot set permissions on %s: %s\n",
                   tmp, g_strerror(errno));
    }
    f = fdopen(fd, "wb");
    if (f == NULL) {
        g_printerr("tcgcov: cannot open %s for writing: %s\n",
                   tmp, g_strerror(errno));
        close(fd);
        unlink(tmp);
        g_free(tmp);
        return NULL;
    }

    *tmp_path_out = tmp;
    return f;
}

/*
 * Flush, sync and close. Returns true only if every byte actually reached the
 * file. `ok` is the running result of the writes; the stream is closed exactly
 * once whatever it is.
 *
 * The close is the check that matters. Because stdio buffers, a typical
 * artifact is handed to write(2) exactly once, inside the flush - so an
 * ENOSPC or EDQUOT is reported by fflush()/fclose() and by no fwrite() at all.
 * Checking only fwrite() (the previous behaviour was to check nothing) would
 * let a truncated file be renamed over a good one, and the loss would surface
 * later as a reader error on a file the run appeared to write successfully.
 */
static bool close_out(FILE *f, bool ok)
{
    if (ok && ferror(f)) {
        ok = false;
    }
    if (ok && fflush(f) != 0) {
        ok = false;
    }
    /*
     * Sync before the rename publishes the name, so a host that dies moments
     * later cannot leave the destination pointing at unwritten data. EINVAL
     * and ENOTSUP mean the target simply does not implement fsync, which is
     * not a write error.
     */
    if (ok && fsync(fileno(f)) != 0
        && errno != EINVAL && errno != ENOTSUP) {
        ok = false;
    }
    if (fclose(f) != 0) {
        ok = false;
    }
    return ok;
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    CovState *s = &g_state;
    GArray *pairs;
    GArray *edges;
    guint n_addrs, n_edges;
    char *meta;
    size_t meta_size;
    tcgcov_header h;
    char *tmp = NULL;
    FILE *f;
    bool ok;

    (void)id;
    (void)userdata;

    g_mutex_lock(&s->lock);
    pairs = s->ctx ? collect_ctx_addrs(s) : collect_addrs(s);
    edges = collect_edges(s);
    g_mutex_unlock(&s->lock);

    n_addrs = s->ctx ? merge_ctx_addrs(pairs) : merge_addrs(pairs);
    n_edges = s->edges ? merge_edges(edges) : 0;

    meta = build_metadata_json(s, n_addrs, n_edges);
    meta_size = strlen(meta);

    memset(&h, 0, sizeof(h));
    /*
     * The magic never changes; the version field is the format signal.
     * Version 2 (ctx=on) restructures the record arrays, so a version-1
     * reader must reject it -- which the version check does loudly, with
     * a better message than a magic mismatch would produce.
     */
    memcpy(h.magic, TCGCOV_MAGIC, 8);
    h.version = s->ctx ? 2 : 1;
    h.endian = 1;                          /* file is written little-endian */
    h.header_size = (uint32_t)sizeof(h);
    h.record_type = mode_is_insn_granular(s->mode) ? TCGCOV_REC_INSN_ADDR
                                                   : TCGCOV_REC_TB_ADDR;
    h.flags = TCGCOV_FLAG_HAS_COUNTS;
    if (s->ctx) {
        h.flags |= TCGCOV_FLAG_HAS_CTX;
    }
    h.record_count = n_addrs;
    h.metadata_offset = sizeof(h);
    h.metadata_size = meta_size;
    h.records_offset = sizeof(h) + meta_size;
    h.records_size = (uint64_t)n_addrs * (s->ctx ? sizeof(CtxAddrCount)
                                                 : sizeof(AddrCount));
    fill_edge_header(s, &h, n_edges);

    f = open_tmp(s->out_path, &tmp);
    if (!f) {
        /* Nothing was touched, so any previous artifact is still valid. */
        goto out;
    }

    ok = write_all(f, &h, sizeof(h)) && write_all(f, meta, meta_size);
    for (guint i = 0; ok && i < n_addrs; i++) {
        /* Both structs are exactly their on-disk record. */
        if (s->ctx) {
            const CtxAddrCount *ac = &g_array_index(pairs, CtxAddrCount, i);
            ok = write_all(f, ac, sizeof(*ac));
        } else {
            const AddrCount *ac = &g_array_index(pairs, AddrCount, i);
            ok = write_all(f, ac, sizeof(*ac));
        }
    }
    ok = ok && write_edges(s, f, edges, n_edges);

    /*
     * On any failure the temporary is removed and the rename is skipped: a
     * previously written artifact stays intact and readable, which is strictly
     * more useful than a truncated file bearing the expected name. The reader
     * rejects a short file loudly, but the point is never to hand it one.
     */
    if (!close_out(f, ok)) {
        g_printerr("tcgcov: failed to write %s: %s; leaving %s unchanged\n",
                   tmp, g_strerror(errno), s->out_path);
        unlink(tmp);
        goto out;
    }

    if (rename(tmp, s->out_path) != 0) {
        g_printerr("tcgcov: failed to rename %s -> %s: %s\n",
                   tmp, s->out_path, g_strerror(errno));
        unlink(tmp);
    } else if (s->verbose) {
        g_printerr("tcgcov: wrote %u {address, count} records (%s), "
                   "%u edges to %s\n",
                   n_addrs, fidelity_name(s->mode),
                   s->edges ? n_edges : 0, s->out_path);
    }

out:
    g_free(tmp);
    g_free(meta);
    g_array_free(pairs, TRUE);
    g_array_free(edges, TRUE);
}

/* ------------------------------------------------------------------ */
/* Argument parsing.                                                  */
/* ------------------------------------------------------------------ */

/* Parse "0xSTART-0xEND[,0xSTART-0xEND...]" into g_state.ranges. */
/*
 * Parse one "0xSTART-0xEND" half. g_ascii_strtoull returns 0 on failure with
 * no error signal, so the endptr must be checked: an unexpanded shell variable
 * or a typo would otherwise parse as 0 and produce an empty range, which
 * matches nothing and silently discards ALL coverage.
 */
static bool parse_addr(const char *text, uint64_t *out)
{
    char *endp = NULL;
    const char *stripped = g_strstrip((char *)text);

    if (*stripped == '\0') {
        return false;
    }
    *out = g_ascii_strtoull(stripped, &endp, 0);
    return endp != NULL && *endp == '\0';
}

/* Returns false on a malformed spec, so installation can fail loudly. */
static bool parse_filter(CovState *s, const char *spec)
{
    g_autofree char **parts = g_strsplit(spec, ",", -1);
    for (int i = 0; parts[i] != NULL; i++) {
        if (parts[i][0] == '\0') {
            continue;
        }
        g_autofree char **se = g_strsplit(parts[i], "-", 2);
        uint64_t start, end;

        if (!se[0] || !se[1]) {
            g_printerr("tcgcov: bad filter range '%s' (want START-END)\n",
                       parts[i]);
            return false;
        }
        if (!parse_addr(se[0], &start) || !parse_addr(se[1], &end)) {
            g_printerr("tcgcov: filter range '%s' is not a number pair\n",
                       parts[i]);
            return false;
        }
        if (end <= start) {
            g_printerr("tcgcov: filter range '%s' is empty "
                       "(end must exceed start)\n", parts[i]);
            return false;
        }
        s->ranges = g_realloc(s->ranges, (s->range_count + 1) * sizeof(Range));
        s->ranges[s->range_count].start = start;
        s->ranges[s->range_count].end = end;
        s->range_count++;
    }
    return true;
}

/*
 * Parse a boolean argument. QEMU's own idiom is on/off/true/false/yes/no, and
 * its plugin loader rewrites the bare `arg="edges"` form into literally
 * "edges=on" (plugins/loader.c). Accepting only "1" therefore silently
 * disabled the option for anyone following QEMU convention, which for edges
 * meant a report where every branch reads as never evaluated. Accept "1"/"0"
 * too, since that is what this plugin documented before.
 *
 * Returns false if the value is not a boolean at all, so the caller can refuse
 * to start rather than guess.
 */
static bool parse_bool_arg(const char *k, const char *v, bool *out)
{
    if (g_strcmp0(v, "1") == 0) {
        *out = true;
        return true;
    }
    if (g_strcmp0(v, "0") == 0) {
        *out = false;
        return true;
    }
    return qemu_plugin_bool_parse(k, v, out);
}

/* Returns false on a bad argument, so installation can fail loudly. */
static bool parse_arg(CovState *s, const char *arg)
{
    g_autofree char **kv = g_strsplit(arg, "=", 2);
    const char *k = kv[0];
    const char *v = kv[1] ? kv[1] : "";

    /* g_strsplit("") yields a 1-element vector holding only the terminator. */
    if (k == NULL) {
        g_printerr("tcgcov: empty argument\n");
        return false;
    }

    if (g_strcmp0(k, "out") == 0) {
        g_free(s->out_path);
        s->out_path = g_strdup(v);
    } else if (g_strcmp0(k, "test_id") == 0) {
        /* Free-form metadata string; JSON-escaped on the way out. */
        g_free(s->test_id);
        s->test_id = g_strdup(v);
    } else if (g_strcmp0(k, "bsp") == 0) {
        /* Free-form metadata string; JSON-escaped on the way out. */
        g_free(s->bsp);
        s->bsp = g_strdup(v);
    } else if (g_strcmp0(k, "elf") == 0) {
        g_free(s->elf_path);
        s->elf_path = g_strdup(v);
    } else if (g_strcmp0(k, "mode") == 0) {
        if (g_strcmp0(v, "tb") == 0) {
            s->mode = TCGCOV_MODE_TB;
        } else if (g_strcmp0(v, "tb-insn") == 0 || g_strcmp0(v, "insn") == 0) {
            s->mode = TCGCOV_MODE_TB_INSN;
        } else if (g_strcmp0(v, "tb-insn-fast") == 0) {
            s->mode = TCGCOV_MODE_TB_INSN_FAST;
        } else {
            g_printerr("tcgcov: unknown mode '%s' "
                       "(want tb, tb-insn or tb-insn-fast)\n", v);
            return false;
        }
    } else if (g_strcmp0(k, "filter") == 0) {
        return parse_filter(s, v);
    } else if (g_strcmp0(k, "counts") == 0) {
        /*
         * Removed rather than silently accepted. Execution counts are now
         * always recorded, so `counts=0` would ask for something this plugin
         * cannot do, and `counts=1` would ask for what it already does; the
         * two used to mean genuinely different artifacts. A script that still
         * passes either must fail loudly, because the alternative is a run
         * that quietly produces a different file than the caller asked for.
         */
        g_printerr("tcgcov: the 'counts' argument was removed; execution "
                   "counts are now always recorded and cannot be disabled "
                   "(removing the option also removed the redundant executed "
                   "flag from the per-instruction fast path). Drop '%s' from "
                   "the plugin arguments.\n", arg);
        return false;
    } else if (g_strcmp0(k, "edges") == 0) {
        return parse_bool_arg(k, v, &s->edges);
    } else if (g_strcmp0(k, "ctx") == 0) {
        return parse_bool_arg(k, v, &s->ctx);
    } else if (g_strcmp0(k, "phys") == 0) {
        return parse_bool_arg(k, v, &s->phys);
    } else if (g_strcmp0(k, "rtl_state") == 0) {
        if (!parse_addr(v, &s->rtl_state_addr)) {
            g_printerr("tcgcov: rtl_state: bad address '%s'\n", v);
            return false;
        }
    } else if (g_strcmp0(k, "rtl_debug") == 0) {
        if (!parse_addr(v, &s->rtl_debug_addr)) {
            g_printerr("tcgcov: rtl_debug: bad address '%s'\n", v);
            return false;
        }
    } else if (g_strcmp0(k, "verbose") == 0) {
        return parse_bool_arg(k, v, &s->verbose);
    } else {
        g_printerr("tcgcov: unknown argument '%s'\n", arg);
        return false;
    }
    return true;
}

/*
 * Allocate the per-vCPU edge table exactly once, cache-line aligned.
 *
 * Sizing comes from info->system.max_vcpus, which is only valid when
 * system_emulation is true - it shares a union with the user-mode arm. There
 * is no equivalent bound in user mode (each guest thread is a vCPU), so a fixed
 * cap is used there and overflow degrades to dropped edges plus one warning.
 *
 * Aligning by hand rather than with g_aligned_alloc() keeps the plugin
 * buildable against older glib; the over-allocation is one cache line, once.
 */
static void alloc_vcpu_table(CovState *s, const qemu_info_t *info)
{
    size_t bytes;
    uintptr_t base;

    if (info->system_emulation && info->system.max_vcpus > 0) {
        s->vcpu_cap = (size_t)info->system.max_vcpus;
    } else {
        s->vcpu_cap = TCGCOV_VCPU_FALLBACK;
    }

    bytes = s->vcpu_cap * sizeof(VcpuState) + TCGCOV_CACHELINE;
    s->vcpu_raw = g_malloc0(bytes);
    base = ((uintptr_t)s->vcpu_raw + TCGCOV_CACHELINE - 1)
           & ~(uintptr_t)(TCGCOV_CACHELINE - 1);
    s->vcpu = (VcpuState *)base;
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    CovState *s = &g_state;

    memset(s, 0, sizeof(*s));
    g_mutex_init(&s->lock);
    s->blocks = g_ptr_array_new();
    s->out_path = g_strdup("tcgcov.cov");
    s->target_name = g_strdup(info->target_name);
    s->system_emulation = info->system_emulation;
    s->mode = TCGCOV_MODE_TB_INSN;  /* default: exact per-instruction */
    /*
     * Edges default to ON: branch coverage working out of the box is worth
     * more than the per-block cost, and a report where every branch reads
     * "never evaluated" because nobody passed edges=1 is a worse failure than
     * a slightly slower run. `edges=off` remains available for runs where the
     * extra per-TB callback and hash insert per block execution do matter.
     */
    s->edges = true;

    /*
     * Refuse to start on a bad argument rather than run with settings the
     * caller did not ask for. A coverage run that silently records nothing
     * (or records no edges) looks like a genuine coverage regression, which
     * is far more expensive to diagnose than a failed launch.
     */
    for (int i = 0; i < argc; i++) {
        if (!parse_arg(s, argv[i])) {
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
    }

    if (s->phys) {
#if !TCGCOV_HAVE_XLATE
        g_printerr("tcgcov: phys=on, but this plugin was built against a "
                   "QEMU header without qemu_plugin_translate_vaddr "
                   "(plugin API v5, QEMU >= 10.1). Rebuild against a newer "
                   "header, or drop phys=on.\n");
        g_printerr("tcgcov: refusing to start\n");
        return -1;
#else
        if (!s->system_emulation) {
            /*
             * In user mode there is no guest MMU: translate_vaddr always
             * fails and every record would silently fall back to the vaddr
             * while the metadata claimed paddr.
             */
            g_printerr("tcgcov: phys=on requires system emulation\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
#endif
    }

    if (s->rtl_state_addr || s->rtl_debug_addr) {
#if !TCGCOV_HAVE_RDMEM
        g_printerr("tcgcov: rtl_state=/rtl_debug=, but this plugin was "
                   "built against a QEMU header without "
                   "qemu_plugin_read_memory_vaddr (plugin API v4). "
                   "Rebuild against a newer header.\n");
        g_printerr("tcgcov: refusing to start\n");
        return -1;
#else
        if (!s->rtl_state_addr || !s->rtl_debug_addr) {
            g_printerr("tcgcov: rtl_state= and rtl_debug= go together "
                       "(&_rtld_debug_state and &_rtld_debug from the base "
                       "image's symbol table)\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
        if (s->ctx) {
            g_printerr("tcgcov: ctx=on and rtl_* are mutually exclusive: "
                       "both want to own the per-record tag\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
        if (s->mode == TCGCOV_MODE_TB_INSN) {
            g_printerr("tcgcov: rtl mode supports mode=tb and "
                       "mode=tb-insn-fast (same limit as ctx=on)\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
        if (!s->system_emulation) {
            g_printerr("tcgcov: rtl mode requires system emulation\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
        /*
         * Generation tagging reuses the whole ctx=on recording path
         * (per-(tag, block) tables, TCGCOV2 output); only the tag's
         * *source* differs, and it needs no QEMU context API.
         */
        s->rtl = true;
        s->ctx = true;
        s->rtl_snaps = g_string_new(NULL);
#endif
    }

    if (s->ctx && !s->rtl) {
#if !TCGCOV_HAVE_CTX
        g_printerr("tcgcov: ctx=on, but this plugin was built against a "
                   "QEMU header without the context-visibility API "
                   "(qemu_plugin_register_vcpu_ctx_changed_cb). Rebuild "
                   "against a QEMU tree carrying the tcgcov context patches "
                   "(docs/QEMU-RFC-context.md), or drop ctx=on.\n");
        g_printerr("tcgcov: refusing to start\n");
        return -1;
#else
        if (s->mode == TCGCOV_MODE_TB_INSN) {
            /*
             * Exact mode records from per-instruction callbacks, which have
             * no per-(context, instruction) storage yet - attributing them
             * to one context would be silently wrong for the others.
             */
            g_printerr("tcgcov: ctx=on supports mode=tb and mode=tb-insn-"
                       "fast; mode=tb-insn is not context-aware yet\n");
            g_printerr("tcgcov: refusing to start\n");
            return -1;
        }
        qemu_plugin_register_vcpu_ctx_changed_cb(id, vcpu_ctx_changed);
#endif
    }

    if (s->edges || s->ctx) {
        alloc_vcpu_table(s, info);
        qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    }
    if (s->edges) {
#if TCGCOV_HAVE_DISCON
        qemu_plugin_register_vcpu_discon_cb(
            id,
            (enum qemu_plugin_discon_type)(QEMU_PLUGIN_DISCON_INTERRUPT |
                                           QEMU_PLUGIN_DISCON_EXCEPTION),
            vcpu_discon);
#endif
    }

    if (s->verbose) {
        g_printerr("tcgcov: target=%s system=%d mode=%s fidelity=%s out=%s "
                   "counts=always edges=%d ctx=%d phys=%d discon=%d "
                   "plugin_api=%d vcpu_slots=%zu filters=%zu\n",
                   s->target_name, s->system_emulation,
                   mode_name(s->mode), fidelity_name(s->mode),
                   s->out_path, s->edges, s->ctx, s->phys,
                   s->edges && TCGCOV_HAVE_DISCON,
                   QEMU_PLUGIN_VERSION, s->vcpu_cap, s->range_count);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
