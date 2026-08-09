/*
 * tcgcov - non-intrusive translation-block coverage for QEMU TCG.
 *
 * Observes executed guest code, deduplicates covered guest code addresses in
 * memory, and writes one compact "TCGCOV1" binary artifact at QEMU exit.
 * Symbolization (addr2line/LCOV) is done offline by a host tool.
 *
 * Optionally (edges=1) it also records the directed control-flow edges taken
 * between translation blocks, so that branch coverage can be computed offline.
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

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/*
 * Feature gate. The plugin is built against whichever qemu-plugin.h matches the
 * QEMU it will be loaded into, and that header defines QEMU_PLUGIN_VERSION.
 * Discontinuity callbacks (interrupt/exception notifications) arrived in API
 * version 5; on older APIs the plugin still works, it just cannot invalidate a
 * pending edge source when an asynchronous event steals control between two
 * translation blocks.
 */
#if defined(QEMU_PLUGIN_VERSION) && QEMU_PLUGIN_VERSION >= 5
#define TCGCOV_HAVE_DISCON 1
#else
#define TCGCOV_HAVE_DISCON 0
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
 * `executed` and `count` are only meaningful in the two TB-level modes; in
 * mode=tb-insn the address records come from CovInsn instead.
 */
typedef struct {
    uint64_t tb_vaddr;
    U64Vec insns;                  /* in-range insn vaddrs (tb-insn-fast) */
    unsigned int executed;         /* monotonic 0 -> 1, relaxed atomic */
    uint64_t count;                /* execution count (counts mode), 64-bit */

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
    uint64_t count;                /* execution count (counts mode) */
    unsigned int executed;         /* monotonic 0 -> 1, relaxed atomic */
} CovInsn;

#define TCGCOV_INSN_SLAB_ITEMS 1024

typedef struct InsnSlab {
    struct InsnSlab *next;
    size_t used;
    CovInsn items[TCGCOV_INSN_SLAB_ITEMS];
} InsnSlab;

/* { address, execution count } record used when counts mode is enabled. */
typedef struct {
    uint64_t addr;
    uint64_t count;
} AddrCount;

/*
 * A directed control-flow edge. src/dst are written to disk in this order;
 * count is written only when TCGCOV_FLAG_EDGE_COUNTS is set. The struct is
 * three uint64_t with no padding on any supported ABI, so the first 16 or 24
 * bytes can be written directly.
 */
typedef struct {
    uint64_t src;                  /* last insn vaddr of the source TB */
    uint64_t dst;                  /* start vaddr of the destination TB */
    uint64_t count;                /* traversals */
} Edge;

G_STATIC_ASSERT(sizeof(Edge) == 24);

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
    GHashTable *edges;             /* Edge* -> same Edge*, keyed on (src,dst) */
    bool prev_valid;
    char pad[TCGCOV_CACHELINE - sizeof(uint64_t) - sizeof(void *)
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
    bool counts;
    bool edges;                    /* edges=1 */
    bool verbose;

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

/* Sort edges ascending by (src, dst), as the file format requires. */
static gint edge_compare(gconstpointer a, gconstpointer b)
{
    const Edge *ea = a;
    const Edge *eb = b;

    if (ea->src != eb->src) {
        return (ea->src > eb->src) - (ea->src < eb->src);
    }
    return (ea->dst > eb->dst) - (ea->dst < eb->dst);
}

static guint edge_hash(gconstpointer p)
{
    const Edge *e = p;
    uint64_t h = e->src * 0x9E3779B97F4A7C15ULL;

    h ^= e->dst + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    return (guint)(h ^ (h >> 32));
}

static gboolean edge_equal(gconstpointer a, gconstpointer b)
{
    const Edge *ea = a;
    const Edge *eb = b;

    return ea->src == eb->src && ea->dst == eb->dst;
}

/* Size of one on-disk edge record for the current configuration. */
static size_t edge_record_size(CovState *s)
{
    return s->counts ? 24 : 16;
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
 * Mark a monotonic 0 -> 1 flag. Deliberately not g_atomic_int_set(): GLib's
 * setter is sequentially consistent and emits a full barrier (two on the
 * __sync fallback path) on every execution. The flag only ever moves one way
 * and is read once, at exit, after all vCPUs have stopped - so a relaxed store
 * suffices, and the guarding relaxed load keeps the steady state (already set)
 * to a plain load off a clean, shared cache line with no store traffic at all.
 */
static inline void mark_executed(unsigned int *flag)
{
    if (!__atomic_load_n(flag, __ATOMIC_RELAXED)) {
        __atomic_store_n(flag, 1, __ATOMIC_RELAXED);
    }
}

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
    Edge key;
    Edge *e;

    if (G_UNLIKELY(v == NULL) || !v->prev_valid) {
        return;
    }
    v->prev_valid = false;

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
        e = g_new0(Edge, 1);
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

    mark_executed(&ctb->executed);

    if (g_state.counts) {
        /* 64-bit atomic add (GLib has no portable g_atomic_int64_add). */
        __atomic_fetch_add(&ctb->count, 1, __ATOMIC_RELAXED);
    }

    if (g_state.edges) {
        record_edge(&g_state, cpu_index, ctb->tb_vaddr);
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
 */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    CovInsn *ci = (CovInsn *)udata;

    (void)cpu_index;

    mark_executed(&ci->executed);

    if (g_state.counts) {
        __atomic_fetch_add(&ci->count, 1, __ATOMIC_RELAXED);
    }
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

/*
 * vCPU initialization. Used only to surface an undersized slot table at
 * startup - when the guest brings the vCPU online - instead of silently at the
 * first edge, or (with counts and edges both quiet) not at all.
 */
static void vcpu_init(qemu_plugin_id_t id, unsigned int cpu_index)
{
    (void)id;
    vcpu_slot(&g_state, cpu_index);
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

    /* If the TB start is outside every filter range, ignore it entirely. */
    if (!range_contains(s, tb_vaddr)) {
        return;
    }

    n = qemu_plugin_tb_n_insns(tb);

    if (s->edges && n > 0) {
        last_insn = qemu_plugin_tb_get_insn(tb, n - 1);
    }

    g_mutex_lock(&s->lock);

    /*
     * A CovTb is needed when a TB-level callback will be registered: for the
     * TB-level address modes it carries the coverage state, and for edges it
     * carries the block's start and last-instruction addresses. In exact mode
     * with edges off, nothing at TB granularity is recorded, so none is made.
     */
    if (s->mode != TCGCOV_MODE_TB_INSN || s->edges) {
        ctb = g_new0(CovTb, 1);
        ctb->tb_vaddr = tb_vaddr;
        g_ptr_array_add(s->blocks, ctb);
    }

    /* last_insn is non-NULL only when edges are on, which guarantees ctb. */
    if (last_insn != NULL && ctb != NULL) {
        ctb->last_insn_vaddr = qemu_plugin_insn_vaddr(last_insn);
        last_in_range = range_contains(s, ctb->last_insn_vaddr);
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
                CovInsn *ci = insn_alloc(s, vaddr);

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
                u64vec_push(&ctb->insns, vaddr);
            }
        }
        qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                             QEMU_PLUGIN_CB_NO_REGS, ctb);
        break;

    case TCGCOV_MODE_TB:
    default:
        qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
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

static char *build_metadata_json(CovState *s, uint64_t record_count,
                                 uint64_t edge_count)
{
    GString *m = g_string_new(NULL);

    g_string_append(m, "{\n");
    g_string_append(m, "  \"format\": \"tcgcov\",\n");
    g_string_append(m, "  \"version\": 1,\n");
    g_string_append_printf(m, "  \"mode\": \"%s\",\n", mode_name(s->mode));
    g_string_append_printf(m, "  \"target_name\": \"%s\",\n",
                           s->target_name ? s->target_name : "");
    g_string_append_printf(m, "  \"system_emulation\": %s,\n",
                           s->system_emulation ? "true" : "false");
    g_string_append_printf(m, "  \"test_id\": \"%s\",\n",
                           s->test_id ? s->test_id : "");
    g_string_append_printf(m, "  \"bsp\": \"%s\",\n", s->bsp ? s->bsp : "");
    g_string_append_printf(m, "  \"elf\": \"%s\",\n",
                           s->elf_path ? s->elf_path : "");
    g_string_append_printf(m, "  \"address_kind\": \"vaddr\",\n");
    g_string_append_printf(m, "  \"counts_enabled\": %s,\n",
                           s->counts ? "true" : "false");
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
    g_string_append_printf(m, "  \"insn_fidelity\": \"%s\",\n",
                           fidelity_name(s->mode));
    g_string_append_printf(m, "  \"discon_tracking\": %s,\n",
                           (s->edges && TCGCOV_HAVE_DISCON) ? "true" : "false");

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
 * Must be called with s->lock held.
 */
static GArray *collect_addrs(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(AddrCount));

    if (s->mode == TCGCOV_MODE_TB_INSN) {
        for (InsnSlab *slab = s->insn_slabs; slab; slab = slab->next) {
            for (size_t i = 0; i < slab->used; i++) {
                CovInsn *ci = &slab->items[i];

                if (!__atomic_load_n(&ci->executed, __ATOMIC_RELAXED)) {
                    continue;
                }
                AddrCount ac = {
                    ci->vaddr,
                    __atomic_load_n(&ci->count, __ATOMIC_RELAXED)
                };
                g_array_append_val(out, ac);
            }
        }
        return out;
    }

    for (guint i = 0; i < s->blocks->len; i++) {
        CovTb *ctb = g_ptr_array_index(s->blocks, i);
        uint64_t c;

        if (!__atomic_load_n(&ctb->executed, __ATOMIC_RELAXED)) {
            continue;
        }
        c = __atomic_load_n(&ctb->count, __ATOMIC_RELAXED);

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
 * array when edges are off.
 */
static GArray *collect_edges(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(Edge));

    for (size_t i = 0; i < s->vcpu_cap; i++) {
        GHashTable *t = s->vcpu[i].edges;
        GHashTableIter it;
        gpointer k, v;

        if (t == NULL) {
            continue;
        }
        g_hash_table_iter_init(&it, t);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            Edge e = *(Edge *)v;
            g_array_append_val(out, e);
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
        Edge cur = g_array_index(edges, Edge, i);

        if (unique > 0 &&
            edge_equal(&cur, &g_array_index(edges, Edge, unique - 1))) {
            g_array_index(edges, Edge, unique - 1).count += cur.count;
        } else {
            g_array_index(edges, Edge, unique) = cur;
            unique++;
        }
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

    h->flags |= TCGCOV_FLAG_HAS_EDGES;
    if (s->counts) {
        h->flags |= TCGCOV_FLAG_EDGE_COUNTS;
    }
    h->edge_count = n_edges;
    h->edges_offset = h->records_offset + h->records_size;
    h->edges_size = n_edges * (uint64_t)edge_record_size(s);
}

static void write_edges(CovState *s, FILE *f, GArray *edges, guint n)
{
    size_t rec = edge_record_size(s);

    if (!s->edges) {
        return;
    }
    for (guint i = 0; i < n; i++) {
        const Edge *e = &g_array_index(edges, Edge, i);
        /* Edge is { src, dst, count }; the first `rec` bytes are the record. */
        fwrite(e, rec, 1, f);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    CovState *s = &g_state;
    GArray *pairs;
    GArray *edges;
    guint n_addrs, n_edges;
    size_t addr_rec = s->counts ? sizeof(AddrCount) : sizeof(uint64_t);
    char *meta;
    size_t meta_size;
    tcgcov_header h;
    char *tmp;
    FILE *f;

    (void)id;
    (void)userdata;

    g_mutex_lock(&s->lock);
    pairs = collect_addrs(s);
    edges = collect_edges(s);
    g_mutex_unlock(&s->lock);

    n_addrs = merge_addrs(pairs);
    n_edges = s->edges ? merge_edges(edges) : 0;

    meta = build_metadata_json(s, n_addrs, n_edges);
    meta_size = strlen(meta);

    memset(&h, 0, sizeof(h));
    memcpy(h.magic, TCGCOV_MAGIC, 8);
    h.version = 1;
    h.endian = 1;                          /* file is written little-endian */
    h.header_size = (uint32_t)sizeof(h);
    h.record_type = mode_is_insn_granular(s->mode) ? TCGCOV_REC_INSN_ADDR
                                                   : TCGCOV_REC_TB_ADDR;
    h.flags = s->counts ? TCGCOV_FLAG_HAS_COUNTS : 0;
    h.record_count = n_addrs;
    h.metadata_offset = sizeof(h);
    h.metadata_size = meta_size;
    h.records_offset = sizeof(h) + meta_size;
    h.records_size = (uint64_t)n_addrs * addr_rec;
    fill_edge_header(s, &h, n_edges);

    tmp = g_strdup_printf("%s.tmp", s->out_path);
    f = fopen(tmp, "wb");
    if (!f) {
        g_printerr("tcgcov: failed to open %s\n", tmp);
        goto out;
    }

    fwrite(&h, sizeof(h), 1, f);
    fwrite(meta, 1, meta_size, f);
    for (guint i = 0; i < n_addrs; i++) {
        /* AddrCount is { addr, count }; the first `addr_rec` bytes are it. */
        const AddrCount *ac = &g_array_index(pairs, AddrCount, i);
        fwrite(ac, addr_rec, 1, f);
    }
    write_edges(s, f, edges, n_edges);
    fclose(f);

    if (rename(tmp, s->out_path) != 0) {
        g_printerr("tcgcov: failed to rename %s -> %s\n",
                   tmp, s->out_path);
    } else if (s->verbose) {
        g_printerr("tcgcov: wrote %u %s records (%s), %u edges to %s\n",
                   n_addrs, s->counts ? "count" : "address",
                   fidelity_name(s->mode), s->edges ? n_edges : 0,
                   s->out_path);
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
        /* Free-form metadata string, copied verbatim into the JSON. */
        g_free(s->test_id);
        s->test_id = g_strdup(v);
    } else if (g_strcmp0(k, "bsp") == 0) {
        /* Free-form metadata string, copied verbatim into the JSON. */
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
        return parse_bool_arg(k, v, &s->counts);
    } else if (g_strcmp0(k, "edges") == 0) {
        return parse_bool_arg(k, v, &s->edges);
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

    if (s->edges) {
        alloc_vcpu_table(s, info);
        qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
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
                   "counts=%d edges=%d discon=%d plugin_api=%d vcpu_slots=%zu "
                   "filters=%zu\n",
                   s->target_name, s->system_emulation,
                   mode_name(s->mode), fidelity_name(s->mode),
                   s->out_path, s->counts, s->edges,
                   s->edges && TCGCOV_HAVE_DISCON,
                   QEMU_PLUGIN_VERSION, s->vcpu_cap, s->range_count);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
