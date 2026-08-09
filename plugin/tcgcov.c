/*
 * tcgcov - non-intrusive translation-block coverage for QEMU TCG.
 *
 * Observes executed translation blocks, deduplicates covered guest code
 * addresses in memory, and writes one compact "TCGCOV1" binary artifact at
 * QEMU exit. Symbolization (addr2line/LCOV) is done offline by a host tool.
 *
 * Optionally (edges=1) it also records the directed control-flow edges taken
 * between translation blocks, so that branch coverage can be computed offline.
 *
 * This follows the same structure as contrib/plugins/drcov.c: the QEMU
 * translation callback carries no userdata, so plugin state lives in a single
 * global object. Retranslated TBs simply produce duplicate per-TB records;
 * that is harmless because addresses are sorted and de-duplicated at exit.
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

typedef struct {
    uint64_t *items;
    size_t count;
    size_t cap;
} U64Vec;

typedef struct {
    uint64_t tb_vaddr;
    U64Vec insns;                  /* in-range insn vaddrs (tb-insn mode) */
    volatile gint executed;
    uint64_t count;                /* execution count (counts mode), 64-bit */

    /*
     * Edge support: the vaddr of the LAST instruction of this TB, and whether
     * that address passes the filter. Using the last instruction rather than
     * the TB start as the edge source is deliberate - on delay-slot
     * architectures (MicroBlaze, SPARC, MIPS) the branch is followed by a
     * delay-slot instruction before control actually transfers, and the last
     * instruction is the one an offline tool can attribute the branch to.
     * Both are computed at translation time so the execution fast path never
     * has to walk the filter ranges.
     */
    uint64_t last_insn_vaddr;
    bool last_insn_in_range;
} CovTb;

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

/*
 * Per-vCPU edge-tracking state: the pending edge source left behind by the
 * previously executed TB on this vCPU.
 *
 * prev_valid is false when there is no usable predecessor, which covers two
 * cases that both mean "emit nothing": (a) this is the first TB executed on
 * the vCPU, and (b) the previous TB's last instruction fell outside every
 * filter range. Collapsing them is intentional - neither produces an edge.
 */
typedef struct {
    uint64_t prev_src;
    bool prev_valid;
} VcpuPrev;

typedef struct {
    uint64_t start;
    uint64_t end;                  /* exclusive */
} Range;

typedef struct {
    GMutex lock;
    GPtrArray *blocks;             /* of CovTb* */

    char *out_path;
    char *test_id;
    char *bsp;
    char *elf_path;
    char *target_name;
    bool system_emulation;

    bool expand_tb_to_insns;       /* mode=tb-insn */
    bool counts;
    bool edges;                    /* edges=1 */
    bool verbose;

    /*
     * Edge state. The per-vCPU array is indexed by cpu_index and grown lazily
     * rather than sized from a fixed maximum: QEMU can hot-plug vCPUs after
     * qemu_plugin_install(), so any fixed cap is either wasteful or a silent
     * correctness hole. Growth is safe without extra synchronisation because
     * *every* access to vcpu_prev - both the reallocating growth and the
     * plain reads/writes from the TB execution callback - happens with
     * ->lock held, so no reader can observe a stale base pointer freed by a
     * concurrent g_realloc().
     *
     * Taking a mutex on each TB execution is a real cost on SMP guests, but
     * it is only paid when edges=1, which is opt-in and off by default.
     */
    VcpuPrev *vcpu_prev;
    size_t vcpu_cap;
    GHashTable *edge_set;          /* Edge* -> same Edge*, keyed on (src,dst) */

    Range *ranges;
    size_t range_count;
} CovState;

static CovState g_state;

/* ------------------------------------------------------------------ */
/* Helpers.                                                           */
/* ------------------------------------------------------------------ */

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

static gint u64_compare(gconstpointer a, gconstpointer b)
{
    uint64_t av = *(const uint64_t *)a;
    uint64_t bv = *(const uint64_t *)b;
    return (av > bv) - (av < bv);
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

/* Must be called with s->lock held. */
static VcpuPrev *vcpu_prev_slot(CovState *s, unsigned int cpu_index)
{
    if (cpu_index >= s->vcpu_cap) {
        size_t newcap = s->vcpu_cap ? s->vcpu_cap : 8;

        while (newcap <= (size_t)cpu_index) {
            newcap *= 2;
        }
        s->vcpu_prev = g_realloc(s->vcpu_prev, newcap * sizeof(VcpuPrev));
        memset(&s->vcpu_prev[s->vcpu_cap], 0,
               (newcap - s->vcpu_cap) * sizeof(VcpuPrev));
        s->vcpu_cap = newcap;
    }
    return &s->vcpu_prev[cpu_index];
}

/* ------------------------------------------------------------------ */
/* TCG callbacks.                                                     */
/* ------------------------------------------------------------------ */

/*
 * Record the edge (previous TB's last insn -> this TB's start) on this vCPU,
 * then remember this TB as the new predecessor.
 *
 * Both endpoints already satisfy the filter: dst is a TB start, and TBs whose
 * start is out of range are never instrumented at all; src was range-checked
 * at translation time. Note the consequence of that filtering - if execution
 * passes through an un-instrumented (out-of-range) TB, the next recorded edge
 * jumps over it rather than being split in two. That is inherent to filtering
 * and is the same trade-off the address records already make.
 */
static void record_edge(CovState *s, unsigned int cpu_index, CovTb *ctb)
{
    g_mutex_lock(&s->lock);

    VcpuPrev *p = vcpu_prev_slot(s, cpu_index);

    if (p->prev_valid) {
        Edge key = { p->prev_src, ctb->tb_vaddr, 0 };
        Edge *e = g_hash_table_lookup(s->edge_set, &key);

        if (!e) {
            e = g_new0(Edge, 1);
            e->src = key.src;
            e->dst = key.dst;
            g_hash_table_insert(s->edge_set, e, e);
        }
        e->count++;
    }

    p->prev_src = ctb->last_insn_vaddr;
    p->prev_valid = ctb->last_insn_in_range;

    g_mutex_unlock(&s->lock);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    CovTb *ctb = (CovTb *)udata;

    g_atomic_int_set(&ctb->executed, 1);

    if (g_state.counts) {
        /* 64-bit atomic add (GLib has no portable g_atomic_int64_add). */
        __atomic_fetch_add(&ctb->count, 1, __ATOMIC_RELAXED);
    }

    if (g_state.edges) {
        record_edge(&g_state, cpu_index, ctb);
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    CovState *s = &g_state;
    uint64_t tb_vaddr = qemu_plugin_tb_vaddr(tb);

    /* If the TB start is outside every filter range, ignore it entirely. */
    if (!range_contains(s, tb_vaddr)) {
        return;
    }

    g_mutex_lock(&s->lock);

    CovTb *ctb = g_new0(CovTb, 1);
    ctb->tb_vaddr = tb_vaddr;

    if (s->expand_tb_to_insns) {
        size_t n = qemu_plugin_tb_n_insns(tb);
        for (size_t i = 0; i < n; i++) {
            struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
            uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
            if (range_contains(s, vaddr)) {
                u64vec_push(&ctb->insns, vaddr);
            }
        }
    }

    if (s->edges) {
        size_t n = qemu_plugin_tb_n_insns(tb);
        if (n > 0) {
            struct qemu_plugin_insn *last = qemu_plugin_tb_get_insn(tb, n - 1);
            ctb->last_insn_vaddr = qemu_plugin_insn_vaddr(last);
        } else {
            /* Defensive: an empty TB should not happen. */
            ctb->last_insn_vaddr = tb_vaddr;
        }
        ctb->last_insn_in_range = range_contains(s, ctb->last_insn_vaddr);
    }

    g_ptr_array_add(s->blocks, ctb);

    g_mutex_unlock(&s->lock);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, ctb);
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
    g_string_append_printf(m, "  \"mode\": \"%s\",\n",
                           s->expand_tb_to_insns ? "tb-insn" : "tb");
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
 * Snapshot the edge set into a flat array sorted by (src, dst).
 * Must be called with s->lock held. Returns an empty array when edges are off.
 */
static GArray *collect_edges(CovState *s)
{
    GArray *out = g_array_new(FALSE, FALSE, sizeof(Edge));

    if (s->edge_set) {
        GHashTableIter it;
        gpointer k, v;

        g_hash_table_iter_init(&it, s->edge_set);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            Edge e = *(Edge *)v;
            g_array_append_val(out, e);
        }
    }

    g_array_sort(out, edge_compare);
    return out;
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

static void write_edges(CovState *s, FILE *f, GArray *edges)
{
    size_t rec = edge_record_size(s);

    if (!s->edges) {
        return;
    }
    for (guint i = 0; i < edges->len; i++) {
        const Edge *e = &g_array_index(edges, Edge, i);
        /* Edge is { src, dst, count }; the first `rec` bytes are the record. */
        fwrite(e, rec, 1, f);
    }
}

/*
 * Counts-mode writer: emit sorted unique { addr, count } records. Each covered
 * address inherits the execution count of every TB it belongs to; counts for
 * the same address (from retranslated/overlapping TBs) are summed.
 */
static void plugin_exit_counts(CovState *s)
{
    GArray *pairs = g_array_new(FALSE, FALSE, sizeof(AddrCount));
    GArray *edges;

    g_mutex_lock(&s->lock);

    for (guint i = 0; i < s->blocks->len; i++) {
        CovTb *ctb = g_ptr_array_index(s->blocks, i);
        if (!g_atomic_int_get(&ctb->executed)) {
            continue;
        }
        uint64_t c = __atomic_load_n(&ctb->count, __ATOMIC_RELAXED);
        if (s->expand_tb_to_insns && ctb->insns.count > 0) {
            for (size_t j = 0; j < ctb->insns.count; j++) {
                AddrCount ac = { ctb->insns.items[j], c };
                g_array_append_val(pairs, ac);
            }
        } else {
            AddrCount ac = { ctb->tb_vaddr, c };
            g_array_append_val(pairs, ac);
        }
    }

    edges = collect_edges(s);

    g_mutex_unlock(&s->lock);

    g_array_sort(pairs, addrcount_compare);

    /* Merge-sum duplicate addresses in place. */
    guint unique = 0;
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

    char *meta = build_metadata_json(s, unique, edges->len);
    size_t meta_size = strlen(meta);

    tcgcov_header h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, TCGCOV_MAGIC, 8);
    h.version = 1;
    h.endian = 1;
    h.header_size = (uint32_t)sizeof(h);
    h.record_type = s->expand_tb_to_insns ? TCGCOV_REC_INSN_ADDR
                                          : TCGCOV_REC_TB_ADDR;
    h.flags = TCGCOV_FLAG_HAS_COUNTS;
    h.record_count = unique;
    h.metadata_offset = sizeof(h);
    h.metadata_size = meta_size;
    h.records_offset = sizeof(h) + meta_size;
    h.records_size = (uint64_t)unique * sizeof(AddrCount);
    fill_edge_header(s, &h, edges->len);

    char *tmp = g_strdup_printf("%s.tmp", s->out_path);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        g_printerr("tcgcov: failed to open %s\n", tmp);
        goto out;
    }

    fwrite(&h, sizeof(h), 1, f);
    fwrite(meta, 1, meta_size, f);
    for (guint i = 0; i < unique; i++) {
        AddrCount ac = g_array_index(pairs, AddrCount, i);
        fwrite(&ac, sizeof(ac), 1, f);
    }
    write_edges(s, f, edges);
    fclose(f);

    if (rename(tmp, s->out_path) != 0) {
        g_printerr("tcgcov: failed to rename %s -> %s\n",
                   tmp, s->out_path);
    } else if (s->verbose) {
        g_printerr("tcgcov: wrote %u count records, %u edges to %s\n",
                   unique, s->edges ? edges->len : 0, s->out_path);
    }

out:
    g_free(tmp);
    g_free(meta);
    g_array_free(pairs, TRUE);
    g_array_free(edges, TRUE);
}

static void plugin_exit(qemu_plugin_id_t id, void *userdata)
{
    CovState *s = &g_state;

    if (s->counts) {
        plugin_exit_counts(s);
        return;
    }

    GArray *covered = g_array_new(FALSE, FALSE, sizeof(uint64_t));
    GArray *edges;

    g_mutex_lock(&s->lock);

    for (guint i = 0; i < s->blocks->len; i++) {
        CovTb *ctb = g_ptr_array_index(s->blocks, i);
        if (!g_atomic_int_get(&ctb->executed)) {
            continue;
        }
        if (s->expand_tb_to_insns && ctb->insns.count > 0) {
            for (size_t j = 0; j < ctb->insns.count; j++) {
                g_array_append_val(covered, ctb->insns.items[j]);
            }
        } else {
            g_array_append_val(covered, ctb->tb_vaddr);
        }
    }

    edges = collect_edges(s);

    g_mutex_unlock(&s->lock);

    g_array_sort(covered, u64_compare);

    /* De-duplicate in place. */
    guint unique = 0;
    for (guint i = 0; i < covered->len; i++) {
        uint64_t cur = g_array_index(covered, uint64_t, i);
        if (unique == 0 || cur != g_array_index(covered, uint64_t, unique - 1)) {
            g_array_index(covered, uint64_t, unique) = cur;
            unique++;
        }
    }

    char *meta = build_metadata_json(s, unique, edges->len);
    size_t meta_size = strlen(meta);

    tcgcov_header h;
    memset(&h, 0, sizeof(h));
    memcpy(h.magic, TCGCOV_MAGIC, 8);
    h.version = 1;
    h.endian = 1;                          /* file is written little-endian */
    h.header_size = (uint32_t)sizeof(h);
    h.record_type = s->expand_tb_to_insns ? TCGCOV_REC_INSN_ADDR
                                          : TCGCOV_REC_TB_ADDR;
    h.flags = 0;
    h.record_count = unique;
    h.metadata_offset = sizeof(h);
    h.metadata_size = meta_size;
    h.records_offset = sizeof(h) + meta_size;
    h.records_size = (uint64_t)unique * sizeof(uint64_t);
    fill_edge_header(s, &h, edges->len);

    char *tmp = g_strdup_printf("%s.tmp", s->out_path);
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        g_printerr("tcgcov: failed to open %s\n", tmp);
        goto out;
    }

    fwrite(&h, sizeof(h), 1, f);
    fwrite(meta, 1, meta_size, f);
    for (guint i = 0; i < unique; i++) {
        uint64_t a = g_array_index(covered, uint64_t, i);
        fwrite(&a, sizeof(a), 1, f);
    }
    write_edges(s, f, edges);
    fclose(f);

    if (rename(tmp, s->out_path) != 0) {
        g_printerr("tcgcov: failed to rename %s -> %s\n",
                   tmp, s->out_path);
    } else if (s->verbose) {
        g_printerr("tcgcov: wrote %u records, %u edges to %s\n",
                   unique, s->edges ? edges->len : 0, s->out_path);
    }

out:
    g_free(tmp);
    g_free(meta);
    g_array_free(covered, TRUE);
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
            s->expand_tb_to_insns = false;
        } else if (g_strcmp0(v, "tb-insn") == 0 || g_strcmp0(v, "insn") == 0) {
            s->expand_tb_to_insns = true;
        } else {
            g_printerr("tcgcov: unknown mode '%s' (want tb or tb-insn)\n", v);
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
    s->expand_tb_to_insns = true;  /* default mode=tb-insn */

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
        /*
         * Keyed and valued by the same Edge*; the table owns the allocation
         * and frees it on destroy. Edge count is bounded by the size of the
         * executed CFG, so no eviction policy is needed.
         */
        s->edge_set = g_hash_table_new_full(edge_hash, edge_equal, g_free,
                                            NULL);
    }

    if (s->verbose) {
        g_printerr("tcgcov: target=%s system=%d mode=%s out=%s "
                   "counts=%d edges=%d filters=%zu\n",
                   s->target_name, s->system_emulation,
                   s->expand_tb_to_insns ? "tb-insn" : "tb",
                   s->out_path, s->counts, s->edges, s->range_count);
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
