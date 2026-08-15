/*
 * tcgcov Linux support: MMU address-space-context (ASID) tagging.
 *
 * Everything specific to the ctx=on tag source lives here: the QEMU
 * context-visibility callback (the proposed API of docs/QEMU-RFC-context.md
 * -- MicroBlaze RPID first; any MMU guest OS qualifies, Linux is the
 * consumer it was built for) and the per-context entry bookkeeping. The
 * generic core knows only s->ctx and the two entry points below.
 *
 * Design and verification: docs/LINUX-VM.md (Tier 3).
 *
 * License: GNU GPL, version 2 or later.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "tcgcov-internal.h"

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

void tcgcov_linux_register(qemu_plugin_id_t id)
{
    qemu_plugin_register_vcpu_ctx_changed_cb(id, vcpu_ctx_changed);
}

void tcgcov_linux_vcpu_init(CovState *s, unsigned int cpu_index)
{
    VcpuState *v = vcpu_slot(s, cpu_index);

    if (v != NULL) {
        v->cur_ctx = qemu_plugin_vcpu_ctx_id(cpu_index);
        ctx_note_entry(s, v->cur_ctx);
    }
}

#else /* !TCGCOV_HAVE_CTX */

/* ctx=on can never survive install without the API (it refuses), but the
 * call sites link against these symbols unconditionally. */
void tcgcov_linux_register(qemu_plugin_id_t id)
{
    (void)id;
}

void tcgcov_linux_vcpu_init(CovState *s, unsigned int cpu_index)
{
    (void)s;
    (void)cpu_index;
}

#endif /* TCGCOV_HAVE_CTX */
