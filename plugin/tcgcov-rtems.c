/*
 * tcgcov RTEMS support: loader-generation tagging.
 *
 * Everything specific to the RTEMS run-time loader (libdl) lives here:
 * the guest-side struct layouts, the r_debug/link_map chain walk, and the
 * execution callback on _rtld_debug_state() that bumps the per-record
 * generation tag and snapshots the module map into the artifact metadata.
 * The generic core knows only s->rtl and tcgcov_rtems_watch_tb().
 *
 * Design and verification: docs/RTEMS-DL.md (stage R3).
 *
 * License: GNU GPL, version 2 or later.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "tcgcov-internal.h"

#if TCGCOV_HAVE_RDMEM

/* ------------------------------------------------------------------ */
/* RTEMS loader-generation mode.                                      */
/* ------------------------------------------------------------------ */

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

void tcgcov_rtems_watch_tb(CovState *s, struct qemu_plugin_tb *tb, size_t n)
{
    for (size_t k = 0; k < n; k++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, k);

        if (qemu_plugin_insn_vaddr(insn) == s->rtl_state_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, vcpu_rtl_state, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
    }
}

#else /* !TCGCOV_HAVE_RDMEM */

/* s->rtl can never be set without RDMEM (install refuses), but the call
 * site links against this symbol unconditionally. */
void tcgcov_rtems_watch_tb(CovState *s, struct qemu_plugin_tb *tb, size_t n)
{
    (void)s;
    (void)tb;
    (void)n;
}

#endif /* TCGCOV_HAVE_RDMEM */
