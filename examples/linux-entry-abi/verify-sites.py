#!/usr/bin/env python3
"""Verify each patched entry.S argument-save-area reserve site executed.

Address-based (no DWARF): scan the vmlinux disassembly for every
`addik r1,r1,-32` reserve, decode the branch that follows, resolve its
target, and match it to the entry.S callee at that address (from
System.map). Each patched callee is only reachable from entry.S, so the
match is unambiguous; the register-indirect `bra r12` is the unique
syscall dispatch. Then check whether the reserve's address was covered.

Usage: verify-sites.py <SP-dir> <cov-file>
"""
import re, sys
from tcgcov.format import read_full

SP = sys.argv[1]
COV = sys.argv[2]

# callee address -> name, for the functions the fix's sites call
CALLEES = {}
for l in open(f"{SP}/System-stress.map"):
    p = l.split()
    if len(p) == 3 and p[2] in (
            "do_syscall_trace_enter", "do_syscall_trace_leave",
            "do_notify_resume", "schedule_tail", "full_exception",
            "do_page_fault", "do_IRQ", "sw_exception",
            "microblaze_kgdb_break"):
        CALLEES[int(p[0], 16)] = p[2]

RESERVE = re.compile(r"^([0-9a-f]+):\t3021ffe0 \taddik\tr1, r1, -32$")
INSN = re.compile(r"^([0-9a-f]+):\t([0-9a-f]{8}) \t(\S+)\s*(.*)$")

dis = []
for l in open(f"{SP}/vmlinux-stress.dis"):
    m = INSN.match(l)
    if m:
        dis.append((int(m.group(1), 16), int(m.group(2), 16),
                    m.group(3), m.group(4)))
idx = {a: i for i, (a, _w, _m, _o) in enumerate(dis)}

def branch_target(i):
    """Decode the branch at dis[i], using a preceding imm if present."""
    addr, word, mnem, ops = dis[i]
    lo = word & 0xffff
    imm_hi = None
    if i > 0 and dis[i - 1][2] == "imm":
        imm_hi = dis[i - 1][1] & 0xffff
    if mnem == "bra" and ops.strip() == "r12":
        return "DISPATCH"
    if mnem in ("brlid", "brl", "bri", "brid"):        # PC-relative
        off = lo if lo < 0x8000 else lo - 0x10000
        return addr + off
    if mnem in ("bralid", "brald", "brai", "braid", "rted", "rtbd", "rtsd"):
        hi = imm_hi if imm_hi is not None else (0xffff if lo & 0x8000 else 0)
        return (hi << 16) | lo
    return None

# find reserve sites and their callee
sites = []          # (reserve_addr, callee_name)
for i, (addr, word, mnem, ops) in enumerate(dis):
    if word != 0x3021ffe0 or mnem != "addik":
        continue
    for j in range(i + 1, min(i + 7, len(dis))):
        m2 = dis[j][2]
        if m2 in ("bra", "brlid", "bralid", "rted", "rtbd", "brald",
                  "braid", "brid"):
            tgt = branch_target(j)
            if tgt == "DISPATCH":
                sites.append((addr, "bra_r12_dispatch")); break
            if isinstance(tgt, int) and tgt in CALLEES:
                sites.append((addr, CALLEES[tgt])); break
            # a non-callee branch: this reserve is an ordinary frame, skip
            break

covered = {a for _c, a, _n in read_full(COV)[2]}

# Exception/interrupt entry code runs in REAL mode at the kernel's physical
# alias (virt 0xc0000000 -> phys 0x90000000 on petalogix); the syscall path
# runs virtual. A site counts as covered at either alias.
PHYS = 0x90000000
VIRT = 0xc0000000

def is_covered(a):
    return a in covered or (a - VIRT + PHYS) in covered

print(f"{len(sites)} entry.S reserve sites matched; "
      f"{len(covered)} covered addrs in filter window\n")
order = ["do_syscall_trace_enter", "bra_r12_dispatch",
         "do_syscall_trace_leave", "do_notify_resume", "schedule_tail",
         "full_exception", "do_page_fault", "do_IRQ", "sw_exception",
         "microblaze_kgdb_break"]
sites.sort(key=lambda s: s[0])
n_cov = 0
for addr, callee in sites:
    hit = is_covered(addr)
    n_cov += hit
    where = ""
    if hit and addr not in covered:
        where = "  (real-mode/phys)"
    print(f"  {'COVERED' if hit else 'MISSED ':7}  0x{addr:08x}  "
          f"{callee}{where}")

# KGDB site is config-gated off -> never in the build
kgdb = any("kgdb" in c for _a, c in sites)
print(f"\n  {n_cov}/{len(sites)} reserve sites executed")
if not kgdb:
    print("  (microblaze_kgdb_break site absent: CONFIG_KGDB not set -- "
          "expected)")
