#!/usr/bin/env bash
#
# End-to-end integration test using the HOST toolchain only.
#
# The unit tests all feed the tool hand-written fixtures, so they verify that
# the code agrees with itself. This one compiles a real C file, disassembles it
# with a real objdump, symbolizes it with a real addr2line, and asserts a
# coverage number that is known by construction -- which is the only way to
# catch the six subcommands failing to compose, or a toolchain output format
# the parsers do not actually handle.
#
# It needs no QEMU: the .cov artifact is synthesized in Python from the real
# instruction addresses of one chosen function, so "what executed" is exact and
# the expected result can be stated up front.
#
# Usage: ci/integration.sh [output-dir]
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"
mkdir -p "$WORK"
cd "$WORK"

# CI uses the host toolchain; TOOLPREFIX lets a developer point at a GNU
# binutils install on a host whose native tools are not GNU (macOS ships atos,
# not addr2line).
: "${TOOLPREFIX:=}"
CC_BIN="${CC:-cc}"
OBJDUMP_BIN="${TOOLPREFIX}objdump"
ADDR2LINE_BIN="${TOOLPREFIX}addr2line"
for tool in "$CC_BIN" "$OBJDUMP_BIN" "$ADDR2LINE_BIN" python3; do
  command -v "$tool" >/dev/null || { echo "SKIP: no $tool available" >&2; exit 0; }
done

cat > prog.c <<'EOF'
volatile int sink;

int covered_fn(int x)          /* line 3  - WILL be marked executed */
{
    if (x > 5) {               /* line 5  */
        sink = 1;              /* line 6  */
        return 1;              /* line 7  */
    }
    sink = 2;                  /* line 9  */
    return 2;                  /* line 10 */
}

int uncovered_fn(int x)        /* line 13 - will NOT be executed */
{
    if (x > 99) {              /* line 15 */
        sink = 3;              /* line 16 */
        return 3;              /* line 17 */
    }
    sink = 4;                  /* line 19 */
    return 4;                  /* line 20 */
}

int main(void) { return covered_fn(7) + uncovered_fn(1); }
EOF

"$CC_BIN" -g -O0 -c prog.c -o prog.o

# Synthesize a .cov whose covered set is exactly covered_fn's instructions.
OBJDUMP="$OBJDUMP_BIN" python3 - "$PWD/prog.o" cov.cov <<'PY'
import json, os, re, struct, subprocess, sys

elf, out = sys.argv[1], sys.argv[2]
dis = subprocess.run([os.environ.get("OBJDUMP", "objdump"), "-d", elf], capture_output=True,
                     encoding="utf-8", errors="surrogateescape").stdout

# Collect the instruction addresses belonging to covered_fn only. objdump marks
# a function with "<name>:" and both tab- and space-separated address lines are
# accepted, matching what the package itself handles.
addrs, inside = [], False
for line in dis.splitlines():
    m = re.match(r"^[0-9a-fA-F]+ <([^>]+)>:", line)
    if m:
        inside = m.group(1) == "covered_fn"
        continue
    m = re.match(r"^[ ]*([0-9a-fA-F]+):[ \t]", line)
    if m and inside:
        addrs.append(int(m.group(1), 16))
if not addrs:
    sys.exit("integration: found no instructions for covered_fn")
addrs = sorted(set(addrs))

meta = json.dumps({
    "format": "tcgcov", "version": 1, "mode": "tb-insn",
    "target_name": "host", "system_emulation": False,
    "test_id": "integration", "bsp": "", "elf": elf,
    "address_kind": "vaddr", "counts_enabled": False,
    "record_count": len(addrs), "edges_enabled": False,
    "edge_count": 0, "filters": [],
}).encode()

HDR = "<8sHHIIIQQQQQQQQ"
hsz = struct.calcsize(HDR)
assert hsz == 88, hsz
recs = b"".join(struct.pack("<Q", a) for a in addrs)
hdr = struct.pack(HDR, b"TCGCOV1\0", 1, 1, hsz, 2, 0, len(addrs),
                  hsz, len(meta), hsz + len(meta), len(recs), 0, 0, 0)
open(out, "wb").write(hdr + meta + recs)
print(f"synthesized {out}: {len(addrs)} addresses from covered_fn")
PY

run() { PYTHONPATH="$REPO" python3 -m tcgcov "$@"; }

run dump --metadata-only cov.cov > /dev/null
run symbolize --cov cov.cov --elf prog.o --toolchain-prefix "$TOOLPREFIX" --all-paths --out covered.jsonl
run coverable --elf prog.o --toolchain-prefix "$TOOLPREFIX" --all-paths --out coverable.jsonl
run lcov covered.jsonl --coverable coverable.jsonl --out prog.info
run merge prog.info --name integration --out agg.info

python3 - <<'PY'
import sys
lines = {}
for raw in open("agg.info"):
    if raw.startswith("DA:"):
        n, _, c = raw[3:].strip().partition(",")
        lines[int(n)] = int(c)
if not lines:
    sys.exit("FAIL: aggregate has no DA records")

# covered_fn is lines 3-11; uncovered_fn is 13-21. Assert the split rather than
# an exact total, because the exact line set depends on the host compiler.
cov_hit  = [n for n, c in lines.items() if c > 0 and 3  <= n <= 11]
unc_hit  = [n for n, c in lines.items() if c > 0 and 13 <= n <= 21]
unc_seen = [n for n in lines if 13 <= n <= 21]

print(f"covered_fn lines hit      : {sorted(cov_hit)}")
print(f"uncovered_fn lines hit    : {sorted(unc_hit)}")
print(f"uncovered_fn lines present: {sorted(unc_seen)}")

fail = False
if not cov_hit:
    print("FAIL: no covered_fn line was reported executed"); fail = True
if unc_hit:
    print(f"FAIL: uncovered_fn lines reported executed: {sorted(unc_hit)}"); fail = True
# The denominator must include code that never ran -- that is the whole point
# of the coverable inventory, and its absence is how a report reads 100%.
if not unc_seen:
    print("FAIL: uncovered_fn absent from the denominator (report would read 100%)")
    fail = True
if len(lines) == len([n for n, c in lines.items() if c > 0]):
    print("FAIL: every line in the report is covered -- denominator collapsed")
    fail = True
sys.exit(1 if fail else 0)
PY

# The same measurement again, in ONE command. `tcgcov report` runs the very
# subcommands the chain above ran by hand, so the only thing it can get wrong
# is what it passes them -- and the way that shows up is a different set of
# lines, which is precisely what is compared here. Branch records are extra
# (the driver runs `branches` by default) and are not part of the comparison.
mkdir -p raw
cp cov.cov raw/
run report --raw-dir raw --out-dir report --all-paths \
  --toolchain-prefix "$TOOLPREFIX" --name integration --out report/agg.info

test -s report/agg.info || { echo "FAIL: report wrote no aggregate"; exit 1; }
test -s report/lcov/per-test/cov.info || \
  { echo "FAIL: report wrote no per-test .info"; exit 1; }

python3 - <<'PY'
import sys

def da(path):
    """{(source file, line): count} from an LCOV .info."""
    out, sf = {}, None
    for raw in open(path):
        if raw.startswith("SF:"):
            sf = raw[3:].strip()
        elif raw.startswith("DA:"):
            n, _, c = raw[3:].strip().partition(",")
            out[(sf, int(n))] = int(c)
    return out

manual, driven = da("agg.info"), da("report/agg.info")
if not driven:
    sys.exit("FAIL: the driven aggregate has no DA records")
if manual != driven:
    only_m = sorted(set(manual) - set(driven))
    only_d = sorted(set(driven) - set(manual))
    diff = sorted(k for k in set(manual) & set(driven)
                  if manual[k] != driven[k])
    print("FAIL: `tcgcov report` disagrees with the hand-run chain")
    print(f"  only in the hand-run aggregate: {only_m[:10]}")
    print(f"  only in the driven aggregate  : {only_d[:10]}")
    print(f"  differing counts              : {diff[:10]}")
    sys.exit(1)
print(f"one-command driver matches the hand-run chain: "
      f"{len(driven)} DA records")
PY

# A second run must reuse the cached per-ELF inventory rather than rebuild it,
# and must still produce the same aggregate.
run report --raw-dir raw --out-dir report --all-paths \
  --toolchain-prefix "$TOOLPREFIX" --name integration --out report/agg2.info
cmp -s report/agg.info report/agg2.info || \
  { echo "FAIL: a repeated report run changed the aggregate"; exit 1; }

echo "integration: PASS"
