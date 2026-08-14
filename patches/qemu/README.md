# QEMU proof-of-concept: plugin context visibility

Companion to [docs/QEMU-RFC-context.md](../../docs/QEMU-RFC-context.md)
(**draft, not sent**) and issue #6.

`0001-plugins-context-visibility-poc.diff` implements the proposed API
against the QEMU 10.2.4 release tarball:

| piece | where |
|---|---|
| `QEMU_PLUGIN_EV_VCPU_CTX_CHANGED` event | `include/qemu/plugin-event.h` |
| `qemu_plugin_vcpu_ctx_id()`, `qemu_plugin_register_vcpu_ctx_changed_cb()`, `QEMU_PLUGIN_CTX_UNAVAILABLE`, version bump 5→6 | `include/qemu/qemu-plugin.h` (symbols auto-export via `scripts/qemu-plugin-symbols.py`) |
| target hook: `CPUClass::plugin_ctx_id` | `include/hw/core/cpu.h` |
| dispatch (`qemu_plugin_vcpu_ctx_changed`) + `plugin_cpu_ctx_id` helper, modeled on the discon/syscall callbacks | `plugins/core.c`, `plugins/api.c`, `plugins/plugin.h`, `include/qemu/plugin.h` |
| MicroBlaze enablement: hook returns `RPID & 0xff`; notifier called from the `MMU_R_PID` write path (the existing TLB-flush choke point) | `target/microblaze/cpu.c`, `target/microblaze/mmu.c` |
| demo plugin: per-context TB exec counts + switch count | `contrib/plugins/ctxdemo.c` |

## Measured result (2026-08-14)

Build: `configure --target-list=microblazeel-softmmu --enable-plugins`,
macOS host. Guest: the Buildroot Linux 6.12.81 image from the PR 121432
work (`-M petalogix-s3adsp1800`, `linux-covtest.bin`, which boots to a
login prompt and auto-runs the covtest userspace binary). 60 s of
execution, clean SIGTERM shutdown so the atexit report fires:

```
ctxdemo: 93 contexts, 137579 context switches
  ctx 0x4b: 2088943001 TB execs (2243 entries)
  ctx 0x40: 126298600 TB execs (1306 entries)
  ...
  ctx 0x00: 48586983 TB execs (68603 entries)
```

Full (truncated) report: `ctxdemo-results-truncated.log`. Context `0x00`
is the kernel/init_mm (68,603 entries — every switch to a kernel thread);
the 93 nonzero PIDs are user address spaces created during boot. This is
exactly the signal Tier 3 of `docs/LINUX-VM.md` needs: per-record context
identity, delivered only at switch time.

## Notes

* The diff applies with `patch -p1` at the root of a qemu-10.2.4 tree
  (verified with `--dry-run` on a pristine copy).
* The callback is delivered from the RPID write in `mmu_write`, i.e.
  before the first TB executes under the new PID — the ordering the RFC
  promises.
* **Not sent anywhere.** Before any qemu-devel posting: re-verify against
  master (the tree there has moved past 10.2), run
  `scripts/get_maintainer.pl`, and fold this into the RFC as a PATCH
  series per the checklist in the RFC draft.
