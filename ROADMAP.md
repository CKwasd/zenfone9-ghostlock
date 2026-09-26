# Roadmap — what we tried, what went wrong, what finally worked

**English** | [繁體中文](ROADMAP.zh.md)

Scope: CVE-2026-43499 (GhostLock) on ASUS Zenfone 9 (SM8475), GKI
`5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`, VA39.
Goal: root + KernelSU late-load, no boot.img change.

---

## Final route (what works)

```
perf SAMPLE_IP  -> KASLR (slide)
OWNPROBE        -> placement (where our spray page is)   [userspace only]
perf REGS_INTR  -> own task_struct (self-location)
pselect stack_fds overlay + requeue/proxy walk -> constrained write
3 writes:  (0) selinux_state = page-aligned alias  (1) real_cred = init_cred  (2) cred = init_cred
ksud late-load --kmi android12-5.10 -> KernelSU
```
Run once per fresh boot; ~3-4 minutes; no boot partition change.

---

## Routes attempted, and why they were abandoned

| # | Route | Why we tried | Why it failed / was dropped |
|---|---|---|---|
| 1 | **Path A: fake `file_operations` hijack + CFI `.cfi_jt` stubs** | Original IonStack shape; would give general kernel R/W | The fops trigger relies on the true-stack UAF (a lottery, ~2%); CFI needed stubs; the second half of the chain was never reached. Not the root cause of progress. |
| 2 | **SEQPACKET `sendmsg` stack overlay** (sabrina shape) | Deterministic waiter overwrite | On 5.10 the sockaddr lands at `W+0x128`, but the `rt_waiter` is at `sp+0x90` → it **cannot** cover the waiter. |
| 3 | **sweep grid + walk read for placement** | First-principles start | Per-boot GB-scale placement drift; cells that fault shift around; every wrong deref = panic (UBSAN_TRAP + PANIC_ON_OOPS) → one boot per attempt, no diagnostics. |
| 4 | **Walk-based slide via loggers / boot_id anchors** | Avoid perf | Anchor slots were filled asynchronously (netd) and non-attributable; walked reads returned garbage that moved with the same bias. Replaced by perf. |
| 5 | **KernelSnitch for placement** | Public, proven | It worked (mm_struct leak), but gave **zero marginal gain** over `ownprobe`, and grooming risk > sweep cost. Closed. |
| 6 | **Parent-side RMW (turn SELinux off from the parent)** | Avoid taking the cred path | shape-0 semantics: `value=0` → NULL deref death; `value≠0` → no effect; `B` is a read-only window. |
| 7 | **Read-back oracles via `boot_id` / poison bait** | Detect whether a write landed | Useful early, but noisy; superseded by `ownprobe` + a write oracle. |

---

## What actually unblocked it

1. **perf_event_open was unrestricted** (`perf_event_paranoid=-1`):
   `SAMPLE_IP` gave a deterministic KASLR slide (5461/5461 samples), and
   `SAMPLE_REGS_INTR` self-located `task_struct`. Two long-running problems
   collapsed to one syscall each.
2. **`ownprobe`**: reframed "is this candidate page mine?" into "where is my page?"
   by writing a self-referential value into our own double-mapped spray and
   scanning it from userspace. Placement with **zero kernel deref** → no deaths.
3. **Correct carrier identification**: the overwrite carrier is the kernel's
   `pselect6` `stack_fds` copy (`nfds=320`), not SEQPACKET; and 5.10's
   `rt_mutex_waiter` is a 10-word flat layout.
4. **Accepting the constrained write as the endpoint**: no arbitrary R/W, just
   3 targeted writes. Removed an entire stage (fops + CFI).
5. **The SELinux trick**: the written `value` is dereferenced by the walk, so it
   must be a safe pointer — hence writing a **page-aligned alias** (low byte 0)
   into `selinux_state` to make `enforcing = 0`, instead of writing literal 0.
6. **`cred == real_cred`**: point both at `init_cred`, and **park** instead of
   exiting to avoid the static-cred exit path.
7. **KernelSU `late-load`** instead of `insmod` (unexported symbols) and instead
   of patching boot.img.

---

## Lessons that cost us the most (and the fixes)

- **Hardening multiplies cost.** `UBSAN_TRAP` + `PANIC_ON_OOPS=1` turn every
  wrong pointer into an instant reboot, so one experiment = one boot and you get
  no crash text. Fix: durable (fsync'd) pre-lines, offline disassembly, and
  designing probes that cannot crash (`ownprobe`).
- **One boot, one launch.** Re-running in the same boot lands on a disturbed map.
- **Verify before you grep.** A "zero results" scan was a UTF-16 artifact
  (PowerShell redirect) that invalidated a whole line of reasoning.
- **Measure, don't assume.** The waiter offset, the shift, the alias arithmetic,
  the seccomp/SELinux field offsets — each assumption was wrong at least once.
- **Push hygiene**: md5 after every push; a silently failed push wasted a run.
- **No panic channel** (ramoops pmsg-only, `/sys/fs/pstore` MAC/DAC-blocked) made
  forensics expensive → prefer provably-safe probes over crash-and-read.
