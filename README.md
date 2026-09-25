# GhostLock (CVE-2026-43499) — ASUS Zenfone 9 exploit + KernelSU late-load

> **Authorized research on your own device only.** Do not use on devices you
> do not own. Kernel exploits can crash or brick a device; use at your own risk.

Get root on an **ASUS Zenfone 9 (SM8475, ASUS_AI2202)**, GKI
`5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`, VA39, via
CVE-2026-43499, and finish with **KernelSU LKM late-load**.
**No boot.img / init_boot.img modification.**

---

## Quick start

```sh
# 1) Fetch KernelSU components (or use the bundled ksu/ if present)
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
│   └── TUTORIAL.md          # full reproduction guide
├── ROADMAP_en.md            # what we tried, what went wrong, final path
└── ROADMAP_zh.md
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

See `CREDITS.md`.

---
---

# GhostLock (CVE-2026-43499) — ASUS Zenfone 9 提權 + KernelSU late-load

> **僅限自有裝置授權研究。** 請勿用於非授權裝置。核心 exploit 可能導致當機或變磚，風險自負。

在 **ASUS Zenfone 9（SM8475，ASUS_AI2202）**、GKI `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`、
VA39 上，透過 CVE-2026-43499 取得 root，並以 **KernelSU LKM late-load** 完成工具化 root。
**全程不修改 boot.img / init_boot.img。**

## 快速開始

```sh
# 1) 取得 KernelSU 元件（或使用 repo 內已附的 ksu/）
sh scripts/fetch-ksu.sh

# 2) 編譯（需 Android NDK r27+ 的 aarch64-linux-android31-clang）
sh build.sh          # 產出 ./slide_dev

# 3) 每次 fresh boot 跑一次；約 3–4 分鐘
ADB="path/to/adb" sh run.sh

# 4) 驗證
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

## 檔案結構

```
zf9-ghostlock/
├── build.sh                 # 編譯 slide_dev
├── run.sh                   # push + 啟動 + 提示驗證
├── Makefile
├── src/                     # exploit 原始碼（slide_dev）
│   ├── main.c util.c slide.c fops.c pipe.c persist.c
│   ├── prop.c cfi.c qmain.c seqoverlay.c
│   ├── common.h target.h offset.h
│   └── kernelsnitch/        # KernelSnitch（mm_struct 洩漏）
├── scripts/fetch-ksu.sh     # 下載 KernelSU v3.3.0 元件
├── ksu/                     # ksud / kernelsu.ko / ksuinit / ksu.apk（gitignore）
├── offsets/                 # 5.10.205 偏移量表（見下）
├── docs/
│   └── TUTORIAL.md          # 完整重現教學
├── ROADMAP_en.md            # 走過的路、走錯的路、最終的路
└── ROADMAP_zh.md
```

## 一鍵配方

```sh
./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq
```
| token | 意義 |
|---|---|
| `0x28000000` | 本機 delta（XBL Kernel 載入位址 0xA8000000 − P0_PHYS_OFFSET 0x80000000） |
| `persist` | exploit 主路徑 |
| `noslide` / `neutral` | 略過舊 walk-slide；頁面中性化 |
| `sweep 64` | 噴塗候選輪 |
| `sweepstart=25` | 從歷史黏性落點（phys 0xaccd7000）開始 |
| `ownprobe` | 純 userspace 自寫探針（零 walk 死亡） |
| `shortseq` | 迷你三發：關 SELinux → `real_cred`/`cred` = `init_cred` |

成功後：`uid=0` → 自動 `ksud late-load --kmi android12-5.10 --allow-shell` → KernelSU。

## 需要知道的事

- **一個 boot 一次**：每次開機後落點與 KASLR 皆新；同 boot 重跑會落在被攪動的記憶體版圖上。
- **LKM 為 per-boot**：重開機後 KernelSU 消失，需重跑 `run.sh`（不改 boot.img 就無法開機自動載入）。
- **不要 `insmod kernelsu.ko`**：會因 ~40 個未匯出符號失敗；必須用 `ksud late-load`。
- 詳細原理與疑難排解見 `docs/TUTORIAL.md`。

## offsets/

`offsets/` 內含本核心的偏移量表，供支援多核心 offsets / runtime JSON 匯入的框架使用：
- `offsets-5.10.205.json` — runtime JSON 格式（`symbols` + `struct_fields`）。
- `5.10.205-offsets.h` — C 標頭格式（`STRUCT_OFFSETS_5_10` entry）。

注意：5.10 的 `rt_mutex_waiter` 為 **10-word flat** 佈局（`tree/pi_tree/task/lock/prio/deadline`），
與 6.1/6.6 皆不同；消費端需對應的 waiter 分支（word10 = 純 prio、無 `ww_ctx`）。

## License

MIT（見 `LICENSE`）。**僅供授權之安全研究。**

## Credits

見 `CREDITS.md`。
