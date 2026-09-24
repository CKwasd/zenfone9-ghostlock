# Credits / 致謝

本專案站在以下公開研究與專案之上。所有商標與著作權屬原持有者。

## 1. 漏洞研究（CVE-2026-43499 "GhostLock"）
- **NebuSec** — CVE-2026-43499 原始研究與 **IonStack** exploit 鏈（rtmutex stack-UAF → `rb_erase` 受限寫）。
  - 專案：https://github.com/NebuSec/CyberMeowfia （與其公開寫作）
- Linux 核心上游：漏洞於 `kernel/locking/rtmutex.c`（`5.10.261` 起修復）。

## 2. 參考實作／移植（本專案直接參考）
| 專案 | 用途 |
|---|---|
| https://github.com/k-o-n-t-o-r/ghostlock-sabrina | arm64 Android 純 cred 路線、SEQPACKET overlay（5.15） |
| https://github.com/pubglite55/oppo-ghostlock | 同世代 5.10.236 移植、KernelSnitch、pipe/fops 參考 |
| https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis | PoC 分析 |
| https://github.com/x-spy/CVE-2026-43499-popsicle | 移植工具鏈參考 |
| https://github.com/hmascs/KSuRoot | KernelSU late-load / APK 整合參考 |
| https://github.com/NebuSec/CyberMeowfia | IonStack 原版（S22U 等機型） |

## 3. 工具與程式庫
- **KernelSU**（tiann 及貢獻者）— https://github.com/tiann/KernelSU
  - 本專案使用其 v3.3.0 LKM 元件（`ksud`、`kernelsu.ko`、`ksuinit`、Manager APK）。
  - `ksud late-load` 內含的 kallsyms 符號注入（源出 `lkmloader`，作者 5ec1cff）是繞過未匯出符號的關鍵。
- **KernelSnitch** — Maar 等，*KernelSnitch: Side-Channel Attacks on Kernel Hash Tables*, NDSS 2025。
  本專案 `src/kernelsnitch/` 為其 futex-hash 時序側信道之移植（來源經 oppo-ghostlock / mt6985 系列移植）。
- **Android NDK**（LLVM/clang）— 建置工具鏈。
- **Ghidra / llvm-objdump** — 離線反編譯與偏移量測。

## 4. 寫作／技術筆記
- NebuSec IonStack 系列（nebusec.ai）— 漏洞與鏈的原理。
- Mallory（mallory.ai）— CVE-2026-43499 條目與鏈路分析。
- Mobile Hacking Lab — GhostLock 於 Samsung Galaxy A17 的移植記錄（exit-path panic 觀察）。
- OnePlus 13T GhostLock 6.6 適配筆記（UBSAN_TRAP / CFI 觀察）。
- 5ec1cff — `lkmloader` 與未匯出符號載入之原理說明。

## 5. 本專案自身貢獻
- Zenfone 9（SM8475, GKI `5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`, VA39）之完整鏈：
  - 5.10 flat `rt_mutex_waiter` 佈局與 `pselect6 stack_fds` 覆蓋（`shift=0`）。
  - `ownprobe`（delta-free 自寫探針，零 walk 死亡定位）。
  - `perf SAMPLE_IP` 解 KASLR、`PERF_SAMPLE_REGS_INTR` 自定位 `task_struct`。
  - `shortseq` 三發寫（關 SELinux 使用頁對齊 alias；`real_cred`/`cred` 同指 `init_cred`）。
  - `ksud late-load` 免改 boot.img 的 KernelSU 工具化 root。
  - 5.10.205 偏移量表（`offsets/`）。

> 若您的專案被誤列或希望調整標註方式，請告知。
