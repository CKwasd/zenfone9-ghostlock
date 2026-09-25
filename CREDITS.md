# Credits

This project builds on the following public research and projects. All
trademarks and copyrights belong to their respective owners.

## 1. Vulnerability research (CVE-2026-43499 "GhostLock")
- **NebuSec** — original research on CVE-2026-43499 and the **IonStack**
  exploit chain (rtmutex stack-UAF → `rb_erase` constrained write).
  Project: https://github.com/NebuSec/CyberMeowfia
- Linux upstream: the bug is in `kernel/locking/rtmutex.c` (fixed from `5.10.261`).

## 2. Tooling & libraries
- **KernelSU** (tiann and contributors) — https://github.com/tiann/KernelSU
  This project uses its v3.3.0 LKM components (`ksud`, `kernelsu.ko`,
  `ksuinit`, Manager APK). The kallsyms symbol injection inside
  `ksud late-load` (originally `lkmloader`, by 5ec1cff) is what bypasses the
  missing exported symbols.
- **KernelSnitch** — Maar et al., *KernelSnitch: Side-Channel Attacks on
  Kernel Hash Tables*, NDSS 2025. `src/kernelsnitch/` is a port of the
  futex-hash timing side channel.
- **Android NDK** (LLVM/clang) — build toolchain.
- **Ghidra / llvm-objdump** — offline disassembly and offset measurement.

## 3. Write-ups / technical notes
- NebuSec IonStack series (nebusec.ai) — vulnerability and chain mechanics.
- Mallory (mallory.ai) — CVE-2026-43499 entry and path analysis.
- Mobile Hacking Lab — GhostLock port to Samsung Galaxy A17 (exit-path panic).
- OnePlus 13T GhostLock 6.6 adaptation notes (UBSAN_TRAP / CFI observations).
- 5ec1cff — explanation of `lkmloader` and loading modules with unexported symbols.

> If your project is mis-attributed or you want the wording changed, please tell us.

---

# 致謝

本專案站在以下公開研究與專案之上。所有商標與著作權屬原持有者。

## 1. 漏洞研究（CVE-2026-43499 "GhostLock"）
- **NebuSec** — CVE-2026-43499 原始研究與 **IonStack** exploit 鏈（rtmutex stack-UAF → `rb_erase` 受限寫）。
  - 專案：https://github.com/NebuSec/CyberMeowfia
- Linux 核心上游：漏洞於 `kernel/locking/rtmutex.c`（`5.10.261` 起修復）。

## 2. 工具與程式庫
- **KernelSU**（tiann 及貢獻者）— https://github.com/tiann/KernelSU
  - 本專案使用其 v3.3.0 LKM 元件（`ksud`、`kernelsu.ko`、`ksuinit`、Manager APK）。
  - `ksud late-load` 內含的 kallsyms 符號注入（源出 `lkmloader`，作者 5ec1cff）是繞過未匯出符號的關鍵。
- **KernelSnitch** — Maar 等，*KernelSnitch: Side-Channel Attacks on Kernel Hash Tables*, NDSS 2025。
  `src/kernelsnitch/` 為其 futex-hash 時序側信道之移植。
- **Android NDK**（LLVM/clang）— 建置工具鏈。
- **Ghidra / llvm-objdump** — 離線反編譯與偏移量測。

## 3. 寫作／技術筆記
- NebuSec IonStack 系列（nebusec.ai）— 漏洞與鏈的原理。
- Mallory（mallory.ai）— CVE-2026-43499 條目與鏈路分析。
- Mobile Hacking Lab — GhostLock 於 Samsung Galaxy A17 的移植記錄（exit-path panic 觀察）。
- OnePlus 13T GhostLock 6.6 適配筆記（UBSAN_TRAP / CFI 觀察）。
- 5ec1cff — `lkmloader` 與未匯出符號載入之原理說明。

> 若您的專案被誤列或希望調整標註方式，請告知。
