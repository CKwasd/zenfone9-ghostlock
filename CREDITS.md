# Credits

**English** | [繁體中文](CREDITS.zh.md)

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
