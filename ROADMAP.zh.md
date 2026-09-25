# 路線圖 — 我們走過什麼、走錯什麼、最終走通什麼

[English](ROADMAP.md) | **繁體中文**

範圍：CVE-2026-43499 (GhostLock) 於 ASUS Zenfone 9（SM8475），GKI
`5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032`，VA39。
目標：root + KernelSU late-load，不改 boot.img。

---

## 最終路線（走通的）

```
perf SAMPLE_IP  -> KASLR（slide）
OWNPROBE        -> 落點（我們的噴塗頁在哪）      [純 userspace]
perf REGS_INTR  -> 自己的 task_struct（E3）
pselect stack_fds 覆蓋 + requeue/proxy walk -> 受限寫
三發： (0) selinux_state = 頁對齊 alias  (1) real_cred = init_cred  (2) cred = init_cred
ksud late-load --kmi android12-5.10 -> KernelSU
```
每次 fresh boot 跑一次；約 3–4 分鐘；不動 boot 分區。

---

## 走過但放棄的路

| # | 路線 | 為何嘗試 | 為何失敗／放棄 |
|---|---|---|---|
| 1 | **Path A：偽造 `file_operations` + CFI `.cfi_jt` 樁** | IonStack 原始形態；可拿通用核心 R/W | fops trigger 依賴真棧 UAF（約 2% 抽獎）；需 CFI 樁；victim 半邊從未走到。非進度瓶頸。 |
| 2 | **SEQPACKET `sendmsg` 堆疊覆蓋**（sabrina 形態） | 確定性覆蓋 waiter | 5.10 的 sockaddr 落在 `W+0x128`，而 `rt_waiter` 在 `sp+0x90` → **無法**覆蓋 waiter。 |
| 3 | **sweep 格網 + walk 讀取定位** | 最初的作法 | 落點逐 boot 漂移 GB 級；死亡格洗牌；一次錯 deref 即 panic（UBSAN_TRAP + PANIC_ON_OOPS）→ 一 boot 一發、無遺言。 |
| 4 | **以 loggers / boot_id 錨點的 walk-slide** | 想避開 perf | 錨點槽位被非同步填充（netd）、無法歸因；walk 讀回垃圾（「common-mode drag」）。後由 perf 取代。 |
| 5 | **KernelSnitch 定位** | 公開且實證 | 可用（mm_struct 洩漏），但相對 `ownprobe` **邊際收益為零**，且 grooming 風險 > sweep 成本。關閉。 |
| 6 | **parent 側 RMW（由 parent 關 SELinux）** | 避開 cred 路徑 | shape-0 語義：`value=0` → NULL deref 死；`value≠0` → 無效；`B` 是唯讀窗口。 |
| 7 | **以 `boot_id` / 毒餌做讀回 oracle** | 判斷寫入是否落地 | 早期有用但雜訊大；後由 `ownprobe` + E4 寫入 oracle 取代。 |

---

## 真正解鎖的關鍵

1. **perf_event_open 未受限**（`perf_event_paranoid=-1`）：
   `SAMPLE_IP` 給出確定性 KASLR slide（5461/5461 樣本），`SAMPLE_REGS_INTR` 自定位 `task_struct`。
   兩個長期問題各用一個 syscall 收掉。
2. **`ownprobe`**：把「這格是不是我的頁？」改成「我的頁在哪？」——在自己的雙映射噴塗頁寫自引用值，
   再從 userspace 掃回。**零核心 deref** → 零死亡。
3. **載具認對**：覆蓋載具是核心的 `pselect6` `stack_fds`（`nfds=320`），不是 SEQPACKET；
   而 5.10 的 `rt_mutex_waiter` 是 10-word flat 佈局。
4. **接受「受限寫就是終點」**：不追求通用 R/W，只做 3 發定向寫。直接砍掉一整段（fops + CFI）。
5. **SELinux 技巧**：被寫入的 `value` 會被 walk deref，必須是安全指標——
   因此改寫**頁對齊 alias**（低位元組 0）進 `selinux_state` 使 `enforcing=0`，而非直接寫 0。
6. **`cred == real_cred`**：兩者同指 `init_cred`，且成功後 **park 不退出**，避開 static cred 的 exit 路徑。
7. **KernelSU `late-load`**：不用 `insmod`（未匯出符號）、不改 boot.img。

---

## 代價最大的教訓（與修法）

- **硬化會放大成本**：`UBSAN_TRAP` + `PANIC_ON_OOPS=1` 讓每次錯指標都變即時重開 → 一實驗一 boot、還沒有崩潰文本。
  修法：durable（fsync）pre-line、離線反編譯、設計**不可能崩**的探針（`ownprobe`）。
- **一個 boot 一次**：同 boot 重跑會落在被攪動的版圖。
- **先驗編碼再 grep**：「零命中」其實是 UTF-16（PowerShell 重導向）假象，曾讓整條推理鏈作廢。
- **量測代替假設**：waiter 偏移、shift、alias 算術、seccomp/SELinux 欄位——每個假設都至少錯過一次。
- **推送紀律**：每次 push 後 md5；靜默失敗的 push 曾浪費一整輪。
- **沒有 panic 通道**（ramoops 只留 pmsg、`/sys/fs/pstore` 被 MAC/DAC 擋）→ 取證昂貴，
  所以偏好「可證明安全」的探針，而不是「炸開再讀」。
