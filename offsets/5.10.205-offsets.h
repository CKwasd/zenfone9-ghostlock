/* 5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032
 * ASUS Zenfone 9 (SM8475, ASUS_AI2202), GKI android12-5.10, VA39.
 *
 * Layout is the 5.10 FLAT rt_mutex_waiter (no per-tree prio/deadline,
 * no wake_state/ww_ctx):  tree(0x0) pi_tree(0x18) task(0x30) lock(0x38)
 * prio(0x40) deadline(0x48)  -> 10 words.  Use .compact_waiter = 2 and
 * STRUCT_OFFSETS_5_10; a consumer must implement the 5.10 waiter word set
 * (word10 = plain prio, no ww_ctx) because the 6.1 "compact" branch encodes
 * that word as (prio<<32)|3, which on 5.10 would put 3 into prio.
 *
 * All off_* are image-relative (link address - KIMAGE_TEXT_BASE), verified
 * against the shipped kernel.elf .symtab.  kernel_phys_load = P0_PHYS_OFFSET
 * (0x80000000) + XBL Kernel load delta (0x28000000) = 0xA8000000.
 */

OFFSETS_ENTRY(
    "5.10.205-android12-9-00029-g3f12df86bfdb-ab11799032",
    STRUCT_OFFSETS_5_10,
    .kernel_phys_load = 0xA8000000,
    .pselect_waiter_shift = 0,          /* measured in-guest: waiter == stack_fds */
    .off_init_task = 0x0279BEC0,
    .off_init_cred = 0x027B0AE0,
    .off_root_task_group = 0x02991040,
    .off_selinux_enforcing = 0x02A40B98,      /* selinux_state; enforcing @ +0 */
    .off_selinux_blob_sizes = 0x022EAAF8,
    .off_security_hook_heads = 0x022EA468,
    .off_slide_nfulnl_logger = 0x027913A0,
    .off_slide_loggers_0_1 = 0x027912D0,
    .off_slide_boot_id = 0x028A76D0,
),
