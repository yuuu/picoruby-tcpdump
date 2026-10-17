/*
 * Capture ring: a byte ring that holds finished pcap records
 * (16-byte record header + up to snaplen bytes of frame), so draining is
 * a plain copy to the file.
 *
 * Indices are free-running uint32 counters; the ring size is a power of
 * two so `counter & mask` stays continuous across the 2^32 wrap.
 *
 *   head  advanced by producers, under tcpdump_port_lock()
 *   tail  advanced by the single consumer (VM thread), lock-free
 *
 * A producer reserves and fills [head, head+n) entirely inside the lock
 * and publishes head with release semantics, so the consumer, which
 * loads head with acquire, only ever sees whole records.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "../include/tcpdump.h"

static uint8_t *ring_buf;
static uint32_t ring_mask;      /* size - 1; 0 when no ring */
static uint32_t ring_head;
static uint32_t ring_tail;
static uint32_t ring_snaplen = TCPDUMP_DEFAULT_SNAPLEN;
static volatile bool ring_enabled;

static uint32_t stat_captured;
static uint32_t stat_dropped;
static uint32_t stat_bytes;

static uint32_t last_attach_ms;
static bool attach_polled;

static inline uint32_t
load_acquire(const uint32_t *p)
{
  return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void
store_release(uint32_t *p, uint32_t v)
{
  __atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static uint32_t
round_down_pow2(uint32_t v)
{
  uint32_t p = 1;
  while (p <= v / 2) p <<= 1;
  return p;
}

bool
tcpdump_ring_start(uint32_t ring_size, uint32_t snaplen)
{
  uint8_t *old;
  uint8_t *buf;

  if (ring_size < TCPDUMP_RING_SIZE_MIN) ring_size = TCPDUMP_RING_SIZE_MIN;
  if (TCPDUMP_RING_SIZE_MAX < ring_size) ring_size = TCPDUMP_RING_SIZE_MAX;
  ring_size = round_down_pow2(ring_size);
  if (snaplen < TCPDUMP_SNAPLEN_MIN) snaplen = TCPDUMP_SNAPLEN_MIN;
  if (TCPDUMP_SNAPLEN_MAX < snaplen) snaplen = TCPDUMP_SNAPLEN_MAX;

  if (ring_buf && ring_mask + 1 == ring_size) {
    buf = NULL; /* reuse */
  } else {
    buf = (uint8_t *)malloc(ring_size);
    if (!buf) return false;
  }

  tcpdump_port_lock();
  ring_enabled = false;
  if (buf) {
    old = ring_buf;
    ring_buf = buf;
    ring_mask = ring_size - 1;
  } else {
    old = NULL;
  }
  ring_head = 0;
  ring_tail = 0;
  ring_snaplen = snaplen;
  stat_captured = 0;
  stat_dropped = 0;
  stat_bytes = 0;
  ring_enabled = true;
  tcpdump_port_unlock();

  /* Outside the lock: nobody can reach `old` any more. */
  if (old) free(old);
  attach_polled = false;
  return true;
}

void
tcpdump_ring_stop(void)
{
  tcpdump_port_lock();
  ring_enabled = false;
  tcpdump_port_unlock();
}

void
tcpdump_ring_free(void)
{
  uint8_t *old;

  tcpdump_port_lock();
  ring_enabled = false;
  old = ring_buf;
  ring_buf = NULL;
  ring_mask = 0;
  ring_head = 0;
  ring_tail = 0;
  tcpdump_port_unlock();
  if (old) free(old);
}

bool
tcpdump_ring_capturing(void)
{
  return ring_enabled;
}

/* Copy `len` bytes into the ring at counter position `pos`, splitting at
 * the physical end. Caller holds the lock. */
static void
ring_put(uint32_t pos, const void *src, uint32_t len)
{
  uint32_t off = pos & ring_mask;
  uint32_t first = ring_mask + 1 - off;
  if (len <= first) {
    memcpy(ring_buf + off, src, len);
  } else {
    memcpy(ring_buf + off, src, first);
    memcpy(ring_buf, (const uint8_t *)src + first, len - first);
  }
}

static void
ring_get(uint32_t pos, void *dst, uint32_t len)
{
  uint32_t off = pos & ring_mask;
  uint32_t first = ring_mask + 1 - off;
  if (len <= first) {
    memcpy(dst, ring_buf + off, len);
  } else {
    memcpy(dst, ring_buf + off, first);
    memcpy((uint8_t *)dst + first, ring_buf, len - first);
  }
}

bool
tcpdump_capture(const void *src, uint32_t orig_len, tcpdump_copy_fn copy)
{
  struct timeval tv;
  uint32_t hdr[4];
  uint32_t caplen;
  uint32_t need;
  uint32_t head;
  uint32_t off;
  uint32_t first;
  bool ok = false;

  if (!ring_enabled) return false;  /* cheap early-out; rechecked below */

  /* Before NTP sync this is time since boot (epoch 1970), which is the
   * uptime-based fallback; afterwards it is wall-clock time. */
  gettimeofday(&tv, NULL);

  tcpdump_port_lock();
  if (!ring_enabled || ring_buf == NULL) goto out;
  caplen = orig_len < ring_snaplen ? orig_len : ring_snaplen;
  need = TCPDUMP_RECORD_HEADER_SIZE + caplen;
  head = ring_head;
  if (ring_mask + 1 - (head - load_acquire(&ring_tail)) < need) {
    stat_dropped++;
    goto out;
  }
  hdr[0] = (uint32_t)tv.tv_sec;
  hdr[1] = (uint32_t)tv.tv_usec;
  hdr[2] = caplen;
  hdr[3] = orig_len;
  ring_put(head, hdr, TCPDUMP_RECORD_HEADER_SIZE);
  off = (head + TCPDUMP_RECORD_HEADER_SIZE) & ring_mask;
  first = ring_mask + 1 - off;
  if (caplen <= first) {
    copy(ring_buf + off, src, 0, caplen);
  } else {
    copy(ring_buf + off, src, 0, first);
    copy(ring_buf, src, first, caplen - first);
  }
  store_release(&ring_head, head + need);
  stat_captured++;
  stat_bytes += orig_len;
  ok = true;
out:
  tcpdump_port_unlock();
  return ok;
}

static void
copy_flat(void *dst, const void *src, uint32_t offset, uint32_t len)
{
  memcpy(dst, (const uint8_t *)src + offset, len);
}

bool
tcpdump_capture_bytes(const uint8_t *data, uint32_t len)
{
  return tcpdump_capture(data, len, copy_flat);
}

uint32_t
tcpdump_ring_pending(void)
{
  if (ring_buf == NULL) return 0;
  return load_acquire(&ring_head) - ring_tail;
}

uint32_t
tcpdump_ring_peek(uint32_t max_bytes)
{
  uint32_t head;
  uint32_t pos;
  uint32_t total = 0;
  uint32_t caplen;
  uint32_t rec;

  if (ring_buf == NULL) return 0;
  head = load_acquire(&ring_head);
  pos = ring_tail;
  while (pos != head) {
    ring_get(pos + 8, &caplen, 4);  /* incl_len */
    rec = TCPDUMP_RECORD_HEADER_SIZE + caplen;
    if (max_bytes - total < rec) break;
    total += rec;
    pos += rec;
  }
  return total;
}

void
tcpdump_ring_read(uint8_t *dst, uint32_t len)
{
  if (ring_buf == NULL || len == 0) return;
  ring_get(ring_tail, dst, len);
  store_release(&ring_tail, ring_tail + len);
}

void
tcpdump_ring_discard(void)
{
  if (ring_buf == NULL) return;
  store_release(&ring_tail, load_acquire(&ring_head));
}

void
tcpdump_ring_stats(tcpdump_stats_t *out)
{
  tcpdump_port_lock();
  out->captured = stat_captured;
  out->dropped = stat_dropped;
  out->bytes = stat_bytes;
  out->ring_size = ring_buf ? ring_mask + 1 : 0;
  out->snaplen = ring_snaplen;
  tcpdump_port_unlock();
}

static void
put_u32(uint8_t *p, uint32_t v)
{
  /* Native byte order: the magic tells the reader which one it is. */
  memcpy(p, &v, 4);
}

static void
put_u16(uint8_t *p, uint16_t v)
{
  memcpy(p, &v, 2);
}

void
tcpdump_pcap_global_header(uint8_t out[TCPDUMP_GLOBAL_HEADER_SIZE], uint32_t snaplen)
{
  put_u32(out + 0, TCPDUMP_PCAP_MAGIC);
  put_u16(out + 4, TCPDUMP_PCAP_VERSION_MAJOR);
  put_u16(out + 6, TCPDUMP_PCAP_VERSION_MINOR);
  put_u32(out + 8, 0);    /* thiszone */
  put_u32(out + 12, 0);   /* sigfigs */
  put_u32(out + 16, snaplen);
  put_u32(out + 20, TCPDUMP_LINKTYPE_ETHERNET);
}

void
tcpdump_attach_poll(bool force)
{
  uint32_t now;

  if (!ring_enabled) return;
  now = tcpdump_port_uptime_ms();
  if (!force && attach_polled && (uint32_t)(now - last_attach_ms) < TCPDUMP_ATTACH_INTERVAL_MS) {
    return;
  }
  attach_polled = true;
  last_attach_ms = now;
  tcpdump_port_attach();
}
