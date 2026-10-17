#ifndef PICORUBY_TCPDUMP_H_
#define PICORUBY_TCPDUMP_H_

/*
 * picoruby-tcpdump: packet capture into a RAM ring, drained to a pcap
 * file from the VM thread.
 *
 * Layers:
 *   src/ring.c         VM- and network-stack-agnostic core: the ring of
 *                      ready-made pcap records, stats, pcap header.
 *   ports/lwip/        lwIP netif hook (wraps netif->input/linkoutput).
 *                      Not compiled on its own: ports/esp32 and
 *                      ports/rp2040 #include it.
 *   ports/<platform>/  lock, clock, and "find the netifs and hook them".
 *
 * Threads: tcpdump_capture() may be called from any thread or ISR-like
 * context (lwIP tcpip thread, Wi-Fi driver task, cyw43 background IRQ)
 * at the same time. Producers serialize through tcpdump_port_lock().
 * The consumer (tcpdump_ring_peek/read, VM thread only) never takes the
 * lock while copying: producers only ever write the free region and the
 * consumer only reads the used one, so the indices are enough.
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCPDUMP_PCAP_MAGIC            0xa1b2c3d4u  /* microsecond timestamps */
#define TCPDUMP_PCAP_VERSION_MAJOR    2
#define TCPDUMP_PCAP_VERSION_MINOR    4
#define TCPDUMP_LINKTYPE_ETHERNET     1
#define TCPDUMP_GLOBAL_HEADER_SIZE    24
#define TCPDUMP_RECORD_HEADER_SIZE    16

#define TCPDUMP_SNAPLEN_MIN           16
#define TCPDUMP_SNAPLEN_MAX           65535
#define TCPDUMP_RING_SIZE_MIN         1024
#define TCPDUMP_RING_SIZE_MAX         (1u << 20)

#ifndef TCPDUMP_DEFAULT_SNAPLEN
#define TCPDUMP_DEFAULT_SNAPLEN       128
#endif
#ifndef TCPDUMP_DEFAULT_RING_SIZE
#define TCPDUMP_DEFAULT_RING_SIZE     16384
#endif

/* Copies `len` bytes starting at byte `offset` of the frame `src` into
 * `dst`. Lets a producer hand over a scattered buffer (lwIP pbuf chain)
 * without flattening it first. */
typedef void (*tcpdump_copy_fn)(void *dst, const void *src, uint32_t offset, uint32_t len);

typedef struct {
  uint32_t captured;   /* records stored in the ring */
  uint32_t dropped;    /* frames lost because the ring was full */
  uint32_t bytes;      /* sum of orig_len of captured frames (wraps) */
  uint32_t ring_size;
  uint32_t snaplen;
} tcpdump_stats_t;

/* ---- core (src/ring.c) ---- */

/* (Re)allocate the ring and start accepting frames. ring_size is rounded
 * down to a power of two. Clears stats and any buffered data. VM thread. */
bool tcpdump_ring_start(uint32_t ring_size, uint32_t snaplen);
/* Stop accepting frames; buffered data stays readable. */
void tcpdump_ring_stop(void);
/* Stop and release the ring. */
void tcpdump_ring_free(void);
bool tcpdump_ring_capturing(void);

/* Producer side; any thread. Returns false when not capturing or when
 * the frame was dropped. */
bool tcpdump_capture(const void *src, uint32_t orig_len, tcpdump_copy_fn copy);
bool tcpdump_capture_bytes(const uint8_t *data, uint32_t len);

/* Consumer side; VM thread only. */
uint32_t tcpdump_ring_pending(void);
/* Number of bytes taken up by the leading whole records that together
 * fit in max_bytes (0 if the first record alone does not fit). */
uint32_t tcpdump_ring_peek(uint32_t max_bytes);
/* Copy out and consume `len` bytes; `len` must come from tcpdump_ring_peek. */
void tcpdump_ring_read(uint8_t *dst, uint32_t len);
/* Throw away everything buffered. */
void tcpdump_ring_discard(void);

void tcpdump_ring_stats(tcpdump_stats_t *out);
void tcpdump_pcap_global_header(uint8_t out[TCPDUMP_GLOBAL_HEADER_SIZE], uint32_t snaplen);

/* Rate-limited netif discovery for the VM thread (scheduler service and
 * Tcpdump.flush). Calls tcpdump_port_attach() at most every
 * TCPDUMP_ATTACH_INTERVAL_MS while capturing. */
#ifndef TCPDUMP_ATTACH_INTERVAL_MS
#define TCPDUMP_ATTACH_INTERVAL_MS 200
#endif
void tcpdump_attach_poll(bool force);

/* ---- port (ports/<platform>/tcpdump.c) ---- */

/* Short critical section around the producer path. Must be usable from
 * every context tcpdump_capture() is called from; never nested. */
void tcpdump_port_lock(void);
void tcpdump_port_unlock(void);
/* Monotonic milliseconds; only differences are used. */
uint32_t tcpdump_port_uptime_ms(void);
/* Find interfaces not hooked yet and hook them. Called from the VM
 * thread; must not block (defer to the network stack's thread if
 * needed). Idempotent. */
void tcpdump_port_attach(void);
/* Number of interfaces currently hooked. */
int tcpdump_port_hooked_count(void);

#ifdef __cplusplus
}
#endif

#endif /* PICORUBY_TCPDUMP_H_ */
