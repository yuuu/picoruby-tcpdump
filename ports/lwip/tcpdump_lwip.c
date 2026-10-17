/*
 * lwIP netif hook, shared by every port that runs lwIP.
 *
 * Not a translation unit of its own: ports/<platform>/tcpdump.c
 * #includes it after pulling in the platform's lwIP headers, then calls
 * tcpdump_lwip_attach_all() from lwIP core context (tcpip thread or with
 * the core lock held).
 *
 * Every Ethernet-type netif (NETIF_FLAG_ETHARP or NETIF_FLAG_ETHERNET,
 * with a linkoutput) gets its input and linkoutput function pointers
 * replaced by wrappers that copy the frame into the capture ring and
 * then call the saved original. The loopback netif has neither flag and
 * is left alone, as is anything that is not Ethernet framed (the pcap
 * is LINKTYPE_ETHERNET).
 *
 * Hooks are never removed: a stopped capture costs one flag test per
 * frame, and not unhooking means there is no window where a driver
 * thread could call through a stale pointer.
 *
 * Define TCPDUMP_LWIP_WEAK_CORE before including when this file may be
 * linked into a firmware whose libmruby lacks the gem (the rp2040 CMake
 * globs every gem's ports/rp2040/); the core entry point then becomes a
 * weak reference.
 */

#include "lwip/netif.h"
#include "lwip/pbuf.h"

#include "../../include/tcpdump.h"

#if defined(TCPDUMP_LWIP_WEAK_CORE)
#pragma weak tcpdump_capture
#endif

#ifndef TCPDUMP_LWIP_MAX_NETIF
#define TCPDUMP_LWIP_MAX_NETIF 4
#endif

typedef struct {
  struct netif *netif;
  netif_input_fn input;
  netif_linkoutput_fn linkoutput;
} tcpdump_lwip_hook_t;

static tcpdump_lwip_hook_t tcpdump_lwip_hooks[TCPDUMP_LWIP_MAX_NETIF];
static int tcpdump_lwip_hook_count;

static tcpdump_lwip_hook_t *
tcpdump_lwip_find(const struct netif *netif)
{
  int n = __atomic_load_n(&tcpdump_lwip_hook_count, __ATOMIC_ACQUIRE);
  int i = 0;
  while (i < n) {
    if (tcpdump_lwip_hooks[i].netif == netif) return &tcpdump_lwip_hooks[i];
    i++;
  }
  return NULL;
}

static void
tcpdump_lwip_copy(void *dst, const void *src, uint32_t offset, uint32_t len)
{
  pbuf_copy_partial((const struct pbuf *)src, dst, (u16_t)len, (u16_t)offset);
}

static void
tcpdump_lwip_record(const struct pbuf *p)
{
#if defined(TCPDUMP_LWIP_WEAK_CORE)
  if (!tcpdump_capture) return;
#endif
  if (p == NULL) return;
  tcpdump_capture(p, p->tot_len, tcpdump_lwip_copy);
}

static err_t
tcpdump_lwip_input(struct pbuf *p, struct netif *netif)
{
  tcpdump_lwip_hook_t *h = tcpdump_lwip_find(netif);
  if (h == NULL || h->input == NULL) return ERR_IF;  /* caller frees p */
  tcpdump_lwip_record(p);
  return h->input(p, netif);
}

static err_t
tcpdump_lwip_linkoutput(struct netif *netif, struct pbuf *p)
{
  tcpdump_lwip_hook_t *h = tcpdump_lwip_find(netif);
  if (h == NULL || h->linkoutput == NULL) return ERR_IF;
  tcpdump_lwip_record(p);
  return h->linkoutput(netif, p);
}

static bool
tcpdump_lwip_hookable(const struct netif *netif)
{
  if ((netif->flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET)) == 0) return false;
  if (netif->input == NULL || netif->linkoutput == NULL) return false;
  return true;
}

/* lwIP core context only. Returns the number of netifs hooked. */
static int
tcpdump_lwip_attach_all(void)
{
  struct netif *netif;
  tcpdump_lwip_hook_t *h;
  int n;

  NETIF_FOREACH(netif) {
    if (!tcpdump_lwip_hookable(netif)) continue;
    h = tcpdump_lwip_find(netif);
    if (h == NULL) {
      n = tcpdump_lwip_hook_count;
      if (TCPDUMP_LWIP_MAX_NETIF <= n) break;
      h = &tcpdump_lwip_hooks[n];
      h->netif = netif;
      h->input = netif->input;
      h->linkoutput = netif->linkoutput;
      /* Entry complete before anyone can find it ... */
      __atomic_store_n(&tcpdump_lwip_hook_count, n + 1, __ATOMIC_RELEASE);
    } else {
      /* Known netif: a driver may have re-initialized it (netif_remove +
         netif_add reuses the struct) and put its own functions back. */
      if (netif->input != tcpdump_lwip_input) h->input = netif->input;
      if (netif->linkoutput != tcpdump_lwip_linkoutput) h->linkoutput = netif->linkoutput;
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
    /* ... and the wrappers go live only after the entry is. */
    netif->input = tcpdump_lwip_input;
    netif->linkoutput = tcpdump_lwip_linkoutput;
  }
  return tcpdump_lwip_hook_count;
}

int
tcpdump_port_hooked_count(void)
{
  return __atomic_load_n(&tcpdump_lwip_hook_count, __ATOMIC_ACQUIRE);
}
