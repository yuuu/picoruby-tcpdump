/*
 * ESP32 port (ESP-IDF v5, lwIP from the lwip component).
 *
 * Frames reach the hooks from two contexts: the Wi-Fi / Ethernet driver
 * task (netif->input, i.e. wlanif_input/ethernetif_input calling
 * tcpip_input) and the tcpip thread (netif->linkoutput), possibly on the
 * other core. A spinlock critical section serializes them; it is held
 * only for a header write plus a snaplen-bounded memcpy.
 *
 * Hooking walks netif_list and rewrites netif fields, which belongs in
 * the tcpip thread: tcpdump_port_attach() posts the walk there with
 * tcpip_try_callback(), which never blocks the VM thread. It is a no-op
 * until esp_netif has created an interface -- before esp_netif_init()
 * there is no tcpip thread to post to. Which interfaces exist does not
 * matter: Wi-Fi STA/AP and Ethernet (including QEMU's openeth) are all
 * picked up, loopback is not.
 *
 * Requires the IDF components esp_netif, lwip and esp_timer.
 */

#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "lwip/tcpip.h"

/* Weak, so the file links even into a firmware whose libmruby was
   built without the gem (e.g. the femtoruby VM): nothing calls
   tcpdump_port_attach() then, so no hook is ever installed. */
#define TCPDUMP_LWIP_WEAK_CORE 1
#include "../lwip/tcpdump_lwip.c"

static portMUX_TYPE tcpdump_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool tcpdump_attach_pending;

void
tcpdump_port_lock(void)
{
  /* _SAFE: also correct if a driver ever calls in from an ISR. */
  portENTER_CRITICAL_SAFE(&tcpdump_mux);
}

void
tcpdump_port_unlock(void)
{
  portEXIT_CRITICAL_SAFE(&tcpdump_mux);
}

uint32_t
tcpdump_port_uptime_ms(void)
{
  return (uint32_t)(esp_timer_get_time() / 1000);
}

static void
tcpdump_esp32_attach_cb(void *ctx)
{
  (void)ctx;
  tcpdump_lwip_attach_all();
  tcpdump_attach_pending = false;
}

void
tcpdump_port_attach(void)
{
  if (esp_netif_get_nr_of_ifs() == 0) return;
  if (tcpdump_attach_pending) return;
  tcpdump_attach_pending = true;
  if (tcpip_try_callback(tcpdump_esp32_attach_cb, NULL) != ERR_OK) {
    tcpdump_attach_pending = false;  /* mbox full; retry next poll */
  }
}
