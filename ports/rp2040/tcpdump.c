/*
 * RP2040/RP2350 port (pico-sdk, cyw43 + lwIP on Pico W / Pico 2 W).
 *
 * picoruby-r2p2's CMake compiles every gem's ports/rp2040 sources whether or
 * not the gem is in the build, so the lwIP side references the core
 * weakly (TCPDUMP_LWIP_WEAK_CORE) and only exists with USE_WIFI.
 *
 * cyw43_arch runs lwIP either from the VM thread (poll) or from a
 * low-priority IRQ (threadsafe_background); disabling interrupts covers
 * both for the producer critical section. Hooking happens inside
 * cyw43_arch_lwip_begin/end.
 */

#include <stdbool.h>
#include <stdint.h>

#include "pico/time.h"
#include "hardware/sync.h"

#include "../../include/tcpdump.h"

static uint32_t tcpdump_irq_state;

void
tcpdump_port_lock(void)
{
  tcpdump_irq_state = save_and_disable_interrupts();
}

void
tcpdump_port_unlock(void)
{
  restore_interrupts(tcpdump_irq_state);
}

uint32_t
tcpdump_port_uptime_ms(void)
{
  return to_ms_since_boot(get_absolute_time());
}

#if defined(USE_WIFI)

#include "pico/cyw43_arch.h"

#define TCPDUMP_LWIP_WEAK_CORE 1
#include "../lwip/tcpdump_lwip.c"

void
tcpdump_port_attach(void)
{
  /* Before CYW43.init there is no lwIP to look at. */
  if (cyw43_arch_async_context() == NULL) return;
  cyw43_arch_lwip_begin();
  tcpdump_lwip_attach_all();
  cyw43_arch_lwip_end();
}

#else

void
tcpdump_port_attach(void)
{
}

int
tcpdump_port_hooked_count(void)
{
  return 0;
}

#endif
