/*
 * POSIX port: host test bench.
 *
 * There is no lwIP here, so nothing to hook; frames come in through
 * Tcpdump.inject. A mutex stands in for the critical section so the
 * core keeps its locking discipline when a test drives it from another
 * thread.
 */

#include <pthread.h>
#include <time.h>

#include "../../include/tcpdump.h"

static pthread_mutex_t tcpdump_mutex = PTHREAD_MUTEX_INITIALIZER;

void
tcpdump_port_lock(void)
{
  pthread_mutex_lock(&tcpdump_mutex);
}

void
tcpdump_port_unlock(void)
{
  pthread_mutex_unlock(&tcpdump_mutex);
}

uint32_t
tcpdump_port_uptime_ms(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

void
tcpdump_port_attach(void)
{
}

int
tcpdump_port_hooked_count(void)
{
  return 0;
}
