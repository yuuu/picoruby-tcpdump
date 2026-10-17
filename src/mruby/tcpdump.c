#include <mruby.h>
#include <mruby/array.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#if defined(MRB_USE_TASK_SCHEDULER)
/* Spelled out: picoruby-mruby/include/hal.h shadows this one on the
   include path. */
#include "picoruby-machine/include/hal.h"
#endif

static mrb_value
int_value(mrb_state *mrb, uint32_t v)
{
  if ((uint64_t)MRB_INT_MAX < (uint64_t)v) return mrb_int_value(mrb, MRB_INT_MAX);
  return mrb_int_value(mrb, (mrb_int)v);
}

/*
 * Tcpdump.__start(snaplen, ring_size) -> true/false
 */
static mrb_value
mrb_tcpdump_s_start(mrb_state *mrb, mrb_value self)
{
  mrb_int snaplen, ring_size;
  mrb_get_args(mrb, "ii", &snaplen, &ring_size);
  if (snaplen < TCPDUMP_SNAPLEN_MIN || TCPDUMP_SNAPLEN_MAX < snaplen) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "snaplen must be %d..%d",
               (int)TCPDUMP_SNAPLEN_MIN, (int)TCPDUMP_SNAPLEN_MAX);
  }
  if (ring_size < TCPDUMP_RING_SIZE_MIN || (mrb_int)TCPDUMP_RING_SIZE_MAX < ring_size) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "buffer_size must be %d..%d",
               (int)TCPDUMP_RING_SIZE_MIN, (int)TCPDUMP_RING_SIZE_MAX);
  }
  if (ring_size < TCPDUMP_RECORD_HEADER_SIZE + snaplen) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "buffer_size too small for snaplen");
  }
  if (!tcpdump_ring_start((uint32_t)ring_size, (uint32_t)snaplen)) {
    return mrb_false_value();
  }
  tcpdump_attach_poll(true);
  return mrb_true_value();
}

static mrb_value
mrb_tcpdump_s_stop(mrb_state *mrb, mrb_value self)
{
  tcpdump_ring_stop();
  return mrb_nil_value();
}

static mrb_value
mrb_tcpdump_s_capturing_p(mrb_state *mrb, mrb_value self)
{
  return mrb_bool_value(tcpdump_ring_capturing());
}

static mrb_value
mrb_tcpdump_s_pending(mrb_state *mrb, mrb_value self)
{
  return int_value(mrb, tcpdump_ring_pending());
}

/*
 * Tcpdump.__drain(max_bytes) -> String
 *
 * Whole pcap records only, at most max_bytes in total. Returns "" when
 * the ring is empty or the first record is larger than max_bytes.
 */
static mrb_value
mrb_tcpdump_s_drain(mrb_state *mrb, mrb_value self)
{
  mrb_int max_bytes;
  uint32_t n;
  mrb_value str;

  mrb_get_args(mrb, "i", &max_bytes);
  if (max_bytes <= 0) return mrb_str_new(mrb, NULL, 0);
  n = tcpdump_ring_peek((uint32_t)max_bytes);
  str = mrb_str_new(mrb, NULL, n);
  if (0 < n) tcpdump_ring_read((uint8_t *)RSTRING_PTR(str), n);
  return str;
}

static mrb_value
mrb_tcpdump_s_discard(mrb_state *mrb, mrb_value self)
{
  tcpdump_ring_discard();
  return mrb_nil_value();
}

/*
 * Tcpdump.__stats -> [captured, dropped, bytes, ring_size, snaplen, netifs]
 */
static mrb_value
mrb_tcpdump_s_stats(mrb_state *mrb, mrb_value self)
{
  tcpdump_stats_t st;
  mrb_value ary;

  tcpdump_ring_stats(&st);
  ary = mrb_ary_new_capa(mrb, 6);
  mrb_ary_push(mrb, ary, int_value(mrb, st.captured));
  mrb_ary_push(mrb, ary, int_value(mrb, st.dropped));
  mrb_ary_push(mrb, ary, int_value(mrb, st.bytes));
  mrb_ary_push(mrb, ary, int_value(mrb, st.ring_size));
  mrb_ary_push(mrb, ary, int_value(mrb, st.snaplen));
  mrb_ary_push(mrb, ary, mrb_int_value(mrb, tcpdump_port_hooked_count()));
  return ary;
}

/*
 * Tcpdump.__header(snaplen) -> 24-byte pcap global header
 */
static mrb_value
mrb_tcpdump_s_header(mrb_state *mrb, mrb_value self)
{
  mrb_int snaplen;
  uint8_t hdr[TCPDUMP_GLOBAL_HEADER_SIZE];

  mrb_get_args(mrb, "i", &snaplen);
  tcpdump_pcap_global_header(hdr, (uint32_t)snaplen);
  return mrb_str_new(mrb, (const char *)hdr, sizeof(hdr));
}

/*
 * Tcpdump.attach -> Integer (interfaces hooked so far)
 *
 * Looks for network interfaces that came up since the last look. Runs
 * on its own from the scheduler and from every flush; call it after
 * bringing up a network by hand to start capturing right away.
 */
static mrb_value
mrb_tcpdump_s_attach(mrb_state *mrb, mrb_value self)
{
  tcpdump_attach_poll(true);
  return mrb_int_value(mrb, tcpdump_port_hooked_count());
}

static bool flush_locked;

/* Tcpdump.__flush_lock -> true if acquired. No preemption inside a C
 * method, so this is an atomic test-and-set as far as tasks go. */
static mrb_value
mrb_tcpdump_s_flush_lock(mrb_state *mrb, mrb_value self)
{
  if (flush_locked) return mrb_false_value();
  flush_locked = true;
  return mrb_true_value();
}

static mrb_value
mrb_tcpdump_s_flush_unlock(mrb_state *mrb, mrb_value self)
{
  flush_locked = false;
  return mrb_nil_value();
}

#if defined(PICORB_PLATFORM_POSIX)
/*
 * Tcpdump.inject(frame) -> true/false   (POSIX build only)
 *
 * Feeds a raw Ethernet frame to the capture path as if a netif had
 * sent or received it. The host build has no lwIP, so this is how tests
 * exercise the ring and the pcap writer.
 */
static mrb_value
mrb_tcpdump_s_inject(mrb_state *mrb, mrb_value self)
{
  mrb_value frame;
  mrb_get_args(mrb, "S", &frame);
  return mrb_bool_value(tcpdump_capture_bytes((const uint8_t *)RSTRING_PTR(frame),
                                              (uint32_t)RSTRING_LEN(frame)));
}
#endif

#if defined(MRB_USE_TASK_SCHEDULER) && !defined(PICORB_PLATFORM_POSIX)
/* Picks up a netif within a few hundred ms of it appearing, so the
   DHCP exchange right after Wi-Fi association is in the capture. */
static void
tcpdump_scheduler_service(mrb_state *mrb, void *ud)
{
  (void)mrb;
  (void)ud;
  tcpdump_attach_poll(false);
}
#endif

void
mrb_picoruby_tcpdump_gem_init(mrb_state *mrb)
{
  struct RClass *mod = mrb_define_module_id(mrb, MRB_SYM(Tcpdump));

  mrb_define_class_method_id(mrb, mod, MRB_SYM(__start), mrb_tcpdump_s_start, MRB_ARGS_REQ(2));
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__stop), mrb_tcpdump_s_stop, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM_Q(capturing), mrb_tcpdump_s_capturing_p, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__pending), mrb_tcpdump_s_pending, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__drain), mrb_tcpdump_s_drain, MRB_ARGS_REQ(1));
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__discard), mrb_tcpdump_s_discard, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__stats), mrb_tcpdump_s_stats, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__header), mrb_tcpdump_s_header, MRB_ARGS_REQ(1));
  mrb_define_class_method_id(mrb, mod, MRB_SYM(attach), mrb_tcpdump_s_attach, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__flush_lock), mrb_tcpdump_s_flush_lock, MRB_ARGS_NONE());
  mrb_define_class_method_id(mrb, mod, MRB_SYM(__flush_unlock), mrb_tcpdump_s_flush_unlock, MRB_ARGS_NONE());
#if defined(PICORB_PLATFORM_POSIX)
  mrb_define_class_method_id(mrb, mod, MRB_SYM(inject), mrb_tcpdump_s_inject, MRB_ARGS_REQ(1));
#endif

  /* The host build is a test bench: no network to capture, and a
     background flusher task would keep bin/picoruby from exiting. */
#if defined(PICORB_PLATFORM_POSIX) || defined(PICORB_TCPDUMP_NO_AUTOSTART)
  mrb_define_const_id(mrb, mod, MRB_SYM(AUTOSTART), mrb_false_value());
#else
  mrb_define_const_id(mrb, mod, MRB_SYM(AUTOSTART), mrb_true_value());
#endif
  mrb_define_const_id(mrb, mod, MRB_SYM(DEFAULT_SNAPLEN), mrb_int_value(mrb, TCPDUMP_DEFAULT_SNAPLEN));
  mrb_define_const_id(mrb, mod, MRB_SYM(DEFAULT_BUFFER_SIZE), mrb_int_value(mrb, TCPDUMP_DEFAULT_RING_SIZE));

#if defined(MRB_USE_TASK_SCHEDULER) && !defined(PICORB_PLATFORM_POSIX)
  picorb_scheduler_service_add(mrb, tcpdump_scheduler_service, NULL);
#endif
}

void
mrb_picoruby_tcpdump_gem_final(mrb_state *mrb)
{
#if defined(MRB_USE_TASK_SCHEDULER) && !defined(PICORB_PLATFORM_POSIX)
  picorb_scheduler_service_remove(mrb, tcpdump_scheduler_service, NULL);
#endif
  /* The netif hooks stay installed (they outlive the VM and only call
     through when nothing is capturing); the ring goes. */
  tcpdump_ring_free();
  flush_locked = false;
}
