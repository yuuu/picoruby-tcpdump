# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this gem is

`picoruby-tcpdump` captures the Ethernet frames a PicoRuby (mruby VM) device
sends and receives into a classic pcap file on the device, for download with
picomodem and analysis in Wireshark. Read `README.md` first.

- mruby VM (`build.picoruby?`) only; mruby/c (femtoruby) is not supported.
- Capture hooks lwIP's `netif->input` / `netif->linkoutput`
  (`ports/lwip/tcpdump_lwip.c`), `#include`d by the lwIP ports. Those run in
  the network driver / tcpip threads, so producers take `tcpdump_port_lock()`
  and the VM thread is the single consumer.
- `src/ring.c` holds the ring buffer and pcap format with no platform or
  network-stack code. Keep it that way.
- On R2P2-ESP32, `ports/esp32/` needs ESP-IDF's lwIP/esp_netif headers and is
  compiled by ESP-IDF's CMake, not by rake. The posix port has no lwIP:
  `Tcpdump.inject(frame)` feeds frames in for tests.

## Build & test

Point `TCPDUMP_PICORUBY_DIR` at a picoruby checkout (submodules initialized):

```sh
TCPDUMP_PICORUBY_DIR=/path/to/picoruby rake build  # build/host/bin/picoruby
TCPDUMP_PICORUBY_DIR=/path/to/picoruby rake test   # test/*_test.rb (picotest)
```

## Coding rules (from PicoRuby's AGENTS.md)

- In `mrblib/`, use `while` loops with an explicit index instead of `each`,
  `times`, `map`, `loop` and friends (they create ireps and deepen the VM
  stack on small targets). Tests are exempt.
- Memoize an ivar into a local when it is read three or more times.
- Never write to the filesystem per packet: frames go to the RAM ring and the
  flusher task writes them out.
