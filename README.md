# picoruby-tcpdump

Captures the device's own network traffic into a pcap file on the
device's filesystem, for download with picomodem and analysis in
Wireshark.

Put the gem in the firmware and capture starts at boot: every Ethernet
frame the device sends or receives over Wi-Fi (or Ethernet) is written to
`/home/capture.pcap`.

## Installation

Add the gem to a PicoRuby (mruby VM) build config:

```ruby
conf.gem github: 'yuuu/picoruby-tcpdump'
```

### R2P2-ESP32

The capture hook (`ports/esp32/`) needs ESP-IDF's lwIP and esp_netif headers,
so R2P2-ESP32 compiles it with ESP-IDF's CMake, not with rake, and the gem has
to be on disk when CMake configures. Clone it into R2P2-ESP32's project-root
`mrbgems/` (changes there trigger a rebuild):

```sh
git clone https://github.com/yuuu/picoruby-tcpdump mrbgems/picoruby-tcpdump
```

Then, in `components/picoruby-esp32/`:

1. `build_config/{xtensa,riscv}-esp-picoruby.rb`:
   ```ruby
   conf.gem gemdir: File.expand_path('../../../mrbgems/picoruby-tcpdump', __dir__)
   ```
2. `CMakeLists.txt`: in the `PICORB_VM STREQUAL "mruby"` branch add the port
   to the sources, and add `esp_netif` and `lwip` to `PRIV_REQUIRES`:
   ```cmake
   set(ADDITIONAL_SRCS
     ${COMPONENT_DIR}/../../mrbgems/picoruby-tcpdump/ports/esp32/tcpdump.c
   )
   ```

### Downloading while capturing

Downloading the pcap with picomodem while the flusher appends to it corrupts
the transfer (littlefs reports `Corrupted @ lfs_file_read`). On a PicoRuby
whose picomodem has `PicoModem.busy?`, writes are held during a session.
Otherwise run `Tcpdump.stop` (it flushes) before `get`.

## How it works

- The gem hooks each lwIP network interface (Wi-Fi STA/AP, Ethernet,
  QEMU's openeth; not loopback) by wrapping its `input` and `linkoutput`
  functions. What gets captured is the Ethernet frames, as lwIP sees them.
  This is not 802.11 monitor mode: you see only this device's traffic,
  without radio headers, management frames, or other stations.
- Each frame is cut to `snaplen` bytes and copied into a RAM ring buffer,
  already in pcap record format. When the ring is full, new frames are
  dropped and counted.
- A background task drains the ring to the file every few seconds. The
  network stack never writes to the filesystem itself.
- Interfaces that come up later (for example, Wi-Fi started from
  `/bin/wifi_connect` or an app) are noticed within about 200 ms.
- The file is classic pcap (`0xa1b2c3d4`, microsecond timestamps,
  `LINKTYPE_ETHERNET`). Timestamps come from the system clock: wall-clock
  time once NTP (or something else) has set it, time since boot
  (shown as 1970-01-01) before that.

## Usage

Nothing is needed: the gem starts with these defaults.

| option        | default              |                                              |
|---------------|----------------------|----------------------------------------------|
| `path`        | `/home/capture.pcap` | output file                                  |
| `snaplen`     | 128                  | bytes kept per frame (16..65535)             |
| `max_size`    | 1 MiB                | capture stops when the file reaches this     |
| `buffer_size` | 16 KiB               | RAM ring, rounded down to a power of two     |
| `interval`    | 5                    | seconds between flushes; 0 = only `flush`    |

```ruby
# Restart with other settings (starts a new file)
Tcpdump.start(path: "/home/dhcp.pcap", snaplen: 1514, max_size: 256 * 1024)

Tcpdump.flush   # write buffered frames now; returns bytes written
Tcpdump.stop    # stop capturing and flush
Tcpdump.stats
# => {captured: 152, dropped: 0, bytes: 48211, written: 21304, pending: 0,
#     netifs: 1, capturing: true, full: false, path: "/home/capture.pcap",
#     snaplen: 128, buffer_size: 16384, max_size: 1048576}
Tcpdump.attach  # look for new interfaces right away; returns how many are hooked
```

Omitted keywords keep their previous values. `start` first finishes the
running session. When it writes its first data, it renames an existing
file to `capture.prev.pcap` and starts a new one, so the capture from
before a reboot or crash stays available until the next session replaces it.

## Download and open in Wireshark

Stop or flush first, so the file holds everything up to now:

```
> Tcpdump.stop
```

On the host (see picoruby-picomodem):

```sh
picoruby tools/picomodem.rb get /home/capture.pcap
wireshark capture.pcap            # or: tcpdump -nn -r capture.pcap
```

## Limitations

- **Truncated frames.** Only the first `snaplen` bytes of each frame are
  kept (128 by default: enough for Ethernet/IP/TCP/UDP headers and the
  start of the payload). Wireshark marks such frames "Packet size
  limited during capture". Raise `snaplen` to see more of each payload.
- **Drops.** A burst larger than the ring between two flushes is lost
  (`stats[:dropped]`). Make `buffer_size` larger, `snaplen` smaller, or
  `interval` shorter.
- **File size.** When `max_size` is reached, capture stops
  (`stats[:full]`). The file is not rotated.
- **Flash wear.** Each flush appends to a file on flash. With the
  defaults, a busy link writes up to 1 MiB, then stops. Don't leave a
  large `max_size` with a short `interval` running for days.
- **CPU and RAM.** Every frame costs a copy of up to `snaplen` bytes
  inside a short critical section, plus the ring buffer (16 KiB by default).
- **Hooks stay installed.** `stop` makes the hooks pass frames straight
  through; it does not remove them.
- **What is missing.** Frames that never reach the interface hooks are not
  captured: frames the Wi-Fi driver drops, 802.11 management traffic,
  and loopback (127.0.0.1) traffic.
- PicoRuby (mruby VM) builds only.

## Privacy

The capture holds everything the device sends and receives, including
the contents of plaintext protocols: HTTP, MQTT without TLS, DNS
queries, and any passwords or tokens sent over them. It stays on `/home`
after you download it. Delete it (`rm /home/capture.pcap
/home/capture.prev.pcap`) when you're done, and remove the gem from
production firmware.

## Porting

- `src/ring.c`: ring buffer and pcap format; no platform or network-stack
  code.
- `ports/lwip/tcpdump_lwip.c`: the lwIP netif hooks, `#include`d by the
  lwIP-based ports.
- `ports/<platform>/tcpdump.c`: the lock, the clock, and how to reach
  lwIP's interface list:
  - esp32: a spinlock critical section; hooks are installed in the tcpip
    thread with `tcpip_try_callback()` once `esp_netif` has created an
    interface. The firmware build must compile this file and give it the
    `esp_netif`, `lwip` and `esp_timer` IDF components.
  - rp2040: interrupts are disabled around each copy; hooks are installed
    inside `cyw43_arch_lwip_begin/end` after `CYW43.init`. The lwIP part
    is compiled only with `USE_WIFI`.
  - posix: there is no lwIP. `Tcpdump.inject(frame)` feeds frames in for
    tests, and capture does not start at boot (a background task would
    keep `picoruby` from exiting).

Define `PICORB_TCPDUMP_NO_AUTOSTART` to keep the gem from starting
at boot on a device build.

## Development

This repo is a standalone mrbgem. Point `TCPDUMP_PICORUBY_DIR` at a
[picoruby](https://github.com/picoruby/picoruby) checkout (submodules
initialized) and use this repo's `Rakefile`:

```sh
TCPDUMP_PICORUBY_DIR=/path/to/picoruby rake build  # build/host/bin/picoruby
TCPDUMP_PICORUBY_DIR=/path/to/picoruby rake test   # test/*_test.rb (picotest)
```

The PicoRuby checkout is used as-is; build artifacts land in this repo's
`build/`.

## License

MIT
