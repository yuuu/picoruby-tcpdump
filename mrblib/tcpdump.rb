#
# Tcpdump: capture the device's Ethernet/Wi-Fi frames into a pcap file.
#
# Frames are copied (up to snaplen bytes each) into a RAM ring by hooks
# on the network interfaces, in whatever thread the network stack runs.
# Nothing touches the filesystem there: a background task (or an explicit
# Tcpdump.flush) drains the ring to the file from the VM thread.
#
module Tcpdump
  DEFAULT_PATH = "/home/capture.pcap"
  DEFAULT_MAX_SIZE = 1024 * 1024
  DEFAULT_INTERVAL = 5
  DEFAULT_PRIORITY = 128
  GLOBAL_HEADER_SIZE = 24
  RECORD_HEADER_SIZE = 16
  CHUNK_SIZE = 4096

  @path = DEFAULT_PATH
  @snaplen = DEFAULT_SNAPLEN
  @max_size = DEFAULT_MAX_SIZE
  @buffer_size = DEFAULT_BUFFER_SIZE
  @interval = DEFAULT_INTERVAL
  @written = 0
  @header_written = false
  @full = false
  @task = nil

  # Start (or restart) capturing. The file at `path` is truncated when
  # the first data is written to it. Keywords left out keep their
  # previous value.
  #   path:        pcap file (default "/home/capture.pcap")
  #   snaplen:     bytes kept per frame (default 128)
  #   max_size:    file size limit in bytes; capture stops there (default 1 MiB)
  #   buffer_size: RAM ring size in bytes, rounded down to a power of two
  #   interval:    seconds between background flushes; 0 = flush manually
  def self.start(path: nil, snaplen: nil, max_size: nil, buffer_size: nil, interval: nil)
    snaplen ||= @snaplen
    max_size ||= @max_size
    buffer_size ||= @buffer_size
    interval ||= @interval
    if max_size < GLOBAL_HEADER_SIZE + RECORD_HEADER_SIZE
      raise ArgumentError, "max_size too small"
    end
    if interval < 0
      raise ArgumentError, "interval must not be negative"
    end
    # Finish the running session in its own file first.
    __stop
    flush if @header_written
    # Raises ArgumentError on a bad snaplen/buffer_size before anything
    # below changes.
    unless __start(snaplen, buffer_size)
      raise RuntimeError, "Tcpdump: cannot allocate #{buffer_size} bytes of capture buffer"
    end
    @path = path if path
    @snaplen = snaplen
    @max_size = max_size
    @buffer_size = buffer_size
    @interval = interval
    @written = 0
    @header_written = false
    @full = false
    start_flusher if 0 < @interval
    true
  end

  # Stop capturing and write out what is buffered.
  def self.stop
    __stop
    flush
    true
  end

  # Write buffered frames to the file. Returns the number of bytes
  # written (0 while the filesystem is not available yet; the frames stay
  # buffered until then).
  def self.flush
    attach
    return 0 if __pending == 0
    # Never append while PicoModem may be sending this file; the frames
    # stay buffered until the next flush. (PicoModem.busy? is
    # missing on older PicoRuby: there writes are never held.)
    return 0 if Object.const_defined?(:PicoModem) &&
      PicoModem.respond_to?(:busy?) && PicoModem.busy?
    # Tasks are preemptive: keep a second flusher from interleaving its
    # chunks with ours. Taken in C, so the test-and-set is atomic.
    return 0 unless __flush_lock
    begin
      flush_locked
    ensure
      __flush_unlock
    end
  end

  def self.flush_locked
    if @full
      __discard
      return 0
    end
    return 0 unless write_header
    file = nil
    total = 0
    max_size = @max_size
    written = @written
    chunk = RECORD_HEADER_SIZE + @snaplen
    chunk = CHUNK_SIZE if chunk < CHUNK_SIZE
    begin
      while 0 < __pending
        room = max_size - written
        room = chunk if chunk < room
        data = __drain(room)
        size = data.bytesize
        if size == 0
          # The next record does not fit under max_size.
          @full = true
          __stop
          __discard
          break
        end
        file = File.open(@path, "a") unless file
        file.write(data)
        written += size
        total += size
      end
    ensure
      @written = written
      file.close if file
    end
    total
  end

  # {captured:, dropped:, bytes:, written:, pending:, netifs:,
  #  capturing:, full:, path:, snaplen:, buffer_size:, max_size:}
  def self.stats
    s = __stats
    {
      captured: s[0],
      dropped: s[1],
      bytes: s[2],
      written: @written,
      pending: __pending,
      netifs: s[5],
      capturing: capturing?,
      full: @full,
      path: @path,
      snaplen: s[4],
      buffer_size: s[3],
      max_size: @max_size
    }
  end

  def self.path
    @path
  end

  def self.full?
    @full
  end

  def self.write_header
    return true if @header_written
    path = @path
    begin
      # Keep the previous session (e.g. the boot before a crash) around.
      if File.exist?(path)
        prev = previous_path(path)
        File.unlink(prev) if File.exist?(prev)
        File.rename(path, prev)
      end
      file = File.open(path, "w")
    rescue
      return false # e.g. the volume is not mounted yet
    end
    begin
      file.write(__header(@snaplen))
    ensure
      file.close
    end
    @written = GLOBAL_HEADER_SIZE
    @header_written = true
    true
  end

  def self.start_flusher
    return if @task
    @task = Task.new(name: "tcpdump", priority: DEFAULT_PRIORITY) do
      while true
        interval = Tcpdump.interval
        if interval < 1
          sleep 1 # flushing was switched to manual by a later start
        else
          sleep interval
          begin
            Tcpdump.flush
          rescue => e
            puts "Tcpdump: flush failed: #{e.message} (#{e.class})"
          end
        end
      end
    end
  end

  def self.interval
    @interval
  end

  # "/home/capture.pcap" -> "/home/capture.prev.pcap"
  def self.previous_path(path)
    if path.end_with?(".pcap")
      path.byteslice(0, path.bytesize - 5).to_s + ".prev.pcap"
    else
      path + ".prev"
    end
  end
end

if Tcpdump::AUTOSTART
  begin
    Tcpdump.start
  rescue => e
    puts "Tcpdump: autostart failed: #{e.message} (#{e.class})"
  end
end
