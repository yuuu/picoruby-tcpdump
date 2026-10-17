class TcpdumpTest < Picotest::Test
  PATH = "/tmp/picoruby_tcpdump_test.pcap"
  PREV = "/tmp/picoruby_tcpdump_test.prev.pcap"

  def setup
    File.unlink(PATH) if File.exist?(PATH)
    File.unlink(PREV) if File.exist?(PREV)
  end

  def teardown
    Tcpdump.stop
    File.unlink(PATH) if File.exist?(PATH)
    File.unlink(PREV) if File.exist?(PREV)
  end

  def u32(s, off)
    s.getbyte(off) | (s.getbyte(off + 1) << 8) | (s.getbyte(off + 2) << 16) | (s.getbyte(off + 3) << 24)
  end

  def frame(len, seed = 0)
    s = ""
    i = 0
    while i < len
      s << ((i + seed) % 256).chr
      i += 1
    end
    s
  end

  def read_file
    f = File.open(PATH, "r")
    data = f.read
    f.close
    data
  end

  def test_global_header
    Tcpdump.start(path: PATH, snaplen: 96, buffer_size: 4096, max_size: 65536, interval: 0)
    Tcpdump.inject(frame(60))
    Tcpdump.flush
    data = read_file
    assert_equal 0xd4, data.getbyte(0)
    assert_equal 0xc3, data.getbyte(1)
    assert_equal 0xb2, data.getbyte(2)
    assert_equal 0xa1, data.getbyte(3)
    assert_equal 2, data.getbyte(4)
    assert_equal 4, data.getbyte(6)
    assert_equal 96, u32(data, 16)
    assert_equal 1, u32(data, 20)
  end

  def test_records_and_snaplen
    Tcpdump.start(path: PATH, snaplen: 64, buffer_size: 4096, max_size: 65536, interval: 0)
    assert_true Tcpdump.inject(frame(42, 1))
    assert_true Tcpdump.inject(frame(200, 2))
    written = Tcpdump.flush
    data = read_file
    assert_equal 24 + (16 + 42) + (16 + 64), data.bytesize
    assert_equal data.bytesize - 24, written
    # record 1
    assert_equal 42, u32(data, 24 + 8)
    assert_equal 42, u32(data, 24 + 12)
    assert_equal frame(42, 1), data.byteslice(24 + 16, 42)
    # record 2: truncated to snaplen
    off = 24 + 16 + 42
    assert_equal 64, u32(data, off + 8)
    assert_equal 200, u32(data, off + 12)
    assert_equal frame(64, 2), data.byteslice(off + 16, 64)
    st = Tcpdump.stats
    assert_equal 2, st[:captured]
    assert_equal 0, st[:dropped]
    assert_equal 242, st[:bytes]
    assert_equal data.bytesize, st[:written]
  end

  def test_flush_appends
    Tcpdump.start(path: PATH, snaplen: 128, buffer_size: 4096, max_size: 65536, interval: 0)
    Tcpdump.inject(frame(50))
    Tcpdump.flush
    Tcpdump.inject(frame(70))
    Tcpdump.flush
    assert_equal 24 + 66 + 86, read_file.bytesize
    assert_equal 0, Tcpdump.flush
  end

  def test_ring_overflow_counts_drops
    # 1024-byte ring, 116-byte records -> 8 fit
    Tcpdump.start(path: PATH, snaplen: 128, buffer_size: 1024, max_size: 65536, interval: 0)
    i = 0
    while i < 20
      Tcpdump.inject(frame(100, i))
      i += 1
    end
    st = Tcpdump.stats
    assert_equal 8, st[:captured]
    assert_equal 12, st[:dropped]
    assert_equal 928, st[:pending]
    Tcpdump.flush
    assert_equal 24 + 928, read_file.bytesize
    # Room again after the flush
    assert_true Tcpdump.inject(frame(100))
  end

  def test_ring_wraparound
    Tcpdump.start(path: PATH, snaplen: 128, buffer_size: 1024, max_size: 1024 * 1024, interval: 0)
    total = 0
    i = 0
    while i < 50
      len = 60 + (i * 7) % 60
      assert_true Tcpdump.inject(frame(len, i))
      total += 16 + len
      Tcpdump.flush if i % 3 == 2
      i += 1
    end
    Tcpdump.flush
    data = read_file
    assert_equal 24 + total, data.bytesize
    # Walk every record and check its payload
    off = 24
    i = 0
    while i < 50
      len = 60 + (i * 7) % 60
      assert_equal len, u32(data, off + 8)
      assert_equal frame(len, i), data.byteslice(off + 16, len)
      off += 16 + len
      i += 1
    end
    assert_equal 0, Tcpdump.stats[:dropped]
  end

  def test_max_size_stops_capture
    Tcpdump.start(path: PATH, snaplen: 128, buffer_size: 4096, max_size: 24 + 2 * 116 + 10, interval: 0)
    i = 0
    while i < 5
      Tcpdump.inject(frame(100))
      i += 1
    end
    Tcpdump.flush
    assert_equal 24 + 2 * 116, read_file.bytesize
    assert_true Tcpdump.full?
    assert_false Tcpdump.capturing?
    assert_false Tcpdump.inject(frame(100))
    assert_equal 0, Tcpdump.stats[:pending]
  end

  def test_stop
    Tcpdump.start(path: PATH, buffer_size: 4096, interval: 0)
    assert_true Tcpdump.capturing?
    Tcpdump.inject(frame(60))
    Tcpdump.stop
    assert_false Tcpdump.capturing?
    assert_false Tcpdump.inject(frame(60))
    assert_equal 24 + 76, read_file.bytesize
  end

  def test_previous_file_is_kept
    Tcpdump.start(path: PATH, buffer_size: 4096, interval: 0)
    Tcpdump.inject(frame(60))
    Tcpdump.flush
    Tcpdump.start(path: PATH, buffer_size: 4096, interval: 0)
    Tcpdump.inject(frame(61))
    Tcpdump.flush
    assert_true File.exist?(PREV)
    assert_equal 24 + 77, read_file.bytesize
  end

  def test_invalid_snaplen
    assert_raise(ArgumentError) do
      Tcpdump.start(path: PATH, snaplen: 4, interval: 0)
    end
    Tcpdump.start(path: PATH, snaplen: 128, interval: 0)
  end
end
