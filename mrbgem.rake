MRuby::Gem::Specification.new('picoruby-tcpdump') do |spec|
  spec.license = 'MIT'
  spec.author  = 'Yuhei Okazaki'
  spec.summary = 'Capture network traffic into a pcap file'

  if build.femtoruby?
    raise "picoruby-tcpdump supports PicoRuby (mruby VM) builds only"
  end

  # Task (background flusher) and the scheduler hook used to notice new
  # network interfaces. picoruby-machine owns the hook slot.
  spec.add_dependency 'mruby-task', gemdir: "#{MRUBY_ROOT}/mrbgems/picoruby-mruby/lib/mruby/mrbgems/mruby-task"
  spec.add_dependency 'picoruby-machine'

  spec.cc.include_paths << "#{dir}/include"
  # picoruby-machine's hal.h is included by path: picoruby-mruby/include/hal.h
  # would shadow a bare "hal.h". This gem lives outside MRUBY_ROOT/mrbgems,
  # so a sibling-relative path does not work.
  spec.cc.include_paths << "#{MRUBY_ROOT}/mrbgems"

  # ports/posix/ is compiled by lib/picoruby/gem.rb for host builds.
  # ports/esp32/ and ports/rp2040/ are compiled by the firmware's CMake
  # with the platform's lwIP headers (see README).
end
