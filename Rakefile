# Builds and tests picoruby-tcpdump against a PicoRuby checkout.
#
# Point TCPDUMP_PICORUBY_DIR at a picoruby checkout (submodules initialized):
#
#   TCPDUMP_PICORUBY_DIR=~/src/picoruby rake test
#
# Build artifacts land in this repo's build/, never in the picoruby checkout.
GEM_ROOT     = __dir__
BUILD_CONFIG = File.join(GEM_ROOT, 'build_config', 'host.rb')
BUILD_DIR    = File.join(GEM_ROOT, 'build')
PICORUBY_BIN = File.join(BUILD_DIR, 'host', 'bin', 'picoruby')

def picoruby_dir
  dir = ENV['TCPDUMP_PICORUBY_DIR']
  abort "TCPDUMP_PICORUBY_DIR is not set: point it at a picoruby checkout" if dir.nil? || dir.empty?
  dir = File.expand_path(dir)
  unless File.exist?(File.join(dir, 'Rakefile'))
    abort "#{dir}/Rakefile not found: TCPDUMP_PICORUBY_DIR does not look like a picoruby checkout"
  end
  dir
end

desc 'Build PicoRuby with picoruby-tcpdump (build/host/bin/picoruby)'
task :build do
  env = { 'MRUBY_CONFIG' => BUILD_CONFIG, 'MRUBY_BUILD_DIR' => BUILD_DIR }
  sh env, 'rake', '-f', File.join(picoruby_dir, 'Rakefile'), 'all'
end

desc 'Run test/*_test.rb on build/host/bin/picoruby (picotest)'
task test: :build do
  require File.join(picoruby_dir, 'mrbgems', 'picoruby-picotest', 'mrblib', 'picotest.rb')
  ENV['RUBY'] = PICORUBY_BIN
  runner = Picotest::Runner.new(File.join(GEM_ROOT, 'test'),
                                require_name: 'tcpdump', load_path: GEM_ROOT)
  abort 'test failed' unless runner.run == 0
end

desc 'Remove build artifacts'
task :clean do
  rm_rf BUILD_DIR
end

task default: :test
