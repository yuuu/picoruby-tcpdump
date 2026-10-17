# PicoRuby (mruby VM) POSIX host build with picoruby-tcpdump, used by this
# repo's Rakefile to build and test the gem:
#
#   MRUBY_CONFIG=<this repo>/build_config/host.rb \
#   MRUBY_BUILD_DIR=<this repo>/build \
#   rake -f <picoruby>/Rakefile
GEM_ROOT = File.expand_path('..', __dir__)

MRuby::Build.new do |conf|
  conf.toolchain :gcc

  conf.cc.defines << "PICORB_PLATFORM_POSIX"
  conf.cc.defines << "MRB_TICK_UNIT=4"
  conf.cc.defines << "MRB_TIMESLICE_TICK_COUNT=3"
  conf.cc.defines << "MRB_INT64"
  conf.cc.defines << "MRB_NO_BOXING"
  conf.cc.defines << "MRB_UTF8_STRING"

  conf.picoruby

  # picoruby-socket (in the stdlib gembox) links OpenSSL.
  conf.linker.libraries << 'ssl'
  conf.linker.libraries << 'crypto'

  conf.gembox "mruby-posix"
  conf.gembox "minimum"
  conf.gembox "core"
  conf.gembox "stdlib"
  conf.gem core: 'picoruby-bin-picoruby'
  conf.gem core: 'picoruby-picotest'
  conf.gem gemdir: GEM_ROOT
end
