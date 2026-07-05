module OpenSSL
  class BioError < Error; end
end

class OpenSSL::GETS_BIO
  BIO_C_FILE_TELL = 133
  BIO_C_FILE_SEEK = 128

  private def self.io_for(bio : LibCrypto::Bio*) : IO
    {% if OpenSSL::BIO.has_method?(:ktls_recv?) %}
      Box(OpenSSL::BIO).unbox(LibCrypto.BIO_get_data(bio)).io
    {% else %}
      Box(IO).unbox(LibCrypto.BIO_get_data(bio))
    {% end %}
  end

  # stdlib's OpenSSL::BIO only grew read/write/read_ex/write_ex/create/destroy
  # class methods in crystal 1.20 (KTLS support). on 1.19.1 that struct barely
  # exists, so we can't delegate to it here - keep our own minimal copies.
  {% unless OpenSSL::BIO.has_method?(:read) %}
    def self.read(bio : LibCrypto::Bio*, buffer : LibC::Char*, len : LibC::Int) : LibC::Int
      io_for(bio).read(Slice.new(buffer, len)).to_i
    end

    def self.write(bio : LibCrypto::Bio*, data : LibC::Char*, len : LibC::Int) : LibC::Int
      io_for(bio).write(Slice.new(data, len))
      len
    end

    def self.create(bio : LibCrypto::Bio*) : LibC::Int
      LibCrypto.BIO_set_shutdown(bio, 1)
      LibCrypto.BIO_set_init(bio, 1)
      1
    end

    def self.destroy(bio : LibCrypto::Bio*) : LibC::Int
      LibCrypto.BIO_set_data(bio, Pointer(Void).null)
      1
    end
  {% end %}

  # own BIO_METHOD, do not touch stdlib CRYSTAL_BIO.
  # mutating the shared one breaks every SSL socket on crystal 1.20.
  # we copy stdlib read/write/create/destroy and set our own ctrl+gets.
  GETS_BIO = begin
    bio_id = LibCrypto.BIO_get_new_index
    raise OpenSSL::Error.new("BIO_get_new_index") if bio_id == -1

    bio_type = bio_id | LibCrypto::BIO_TYPE_SOURCE_SINK | LibCrypto::BIO_TYPE_DESCRIPTOR
    biom = LibCrypto.BIO_meth_new(bio_type, "Crystal GETS BIO")
    raise OpenSSL::Error.new("BIO_meth_new") if biom.null?

    # reuse stdlib callbacks so KTLS builds keep read_ex/write_ex.
    # fall back to our own copies on crystal < 1.20 where OpenSSL::BIO doesn't have them.
    {% if LibCrypto.has_method?(:BIO_meth_set_read_ex) %}
      LibCrypto.BIO_meth_set_read_ex(biom, ->OpenSSL::BIO.read_ex(LibCrypto::Bio*, UInt8*, LibC::SizeT, LibC::SizeT*))
    {% elsif OpenSSL::BIO.has_method?(:read) %}
      LibCrypto.BIO_meth_set_read(biom, ->OpenSSL::BIO.read(LibCrypto::Bio*, UInt8*, LibC::Int))
    {% else %}
      LibCrypto.BIO_meth_set_read(biom, ->OpenSSL::GETS_BIO.read(LibCrypto::Bio*, LibC::Char*, LibC::Int))
    {% end %}

    {% if LibCrypto.has_method?(:BIO_meth_set_write_ex) %}
      LibCrypto.BIO_meth_set_write_ex(biom, ->OpenSSL::BIO.write_ex(LibCrypto::Bio*, UInt8*, LibC::SizeT, LibC::SizeT*))
    {% elsif OpenSSL::BIO.has_method?(:write) %}
      LibCrypto.BIO_meth_set_write(biom, ->OpenSSL::BIO.write(LibCrypto::Bio*, UInt8*, LibC::Int))
    {% else %}
      LibCrypto.BIO_meth_set_write(biom, ->OpenSSL::GETS_BIO.write(LibCrypto::Bio*, LibC::Char*, LibC::Int))
    {% end %}

    {% if OpenSSL::BIO.has_method?(:create) %}
      LibCrypto.BIO_meth_set_create(biom, ->OpenSSL::BIO.create(LibCrypto::Bio*))
      LibCrypto.BIO_meth_set_destroy(biom, ->OpenSSL::BIO.destroy(LibCrypto::Bio*))
    {% else %}
      LibCrypto.BIO_meth_set_create(biom, ->OpenSSL::GETS_BIO.create(LibCrypto::Bio*))
      LibCrypto.BIO_meth_set_destroy(biom, ->OpenSSL::GETS_BIO.destroy(LibCrypto::Bio*))
    {% end %}

    ctrl = Proc(LibCrypto::Bio*, LibC::Int, LibC::Long, Void*, LibC::Long).new do |bio, cmd, _num, _ptr|
      io = io_for(bio)
      val = {% begin %}
              case cmd
              when LibCrypto::CTRL_FLUSH
                io.flush
                1
              when LibCrypto::CTRL_PUSH, LibCrypto::CTRL_POP, LibCrypto::CTRL_EOF
                0
              when BIO_C_FILE_TELL, BIO_C_FILE_SEEK
                0
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS) %}
                when LibCrypto::CTRL_SET_KTLS
                  0
              {% elsif LibCrypto.has_constant?(:CTRL_SET_KTLS_SEND) %}
                when LibCrypto::CTRL_SET_KTLS_SEND
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_GET_KTLS_SEND) && LibCrypto.has_constant?(:CTRL_GET_KTLS_RECV) %}
                when LibCrypto::CTRL_GET_KTLS_SEND, LibCrypto::CTRL_GET_KTLS_RECV
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS_TX_SEND_CTRL_MSG) && LibCrypto.has_constant?(:CTRL_CLEAR_KTLS_TX_CTRL_MSG) %}
                when LibCrypto::CTRL_SET_KTLS_TX_SEND_CTRL_MSG, LibCrypto::CTRL_CLEAR_KTLS_TX_CTRL_MSG
                  0
              {% end %}
              {% if LibCrypto.has_constant?(:CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE) %}
                when LibCrypto::CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE
                  0
              {% end %}
              else
                STDERR.puts "WARNING: Unsupported BIO ctrl call (#{cmd})"
                0
              end
            {% end %}
      LibCrypto::Long.new(val)
    end

    bgets = Proc(LibCrypto::Bio*, LibC::Char*, LibC::Int, LibC::Int).new do |bio, buffer, len|
      io = io_for(bio)
      io.flush

      position = io.pos

      line = io.gets(len, false)

      if line.nil?
        0
      else
        io.seek(position)
        bytes = io.read(Slice.new(buffer, line.bytesize)).to_i

        bytes -= 1 unless bytes == 1
        bytes
      end
    end

    # use our version of ctrl to avoid warnings
    # is also more performant than the standard library version
    {% if compare_versions(LibCrypto::OPENSSL_VERSION, "1.1.0") >= 0 %}
      LibCrypto.BIO_meth_set_ctrl(biom, ctrl)
      LibCrypto.BIO_meth_set_gets(biom, bgets)
    {% else %}
      biom.value.ctrl = ctrl
      biom.value.bgets = bgets
    {% end %}
    biom
  end

  @bridge_bio : OpenSSL::BIO? = nil
  @boxed_data : Void* = Pointer(Void).null

  def initialize(@io : IO)
    @bio = LibCrypto.BIO_new(GETS_BIO)
    raise BioError.new("BIO_new") if @bio.null?

    {% if OpenSSL::BIO.has_method?(:ktls_recv?) %}
      # Crystal's BIO read/write callbacks unbox OpenSSL::BIO from BIO data.
      # Keep a dedicated bridge object so those callbacks can access `#io` safely.
      bridge_bio = OpenSSL::BIO.new(io)
      @bridge_bio = bridge_bio

      # Keep a reference to this box because it lives in C-land.
      @boxed_data = Box(OpenSSL::BIO).box(bridge_bio)
      LibCrypto.BIO_set_data(@bio, @boxed_data)
    {% else %}
      @boxed_data = Box(IO).box(io)
      LibCrypto.BIO_set_data(@bio, @boxed_data)
    {% end %}
  end

  def finalize
    LibCrypto.bio_free_all(@bio)
    if bridge = @bridge_bio
      LibCrypto.bio_free_all(bridge.to_unsafe)
    end
  end

  getter io

  def to_unsafe
    @bio
  end
end
