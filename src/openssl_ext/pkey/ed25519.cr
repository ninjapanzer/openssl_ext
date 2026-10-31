require "../lib_crypto"
require "./pkey"

module OpenSSL::PKey
  class Ed25519Error < PKeyError; end

  # An Ed25519 key (RFC 8032). Ed25519 hashes the message itself, so `sign`
  # and `verify` take the message and no digest.
  class Ed25519 < PKey
    KEY_SIZE       = 32
    SIGNATURE_SIZE = 64

    private NO_DIGEST = "Ed25519 signs the message itself and takes no digest"

    def self.generate : Ed25519
      ctx = LibCrypto.evp_pkey_ctx_new_id(LibCrypto::EVP_PKEY_ED25519, nil)
      raise Ed25519Error.new "Could not create a key context" if ctx.null?

      begin
        pkey = Pointer(LibCrypto::EvpPKey).null
        unless LibCrypto.evp_pkey_keygen_init(ctx) == 1 && LibCrypto.evp_pkey_keygen(ctx, pointerof(pkey)) == 1
          raise Ed25519Error.new "Could not generate a key"
        end
        new(pkey, true)
      ensure
        LibCrypto.evp_pkey_ctx_free(ctx)
      end
    end

    # Reads a PEM or base64 DER key, private or public, as
    # `OpenSSL::PKey.read` does, and refuses any key that is not Ed25519.
    def self.new(encoded : String, passphrase = nil)
      new(IO::Memory.new(encoded), passphrase)
    end

    def self.new(io : IO, passphrase = nil)
      pkey, is_private = OpenSSL::PKey.read_evp_pkey(io, passphrase)
      unless OpenSSL::PKey.get_pkey_id(pkey) == LibCrypto::EVP_PKEY_ED25519
        LibCrypto.evp_pkey_free(pkey)
        raise Ed25519Error.new("Not an Ed25519 key", fetched: true)
      end
      new(pkey, is_private)
    end

    # *seed* is the 32-byte secret key of RFC 8032.
    def self.from_raw_private_key(seed : Bytes) : Ed25519
      check_size(seed)
      pkey = LibCrypto.evp_pkey_new_raw_private_key(LibCrypto::EVP_PKEY_ED25519, nil, seed, seed.size)
      raise Ed25519Error.new "Could not load the private key" if pkey.null?
      new(pkey, true)
    end

    def self.from_raw_public_key(key : Bytes) : Ed25519
      check_size(key)
      pkey = LibCrypto.evp_pkey_new_raw_public_key(LibCrypto::EVP_PKEY_ED25519, nil, key, key.size)
      raise Ed25519Error.new "Could not load the public key" if pkey.null?
      new(pkey, false)
    end

    private def self.check_size(key : Bytes)
      return if key.size == KEY_SIZE
      raise Ed25519Error.new("An Ed25519 key is #{KEY_SIZE} bytes, got #{key.size}", fetched: true)
    end

    def raw_private_key : Bytes
      raise Ed25519Error.new("Private key is needed", fetched: true) unless private?
      raw { |buf, len| LibCrypto.evp_pkey_get_raw_private_key(self, buf, len) }
    end

    def raw_public_key : Bytes
      raw { |buf, len| LibCrypto.evp_pkey_get_raw_public_key(self, buf, len) }
    end

    private def raw(&)
      buf = Bytes.new(KEY_SIZE)
      len = LibC::SizeT.new(buf.size)
      raise Ed25519Error.new "Could not export the raw key" unless yield(buf.to_unsafe, pointerof(len)) == 1
      buf[0, len]
    end

    def public_key : Ed25519
      Ed25519.from_raw_public_key(raw_public_key)
    end

    def sign(data) : Bytes
      raise Ed25519Error.new("Private key is needed", fetched: true) unless private?
      data = data.to_slice

      with_md_ctx do |ctx|
        raise Ed25519Error.new "Unable to sign" unless LibCrypto.evp_digest_sign_init(ctx, nil, nil, nil, self) == 1

        signature = Bytes.new(SIGNATURE_SIZE)
        len = LibC::SizeT.new(signature.size)
        unless LibCrypto.evp_digest_sign(ctx, signature, pointerof(len), data, data.size) == 1
          raise Ed25519Error.new "Unable to sign"
        end
        signature[0, len]
      end
    end

    # Returns false for every signature that does not verify, including one of
    # the wrong length, and raises only when the key itself cannot verify.
    def verify(signature, data) : Bool
      signature = signature.to_slice
      data = data.to_slice

      with_md_ctx do |ctx|
        raise Ed25519Error.new "Unable to verify" unless LibCrypto.evp_digest_verify_init(ctx, nil, nil, nil, self) == 1

        next true if LibCrypto.evp_digest_verify(ctx, signature, signature.size, data, data.size) == 1

        # A rejected signature leaves its reason on OpenSSL's error queue,
        # where the next unrelated OpenSSL::Error would report it.
        LibCrypto.err_clear_error
        false
      end
    end

    # `PKey#sign(digest, data)` with a nil digest, so code written over any
    # `PKey` can sign with an Ed25519 key. A real digest is refused.
    def sign(digest : Nil, data) : Bytes
      sign(data)
    end

    def sign(digest, data)
      raise Ed25519Error.new(NO_DIGEST, fetched: true)
    end

    def verify(digest : Nil, signature, data) : Bool
      verify(signature, data)
    end

    def verify(digest, signature, data)
      raise Ed25519Error.new(NO_DIGEST, fetched: true)
    end

    private def with_md_ctx(&)
      ctx = LibCrypto.evp_md_ctx_new
      raise Ed25519Error.new "Could not allocate a digest context" if ctx.null?

      begin
        yield ctx
      ensure
        LibCrypto.evp_md_ctx_free(ctx)
      end
    end
  end
end
