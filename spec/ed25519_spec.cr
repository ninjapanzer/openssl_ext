require "./spec_helper"
require "../src/openssl_ext/pkey/ed25519"
require "file_utils"

# RFC 8032, section 7.1: secret key, public key, message, signature.
RFC8032_VECTORS = {
  "TEST 1" => {
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  "TEST 2" => {
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "72",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  "TEST 3" => {
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "af82",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
  "TEST 1024" => {
    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
    "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
  },
  "TEST SHA(abc)" => {
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  },
}

X25519_PUBLIC_PEM = <<-PEM
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VuAyEA79EskvvEP8uSePAz2tmWynNI4z97aOY0huWIoIw6wzU=
  -----END PUBLIC KEY-----
  PEM

def flip_bit(bytes : Bytes, index : Int32) : Bytes
  bytes.dup.tap { |copy| copy[index] ^= 0x01 }
end

def openssl_cli(*args) : Process::Status
  Process.run("openssl", args.to_a, error: IO::Memory.new)
end

describe OpenSSL::PKey::Ed25519 do
  describe "RFC 8032 test vectors" do
    RFC8032_VECTORS.each do |name, (secret, public, message, signature)|
      it "#{name}: derives the public key, signs, and verifies" do
        key = OpenSSL::PKey::Ed25519.from_raw_private_key(secret.hexbytes)
        key.raw_public_key.hexstring.should eq public
        key.sign(message.hexbytes).hexstring.should eq signature

        public_key = OpenSSL::PKey::Ed25519.from_raw_public_key(public.hexbytes)
        public_key.verify(signature.hexbytes, message.hexbytes).should be_true
      end
    end
  end

  describe "#verify" do
    secret, public, message, signature = RFC8032_VECTORS["TEST 3"]
    key = OpenSSL::PKey::Ed25519.from_raw_public_key(public.hexbytes)

    it "rejects a signature with one bit flipped in R" do
      key.verify(flip_bit(signature.hexbytes, 0), message.hexbytes).should be_false
    end

    it "rejects a signature with one bit flipped in S" do
      key.verify(flip_bit(signature.hexbytes, 40), message.hexbytes).should be_false
    end

    it "rejects a message with one bit flipped" do
      key.verify(signature.hexbytes, flip_bit(message.hexbytes, 1)).should be_false
    end

    it "rejects a signature made by another key" do
      other = OpenSSL::PKey::Ed25519.generate
      key.verify(other.sign(message.hexbytes), message.hexbytes).should be_false
    end

    it "rejects a good signature checked against another key" do
      other = OpenSSL::PKey::Ed25519.generate.public_key
      other.verify(signature.hexbytes, message.hexbytes).should be_false
    end

    it "rejects signatures of the wrong length without raising" do
      sig = signature.hexbytes
      key.verify(sig[0, 63], message.hexbytes).should be_false
      key.verify(sig + Bytes[0], message.hexbytes).should be_false
      key.verify(Bytes.empty, message.hexbytes).should be_false
    end

    it "rejects a signature whose S is not below the group order" do
      sig = signature.hexbytes[0, 32] + Bytes.new(32, 0xff_u8)
      key.verify(sig, message.hexbytes).should be_false
    end

    it "rejects every signature under a public key that is not a curve point" do
      bad_key = OpenSSL::PKey::Ed25519.from_raw_public_key(Bytes.new(32, 0xff_u8))
      bad_key.verify(signature.hexbytes, message.hexbytes).should be_false
    end

    it "leaves OpenSSL's error queue empty after a rejection" do
      key.verify(flip_bit(signature.hexbytes, 0), message.hexbytes).should be_false
      LibCrypto.err_get_error.should eq 0
    end

    it "verifies with a private key too" do
      private_key = OpenSSL::PKey::Ed25519.from_raw_private_key(secret.hexbytes)
      private_key.verify(signature.hexbytes, message.hexbytes).should be_true
    end
  end

  describe "empty input" do
    it "signs and verifies an empty String and empty Bytes alike" do
      key = OpenSSL::PKey::Ed25519.generate
      signature = key.sign("")
      signature.size.should eq OpenSSL::PKey::Ed25519::SIGNATURE_SIZE
      key.sign(Bytes.empty).should eq signature
      key.public_key.verify(signature, "").should be_true
      key.public_key.verify(signature, "x").should be_false
    end
  end

  describe ".generate" do
    it "makes a private key that signs and verifies" do
      key = OpenSSL::PKey::Ed25519.generate
      key.private?.should be_true
      key.raw_private_key.size.should eq OpenSSL::PKey::Ed25519::KEY_SIZE
      key.public_key.verify(key.sign("my test data"), "my test data").should be_true
    end

    it "makes a different key each time" do
      OpenSSL::PKey::Ed25519.generate.raw_private_key.should_not eq OpenSSL::PKey::Ed25519.generate.raw_private_key
    end
  end

  describe "raw keys" do
    secret, public, _, _ = RFC8032_VECTORS["TEST 1"]

    it "exports the 32 bytes it was loaded from" do
      OpenSSL::PKey::Ed25519.from_raw_private_key(secret.hexbytes).raw_private_key.hexstring.should eq secret
      OpenSSL::PKey::Ed25519.from_raw_public_key(public.hexbytes).raw_public_key.hexstring.should eq public
    end

    it "refuses a key that is not 32 bytes" do
      expect_raises(OpenSSL::PKey::Ed25519Error, /32 bytes, got 31/) do
        OpenSSL::PKey::Ed25519.from_raw_private_key(secret.hexbytes[0, 31])
      end
      expect_raises(OpenSSL::PKey::Ed25519Error, /32 bytes, got 33/) do
        OpenSSL::PKey::Ed25519.from_raw_public_key(public.hexbytes + Bytes[0])
      end
    end

    it "has no private half on a public key" do
      key = OpenSSL::PKey::Ed25519.from_raw_public_key(public.hexbytes)
      key.public?.should be_true
      expect_raises(OpenSSL::PKey::Ed25519Error, /Private key is needed/) { key.raw_private_key }
      expect_raises(OpenSSL::PKey::Ed25519Error, /Private key is needed/) { key.sign("data") }
    end
  end

  describe "PEM" do
    it "round-trips a private key" do
      key = OpenSSL::PKey::Ed25519.generate
      loaded = OpenSSL::PKey::Ed25519.new(key.to_pem)
      loaded.private?.should be_true
      loaded.raw_private_key.should eq key.raw_private_key
    end

    it "round-trips a public key" do
      key = OpenSSL::PKey::Ed25519.generate.public_key
      loaded = OpenSSL::PKey::Ed25519.new(key.to_pem)
      loaded.public?.should be_true
      loaded.raw_public_key.should eq key.raw_public_key
    end

    it "is what OpenSSL::PKey.read returns for an Ed25519 key" do
      key = OpenSSL::PKey::Ed25519.generate
      read = OpenSSL::PKey.read(key.to_pem)
      read.should be_a OpenSSL::PKey::Ed25519
      read.private?.should be_true
      public_read = OpenSSL::PKey.read(key.public_key.to_pem)
      public_read.should be_a OpenSSL::PKey::Ed25519
      public_read.public?.should be_true
    end

    it "refuses a key of another type" do
      rsa_pem = OpenSSL::PKey::RSA.new(2048).to_pem
      expect_raises(OpenSSL::PKey::Ed25519Error, /Not an Ed25519 key/) { OpenSSL::PKey::Ed25519.new(rsa_pem) }
    end

    it "makes OpenSSL::PKey.read raise for a key type it does not know" do
      expect_raises(OpenSSL::PKey::PKeyError, /unsupported key type/) { OpenSSL::PKey.read(X25519_PUBLIC_PEM) }
    end
  end

  describe "the digest-taking forms inherited from PKey" do
    key = OpenSSL::PKey::Ed25519.generate

    it "treat a nil digest as no digest" do
      signature = key.sign(nil, "data")
      signature.should eq key.sign("data")
      key.verify(nil, signature, "data").should be_true
      key.verify(nil, signature, "other").should be_false
    end

    it "refuse a real digest" do
      expect_raises(OpenSSL::PKey::Ed25519Error, /takes no digest/) { key.sign(OpenSSL::Digest.new("SHA256"), "data") }
      expect_raises(OpenSSL::PKey::Ed25519Error, /takes no digest/) do
        key.verify(OpenSSL::Digest.new("SHA256"), key.sign("data"), "data")
      end
    end
  end

  describe "interoperability with the openssl command" do
    message = "signed across implementations"

    it "makes signatures that openssl pkeyutl verifies" do
      key = OpenSSL::PKey::Ed25519.generate
      dir = File.tempname("ed25519")
      Dir.mkdir(dir)
      begin
        File.write(File.join(dir, "pub.pem"), key.public_key.to_pem)
        File.write(File.join(dir, "msg"), message)
        File.write(File.join(dir, "sig"), key.sign(message))
        openssl_cli("pkeyutl", "-verify", "-pubin", "-inkey", File.join(dir, "pub.pem"), "-rawin",
          "-in", File.join(dir, "msg"), "-sigfile", File.join(dir, "sig")).success?.should be_true

        File.write(File.join(dir, "sig"), flip_bit(key.sign(message), 0))
        openssl_cli("pkeyutl", "-verify", "-pubin", "-inkey", File.join(dir, "pub.pem"), "-rawin",
          "-in", File.join(dir, "msg"), "-sigfile", File.join(dir, "sig")).success?.should be_false
      ensure
        FileUtils.rm_rf(dir)
      end
    end

    it "verifies signatures made by openssl pkeyutl" do
      key = OpenSSL::PKey::Ed25519.generate
      dir = File.tempname("ed25519")
      Dir.mkdir(dir)
      begin
        File.write(File.join(dir, "key.pem"), key.to_pem)
        File.write(File.join(dir, "msg"), message)
        openssl_cli("pkeyutl", "-sign", "-inkey", File.join(dir, "key.pem"), "-rawin",
          "-in", File.join(dir, "msg"), "-out", File.join(dir, "sig")).success?.should be_true
        signature = File.read(File.join(dir, "sig")).to_slice
        key.public_key.verify(signature, message).should be_true
        key.public_key.verify(signature, message + "!").should be_false
      ensure
        FileUtils.rm_rf(dir)
      end
    end
  end
end
