require 'sinatra'

require_relative 'matasano_lib/digest'

class SHA1_HMAC
  attr_reader :digest, :hex_digest

  BLOCKSIZE = 64

  def initialize(key, message)
    # Per RFC 2104 -- https://en.wikipedia.org/wiki/HMAC
    #   HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m)) such that 
    #   K' = H(K) if K > blocksize; else, K
    key = SHA1.new(key).digest if key.size > BLOCKSIZE
    key = key.ljust(BLOCKSIZE, "\0")  # We must pad to 64 bytes either way (whether key is hashed to 20 bytes or plaintext/unchanged).

    o_key_pad = key.bytes.map { |k| (k ^ 0x5c) }.pack('C*')
    i_key_pad = key.bytes.map { |k| (k ^ 0x36) }.pack('C*')

    sha1_hmac = SHA1.new(o_key_pad + SHA1.digest(i_key_pad + message))  # HMAC(K, m)

    @digest     = sha1_hmac.digest
    @hex_digest = sha1_hmac.hex_digest
  end

  def self.digest(key, message)
    new(key, message).digest
  end

  def self.hex_digest(key, message)
    new(key, message).hex_digest
  end

  # Not used for challenges but could be useful for testing.
  def self.verify(key, message, digest)
    new(key, message).digest == digest
  end
end

class Oracle
  HMAC_KEY = 'YELLOW SUBMARINE'

  def initialize(file)
    @hmac = MatasanoLib::Digest::SHA1_HMAC.hex_digest(HMAC_KEY, file)
  end

  def insecure_compare(signature)
    return false unless signature.bytesize == @hmac.bytesize

    # Validate HMAC signature with byte-at-a-time comparison (insecurely).
    @hmac.bytes.zip(signature.bytes).each do |b1, b2|
      return false if b1 != b2  # Exit early if bytes do not match (vulnerability part 1/2).
      sleep(0.0001)             # Artificial timing leak of 0.1ms (vulnerability part 2/2).
    end

    true  # Bytes match (artificial delay in effect).
  end
end

get '/test' do
  file, signature = params['file'], params['signature']

  oracle = Oracle.new(file)

  if oracle.insecure_compare(signature)
    status 200
    body '200 OK'
  else
    halt 500, '500 Internal Server Error'
  end
end
