# NOTE/TODO: MatasanoLib::Digest::SHA1 needs fixing - digests are only correct for some inputs.
#            Using OpenSSL for correctness for now.

require 'sinatra'
require 'openssl'
require 'securerandom'

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/xor'

HMAC_KEY = 'YELLOW SUBMARINE'

class MyDigest
  def self.HMAC_SHA1(key, message)
    key = OpenSSL::Digest::SHA1.digest(key).digest if key.size > 64
    key = pad(key)                                 if key.size < 64

    opad = MatasanoLib::XOR.crypt("\x5c" * 64, key).unhex
    ipad = MatasanoLib::XOR.crypt("\x36" * 64, key).unhex

    sha1 = OpenSSL::Digest::SHA1.new
    data = opad + OpenSSL::Digest::SHA1.digest(ipad + message)
    sha1.digest(data).to_hex
  end

  def self.pad(key)
    key + "\0" * (64 - (key.size % 64))
  end
end

class Oracle
  attr_reader :file, :key, :hmac

  def initialize(file)
    @file = file
    @key  = HMAC_KEY
    @hmac = MyDigest::HMAC_SHA1(@key, @file)
  end

  def insecure_compare(signature)
    # Break into two chunks because we're dealing with hexadecimal: two chars equals one byte.
    @hmac.chunk(2).zip(signature.chunk(2)).each do |c1, c2|
      return false if c1 != c2  # Exit early if bytes match (vulnerability part 1/2).
      sleep(0.005)              # Artificial timing leak (vulnerability part 2/2).
    end

    true
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
