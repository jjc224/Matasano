#require 'sinatra'
require_relative 'matasano_lib/digest'
require_relative 'matasano_lib/xor'

#require 'openssl'

#get '/' do
#  'Hello, world!'
#end

include MatasanoLib::Digest

def HMAC_SHA1(key, message)
  key = SHA1.new(key).hex_digest.unhex if key.size > 64
  key += "\0" * (64 - key.size)        if key.size < 64

  opad = MatasanoLib::XOR.crypt(0x5c.chr * 64, key).unhex
  ipad = MatasanoLib::XOR.crypt(0x36.chr * 64, key).unhex

  p [key, opad, ipad]
  puts

  #sha1 = OpenSSL::Digest::SHA1.new
  #data = opad
  #data += OpenSSL::Digest.digest(ipad + message)
  #sha1.digest(data)

  SHA1.new(opad + SHA1.new(ipad + message).hex_digest.unhex).hex_digest
end

def pad(key)
  #key += "\0" * (64 - (key.size % 64))
  key += "\0" * (64 - key.size)
end

puts
p HMAC_SHA1('key', 'The quick brown fox jumps over the lazy dog')
p HMAC_SHA1('', '')
