# Challenge 28: implement a SHA-1 keyed MAC.

# Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
# SHA1(key || message)

# Don't cheat. It won't work.
# ---------------------------
# Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
# (This is because I will need the code in the following challenges for the rest of the set).

require_relative 'matasano_lib/monkey_patch'

# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
#         ml, the message length, which is a 64-bit quantity, and
#         hh, the message digest, which is a 160-bit quantity.
#
# Note 2: All constants in this pseudo-code are in big-endian.
#         Within each word, the most significant byte is stored in the left-most byte position.
class SHA1
  BLOCKSIZE = 64

  attr_reader :digest, :hex_digest

  # 32-bit cyclic left-rotation.
  # (Generic version added to monkey patch.)
  private def left_rotate(value, shift)
    (value << shift & 0xffffffff) | value >> (32 - shift)
  end

  # Initialize variables:
  #
  # Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c", etc. (they normally start at magic numbers).
  # With the registers "fixated", hash the additional data you want to forge.
  def initialize(message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0)
    # Message length in bits (always a multiple of the number of bits in a character).
    ml ||= message.size * 8

    # Pre-processing:
    # ---------------
    # Append the bit '1' to the message; e.g., by adding 0x80 if message length is a multiple of 8 bits.
    message += 0x80.chr

    # Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512).
    # Since 512 is a power of two (2**9), it is much faster to perform modulo via bitwise (i & (n - 1)) than via the modulo operator (%).
    message += "\0" * (56 - (message.size & 63) & 63)  # 56 = 448 / 8, and 63 = 512 / 8 - 1. (Readable equivalent for the latter would be '% 64'.)

    # Append ml, the original message length, as an (unsigned) 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
    message += [ml].pack('Q>')

    # Process the message in successive 512-bit chunks:
    message.bytes.each_slice(BLOCKSIZE).each do |chunk|
      # For each chunk, break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15.
      w = chunk.pack('C*').unpack('N16')

      # Extend the sixteen 32-bit w into eighty 32-bit w:
      (16..79).each do |i|
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
      end

      # Initialize hash value for this chunk:
      a = h0
      b = h1
      c = h2
      d = h3
      e = h4

      # Main loop:
      (0..79).each do |i|
        if i <= 19
          f = (b & c) | ((~b) & d)
          k = 0x5A827999
        elsif i.between?(20, 39)
          f = b ^ c ^ d
          k = 0x6ED9EBA1
        elsif i.between?(40, 59)
          f = (b & c) | (b & d) | (c & d)
          k = 0x8F1BBCDC
        elsif i.between?(60, 79)
          f = b ^ c ^ d
          k = 0xCA62C1D6
        end

        temp = left_rotate(a, 5) + f + e + k + w[i] & 0xffffffff
        e    = d
        d    = c
        c    = left_rotate(b, 30)
        b    = a
        a    = temp
      end

      # Add this chunk's hash to result so far:
      h0 = (h0 + a) & 0xffffffff
      h1 = (h1 + b) & 0xffffffff
      h2 = (h2 + c) & 0xffffffff
      h3 = (h3 + d) & 0xffffffff
      h4 = (h4 + e) & 0xffffffff
    end

    # Produce the final hash value (big-endian) as a 160-bit number:
    # Return the hash / message digest as raw bytes:
    @digest     = [h0, h1, h2, h3, h4].pack('N5')  # 32-bit unsigned, big endian.
    @hex_digest = @digest.to_hex

    # Alternative/old method:
    # hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    # @digest = [hh.to_s(16).rjust(40, '0')].pack('H*')
  end

  def self.digest(message)
    new(message).digest
  end

  def self.hex_digest(message)
    new(message).hex_digest
  end
end

class SHA1_MAC
  attr_reader :digest, :hex_digest

  def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0)
    sha1 = SHA1.new(key + message, ml, h0, h1, h2, h3, h4)

    @digest     = sha1.digest
    @hex_digest = sha1.hex_digest
  end

  def self.digest(key, message)
    new(key, message).digest
  end

  def self.hex_digest(key, message)
    new(key, message).hex_digest
  end
end

puts SHA1::hex_digest('The quick brown fox jumps over the lazy dog')
puts SHA1::hex_digest('The quick brown fox jumps over the lazy cog')
puts SHA1::hex_digest('')
puts SHA1::hex_digest('blah')
puts
puts SHA1_MAC::hex_digest('Some key.', 'The quick brown fox jumps over the lazy dog')
puts SHA1_MAC::hex_digest('Some key.', 'blah')

# Output:
# ----------------------------------------------------------
# [josh@jizzo:~/Projects/Matasano/Ruby on master] ruby 28.rb
# 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
# de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3
# da39a3ee5e6b4b0d3255bfef95601890afd80709
# 5bf1fd927dfb8679496a2e6cf00cbe50c1c87145
# 
# 88ef13fb78b506e9f373d1023571070564b422d
# 10f2518e886875283ed03eb16d13ef6aecde988
