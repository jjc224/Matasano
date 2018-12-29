# Challenge 28: implement a SHA-1 keyed MAC.

# Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:
# SHA1(key || message)

# Don't cheat. It won't work.
# ---------------------------
# Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
# (This is because I will need the code in the following challenges for the rest of the set).

require_relative 'matasano_lib/monkey_patch'

# TODO: Add to monkey patch and include a right-rotate just in case for the future?
#       Make generic if so? Simply done by an extra param n such that the mask becomes (1 << n) - 1 with value >> (n - shift).
# 32-bit cyclic left-rotation.
def left_rotate(value, shift)
  ((value << shift) & 0xffffffff) | (value >> (32 - shift))
end

# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
#         ml, the message length, which is a 64-bit quantity, and
#         hh, the message digest, which is a 160-bit quantity.
#
# Note 2: All constants in this pseudo-code are in big-endian.
#         Within each word, the most significant byte is stored in the left-most byte position.
class SHA1
  attr_reader :digest

  def initialize(message)
    # Initialize variables:
    @h0 = 0x67452301
    @h1 = 0xEFCDAB89
    @h2 = 0x98BADCFE
    @h3 = 0x10325476
    @h4 = 0xC3D2E1F0

    # Message length in bits (always a multiple of the number of bits in a character).
    @ml = message.size * 8

    # Pre-processing:
    # ---------------
    # Append the bit '1' to the message; e.g., by adding 0x80 if message length is a multiple of 8 bits.
    message += 0x80.chr

    # Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512).
    # Since 512 is a power of two (2**9), it is much faster to perform modulo via bitwise (i & (n - 1)) than via the modulo operator (%).
    message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))

    # Append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
    message += [@ml].pack('Q>')  # Unsigned 64-bit integer (big-endian).

    # Process the message in successive 512-bit chunks:
    message.chunk(64).each do |chunk|
      # For each chunk, break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15.
      w = chunk.chunk(64 / 16).map { |word| word.unpack('L>')[0] }

      # Extend the sixteen 32-bit w into eighty 32-bit w:
      (16..79).each do |i|
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
      end

      # Initialize hash value for this chunk:
      a = @h0
      b = @h1
      c = @h2
      d = @h3
      e = @h4

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
      @h0 = (@h0 + a) & 0xffffffff
      @h1 = (@h1 + b) & 0xffffffff
      @h2 = (@h2 + c) & 0xffffffff
      @h3 = (@h3 + d) & 0xffffffff
      @h4 = (@h4 + e) & 0xffffffff
    end

    # Produce the final hash value (big-endian) as a 160-bit number:
    hh = (@h0 << 128) | (@h1 << 96) | (@h2 << 64) | (@h3 << 32) | @h4

    # Return the hash / message digest as hex:
    @digest = hh.to_hex
  end
end

class SHA1_MAC < SHA1
  def initialize(key, message)
    super(key + message)
  end
end

p SHA1.new('The quick brown fox jumps over the lazy dog').digest
p SHA1.new('The quick brown fox jumps over the lazy cog').digest
p SHA1.new('').digest
puts
p SHA1_MAC.new('Some key.', 'The quick brown fox jumps over the lazy dog').digest

# Output:
# ----------------------------------------------------------
# [josh@jizzo:~/Projects/Matasano/Ruby on master] ruby 28.rb
# "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
# "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
# "da39a3ee5e6b4b0d3255bfef95601890afd80709"
#
# "f88ef13fb78b506e9f373d1023571070564b422d"
