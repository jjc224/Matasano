require_relative 'monkey_patch'

module MatasanoLib
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
          w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).left_rotate(1)
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

          temp = a.left_rotate(5) + f + e + k + w[i] & 0xffffffff
          e    = d
          d    = c
          c    = b.left_rotate(30)
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
end
