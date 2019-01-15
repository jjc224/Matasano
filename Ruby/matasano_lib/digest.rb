require_relative 'monkey_patch'

module MatasanoLib
  module Digest
    # -- SHA-1 -- #

    # Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
    #         ml, the message length, which is a 64-bit quantity, and
    #         hh, the message digest, which is a 160-bit quantity.
    #
    # Note 2: All constants in this pseudo-code are in big-endian.
    #         Within each word, the most significant byte is stored in the left-most byte position.
    class SHA1
      attr_reader :digest

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
        message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))

        # Append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
        message += [ml].pack('Q>')  # Unsigned 64-bit integer (big-endian).

        # Process the message in successive 512-bit chunks:
        message.chunk(64).each do |chunk|
          # For each chunk, break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15.
          w = chunk.chunk(64 / 16).map { |word| word.unpack('L>')[0] }

          # Extend the sixteen 32-bit w into eighty 32-bit w:
          (16..79).each do |i|
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).left_rotate(1)
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

            temp = a.left_rotate(5) + f + e + k + w[i] & 0xffffffff
            e    = d
            d    = c
            c    = b.left_rotate(30)
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
        hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

        # Return the hash / message digest as hex:
        @digest = hh
      end

      def hex_digest
        @digest.to_hex
      end

      # To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using.
      # This should take you 5-10 minutes.
      #   -> (More like 10 seconds rofl.)
      def self.pad(message)
        ml = message.size * 8

        message += 0x80.chr
        message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))
        message += [ml].pack('Q>')
      end

      # Now, take the SHA-1 secret-prefix MAC of the message you want to forge -- this is just a SHA-1 hash -- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", etc.).
      def self.state(digest)
        # Translate hexadecimal MAC to integer equivalent if needed (i.e., SHA1_MAC.hex_digest -> SHA1_MAC.digest).
        digest = digest.to_i(16) unless digest.is_a?(Integer)

        # Reverse the final step in SHA-1 to retrieve the internal state for cloning state, ultimately allowing us to suffix a payload.
        # I.e., this gives us our five 32-bit SHA-1 registers.
        a = (digest >> 128) & 0xffffffff
        b = (digest >> 96)  & 0xffffffff
        c = (digest >> 64)  & 0xffffffff
        d = (digest >> 32)  & 0xffffffff
        e = digest          & 0xffffffff

        [a, b, c, d, e]
      end

      def self.length_extension_attack(mac, message, payload, oracle)
        Digest::Attack::length_extension_attack(mac, message, payload, oracle, SHA1_MAC)
      end
    end

    class SHA1_MAC < SHA1
      attr_accessor :key

      def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0)
        super(key + message, ml, h0, h1, h2, h3, h4)
      end

      def self.verify(key, message, digest)
        SHA1_MAC.new(key, message).digest == digest
      end
    end  


    # -- MD4 -- #

    class MD4
      attr_reader :digest

      def initialize(message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476)
        f = proc { |x, y, z| x & y | ~x & z }
        g = proc { |x, y, z| x & y | x & z | y & z }
        h = proc { |x, y, z| x ^ y ^ z }

        # Message length in bits (always a multiple of the number of bits in a character).
        ml ||= message.size * 8

        # Append the bit '1' to the message; e.g., by adding 0x80 if message length is a multiple of 8 bits.
        message += 0x80.chr

        # Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512).
        # Since 512 is a power of two (2**9), it is much faster to perform modulo via bitwise (i & (n - 1)) than via the modulo operator (%).
        message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))

        # Append ml, the original message length, as a 64-bit little-endian integer. Thus, the total length is a multiple of 512 bits.
        message += [ml].pack('Q<')  # Unsigned 64-bit integer (little-endian).

        # Process the message in successive 512-bit chunks:
        message.chunk(64).each do |chunk|
          # Break chunk into sixteen 32-bit (unsigned) little-endian words x[i], 0 ≤ i ≤ 15.
          x = chunk.unpack('V16')

          # Initialize hash value for this chunk:
          a = h0
          b = h1
          c = h2
          d = h3

          # Round 1.
          # Let [abcd k s] denote the operation:
          #   a = (a + F(b,c,d) + X[k]) <<< s
          # Do the following 16 operations:
          #   [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
          #   [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
          #   [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
          #   [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]
          [0, 4, 8, 12].each do |i|
            a = (a + f[b, c, d] + x[i]).left_rotate(3)
            d = (d + f[a, b, c] + x[i + 1]).left_rotate(7)
            c = (c + f[d, a, b] + x[i + 2]).left_rotate(11)
            b = (b + f[c, d, a] + x[i + 3]).left_rotate(19)
          end

          # Round 2.
          # Let [abcd k s] denote the operation:
          #   a = (a + G(b,c,d) + X[k] + 5A827999) <<< s
          # Do the following 16 operations:
          #   [ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
          #   [ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
          #   [ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
          #   [ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]
          [0, 1, 2, 3].each do |i|
            a = (a + g[b, c, d] + x[i]       + 0x5A827999).left_rotate(3)
            d = (d + g[a, b, c] + x[i + 4]   + 0x5A827999).left_rotate(5)
            c = (c + g[d, a, b] + x[i + 8]   + 0x5A827999).left_rotate(9)
            b = (b + g[c, d, a] + x[i + 12]  + 0x5A827999).left_rotate(13)
          end

          # Round 3.
          # Let [abcd k s] denote the operation:
          #   a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s
          # Do the following 16 operations:
          #   [ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
          #   [ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
          #   [ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
          #   [ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]
          [0, 2, 1, 3].each do |i|
            a = (a + h[b, c, d] + x[i]       + 0x6ED9EBA1).left_rotate(3)
            d = (d + h[a, b, c] + x[i + 8]   + 0x6ED9EBA1).left_rotate(9)
            c = (c + h[d, a, b] + x[i + 4]   + 0x6ED9EBA1).left_rotate(11)
            b = (b + h[c, d, a] + x[i + 12]  + 0x6ED9EBA1).left_rotate(15)
          end

          # Add this chunk's hash to result so far:
          h0 = (h0 + a) & 0xffffffff
          h1 = (h1 + b) & 0xffffffff
          h2 = (h2 + c) & 0xffffffff
          h3 = (h3 + d) & 0xffffffff
        end

        # Produce the final unsigned 128-bit (little-endian) hash/digest:
        @digest = [h0, h1, h2, h3].pack('V4')
      end

      # To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your MD4 implementation is using.
      # This should take you 5-10 minutes.
      #   -> (More like 10 seconds rofl.)
      def self.pad(message)
        ml = message.size * 8

        message += 0x80.chr
        message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))
        message += [ml].pack('Q<')
      end

      # Now, take the MD4 secret-prefix MAC of the message you want to forge -- this is just a MD4 hash -- and break it into 32 bit MD4 registers (MD4 calls them "a", "b", "c", etc.).
      def self.state(digest)
        # Reverse the final step in MD4 to retrieve the internal state such that you can clone the state, ultimately allowing us to suffix a payload.
        # I.e., this gives us our four 32-bit MD4 registers, which will be fixated for forging.
        digest.unpack('V4')
      end

      def self.length_extension_attack(mac, message, payload, oracle)
        Digest::Attack::length_extension_attack(mac, message, payload, oracle, MD4_MAC)
      end
    end

    class MD4_MAC < MD4
      def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476)
        super(key + message, ml, h0, h1, h2, h3)
      end

      def self.verify(key, message, digest)
        MD4_MAC.new(key, message).digest == digest
      end
    end


    # -- Auxiliary -- #

    module Attack
      module_function

      # Performs a length-extension attack on a MAC with a secret-key.
      # Forges a variant of the given message such that it is suffixed with payload (';admin=true').
      # Returns the newly-constructed (forged) message and its respective, valid MAC digest.
      def length_extension_attack(mac, message, payload, oracle, type)
        # We will assume a 256-bit key (for no real reason other than a more realistic demonstration).
        (0..32).each do |key_size|
          # The forged message is constructed as H(key || original-message || glue-padding || new-message).
          # The key need not be the true key, as we only care about the key-size, as per the way Merkle-Damgard constructed digests are padded.
          # Hence, we can use any key for the glue-padding, so long as the guessed key-size is correct.
          forged_message = type.pad('A' * key_size + message)[key_size..-1] + payload

          # With the registers "fixated", hash the additional data you want to forge.
          registers  = type.state(mac)
          forged_mac = type.new('', payload, (key_size + forged_message.size) * 8, *registers).digest

          if oracle.verify(forged_message, forged_mac)
            return [forged_message, forged_mac, key_size]
          end
        end

        raise 'Length-extension attack failed.'
      end
    end
  end
end
