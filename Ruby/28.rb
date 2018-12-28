# Challenge 28: implement a SHA-1 keyed MAC. 

# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
#         ml, the message length, which is a 64-bit quantity, and
#         hh, the message digest, which is a 160-bit quantity.
#
# Note 2: All constants in this pseudo-code are in big-endian.
#         Within each word, the most significant byte is stored in the left-most byte position.
class SHA1
  # Initialize variables:
  @@h0 = 0x67452301
  @@h1 = 0xEFCDAB89
  @@h2 = 0x98BADCFE
  @@h3 = 0x10325476
  @@h4 = 0xC3D2E1F0

  def initialize(message)
    # Message length in bits (always a multiple of the number of bits in a character).
    @ml = message.size * 8
    
    # Pre-processing:
    # --------------
    # Append the bit '1' to the message; e.g., by adding 0x80 if message length is a multiple of 8 bits.
    message += 0x80.chr  # It's always a multiple of 8 bits, as per `@ml`.

    # Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512).
    message += "\0" * (447 - @ml) & (512 - 1)  # Since 512 is a power of two (2**9), it is much faster to perform modulo by `i & (n - 1)`.

    # Append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.
    message += [@ml].pack('Q>')  # Unsigned 64-bit integer (big-endian).

  end
end
