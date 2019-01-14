# Challenge 29: break a SHA-1 keyed MAC using length-extension.

# Secret-prefix SHA-1 MACs are trivially breakable.
#
# The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
# Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.
#
# To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding.
# We call this "glue padding". The final message you actually forge will be:
#
# SHA1(key || original-message || glue-padding || new-message)
#
# (where the final padding on the whole constructed message is implied)
#
# Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
# This sounds more complicated than it is in practice.

require_relative 'matasano_lib/sha1'

include MatasanoLib

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
end

class SHA1_MAC < SHA1
  attr_accessor :key

  def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0)
    super(key + message, ml, h0, h1, h2, h3, h4)
  end

  def verify(message)
    @digest == SHA1_MAC.new(KEY, message).digest
  end
end

# To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using.
# This should take you 5-10 minutes.
#   -> (More like 10 seconds rofl.)
def pad(message)
  ml = message.size * 8

  message += 0x80.chr
  message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))
  message += [ml].pack('Q>')
end

# Now, take the SHA-1 secret-prefix MAC of the message you want to forge -- this is just a SHA-1 hash -- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", etc.).
def state(digest)
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

def length_extension_attack(mac, message, payload)
  # We will assume up to a 256-bit key (for no real reason other than demonstration).
  (0..32).each do |key_size|
    forged_message = pad('A' * key_size + message)[key_size..-1] + payload
    sha1_mac       = SHA1_MAC.new('', payload, (key_size + forged_message.size) * 8, *state(mac))
    forged_mac     = sha1_mac.digest

    if sha1_mac.verify(forged_message)
      return [forged_message, forged_mac, key_size]
    end
  end

  raise 'SHA-1 length-extension attack failed.'
end

# Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:
# "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
KEY     = File.readlines('/usr/share/dict/words').sample[0, 32].chomp  # Ensure the key is ≤ 256 bits as per this particular demonstration.
message = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'

# Forge a variant of this message that ends with ";admin=true".
message_mac = SHA1_MAC.new(KEY, message).digest
payload     = ';admin=true'

forged_message, forged_mac, key_size = length_extension_attack(message_mac, message, payload)
raise "Payload injection not entirely successful: #{payload} not in forged message." unless forged_message.include?(';admin=true')

puts "[+] Original message: #{message}"
puts "[+] Original MAC: #{message_mac.to_hex}"
puts
puts "[+] Forged message: #{forged_message}"
puts "[+] Forged MAC: #{forged_mac.to_hex}"
puts "[+] Determined key-size: #{key_size}"

# Output:
# -----------------------------------------------------------------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys002] [master ⚡] [~/Projects/Matasano/Ruby]> for i in {1..8}; do ruby 29_other.rb && echo "\n<---------->\n"; done
#
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 1364043312993936405245046336086713586816082180621
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 1073363108248356387979110315233622829983681128082
# [+] Determined key-size: 5
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 1318505146926662719511180311242812175145960005453
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 266351775904381741242407278603150132491016761200
# [+] Determined key-size: 10
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 169078026203637058668788470453826660471149508345
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 697720360276698327461582907233875925003212177371
# [+] Determined key-size: 10
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 785567993982986776412330106129493176274855975041
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 787283702797490409601020113678676943769892959758
# [+] Determined key-size: 9
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 942559984779095756508382273323558394715428859998
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 731051995359260150957930871762487323313531667106
# [+] Determined key-size: 11
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 729195683821557351624826425434357726432312483412
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 594947050219617828738518175656568068355363753075
# [+] Determined key-size: 9
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 543893416812179268425484852169837254949141738709
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 886779176114416459738572071992209268787069510839
# [+] Determined key-size: 11
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 1184936309796577519623836230381011893049853497249
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 1419876567968266581395825392688392695965644691006
# [+] Determined key-size: 7
# 
# <---------->
