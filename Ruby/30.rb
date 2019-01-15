# Challenge 30: break an MD4 keyed MAC using length-extension.

require_relative 'matasano_lib/monkey_patch'

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
end

class MD4_MAC < MD4
  def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476)
    super(key + message, ml, h0, h1, h2, h3)
  end

  def self.verify(key, message, digest)
    MD4_MAC.new(key, message).digest == digest
  end
end

class Oracle
  # Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:
  # "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
  def initialize
    @key = File.readlines('/usr/share/dict/words').sample[0, 32].chomp  # Ensure the key is ≤ 256 bits (32 bytes) as per this particular demonstration.
  end

  # Returns a new MD4 MAC digest with a random key.
  def generate_digest(message)
    MD4_MAC.new(@key, message).digest
  end

  # Performs MAC verification given a message and its digest under a secret key only known by the oracle.
  def verify(message, digest)
    MD4_MAC::verify(@key, message, digest)
  end
end

# To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your MD4 implementation is using.
# This should take you 5-10 minutes.
#   -> (More like 10 seconds rofl.)
def pad(message)
  ml = message.size * 8

  message += 0x80.chr
  message += "\0" * ((448 / 8 - message.size) & ((512 - 1) / 8))
  message += [ml].pack('Q<')
end

# Now, take the MD4 secret-prefix MAC of the message you want to forge -- this is just a MD4 hash -- and break it into 32 bit MD4 registers (MD4 calls them "a", "b", "c", etc.).
def internal_state(digest)
  # Reverse the final step in MD4 to retrieve the internal state such that you can clone the state, ultimately allowing us to suffix a payload.
  # I.e., this gives us our four 32-bit MD4 registers, which will be fixated for forging.
  digest.unpack('V4')
end

# Performs a length-extension attack on a MD4 MAC with a secret-key.
# Forges a variant of the given message such that it is suffixed with payload (';admin=true').
# Returns the newly-constructed (forged) message and its respective, valid MD4 MAC digest.
def length_extension_attack(mac, message, payload, oracle)
  # We will assume a 256-bit key (for no real reason other than a more realistic demonstration).
  (0..32).each do |key_size|
    # The forged message is constructed as MD4(key || original-message || glue-padding || new-message).
    # The key need not be the true key, as we only care about the key-size, as per the way Merkle-Damgard constructed digests are padded.
    # Hence, we can use any key for the glue-padding, so long as the guessed key-size is correct.
    forged_message = pad('A' * key_size + message)[key_size..-1] + payload

    # With the registers "fixated", hash the additional data you want to forge.
    registers  = internal_state(mac)
    md4_mac    = MD4_MAC.new('', payload, (key_size + forged_message.size) * 8, *registers)
    forged_mac = md4_mac.digest

    if oracle.verify(forged_message, forged_mac)
      return [forged_message, forged_mac, key_size]
    end
  end

  raise 'MD4 length-extension attack failed.'
end

# Forge a variant of this message that ends with ";admin=true".
oracle      = Oracle.new
message     = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
message_mac = oracle.generate_digest(message)
payload     = ';admin=true'

forged_message, forged_mac, key_size = length_extension_attack(message_mac, message, payload, oracle)

# Assert that the forged message does include ';admin=true' as a substring (can also check -payload.size bytes back since it is suffixed).
# This means we've successfully added a flag with which we would have privilege escalation from a guest and/or typical, low-privileged user.
# (Note we have already verified the forged MAC.)
unless forged_message.include?(';admin=true')
  raise "Payload injection unsuccessful: '#{payload}' not in forged message despite a verified forged MAC."
end

puts "[+] Original message: #{message}"
puts "[+] Original MAC: #{message_mac.to_hex}"
puts
puts "[+] Forged message: #{forged_message}"
puts "[+] Forged MAC: #{forged_mac.to_hex}"
puts "[+] Determined key-size: #{key_size}"

# Output:
# ------------------------------------------------------------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys000] [master ⚡] [~/Projects/Matasano/Ruby]> for i in {1..8}; do ruby 30.rb  && echo "\n<---------->\n"; done
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: e7780e785b713342785de397ce9a720c
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 7aa7e13c9c4f30885996597b2b83483b
# [+] Determined key-size: 10
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: bb2e68d570eb0a10530d5b94dec050a4
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: e1233794774bc7d800517ba3ac3b1a3b
# [+] Determined key-size: 12
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: a3a4c0ea7d2ca6900b30c0430b22d628
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 756a137654a8d5e5db8330315f15f16b
# [+] Determined key-size: 12
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 3a394ae31b91d5be03badceb841c4367
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 71785c80e5d2102d103861198866bced
# [+] Determined key-size: 13
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 28bac2f2a7ce8f79d25861ce31b83d6a
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 16c422a4bf7f723b704871dfa9feb7a0
# [+] Determined key-size: 6
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: e12a1ebbefcfce71b06be0dc12c458ff
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 5b81ffeb7bcbd328722a7454fe01b42d
# [+] Determined key-size: 6
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 425eaa06eef19a0fb8948edc3ba54711
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 1e125ad1507d050b77eedd8d9370fe9d
# [+] Determined key-size: 14
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 2b01c612bccbf247b8559dbc496678c1
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon��;admin=true
# [+] Forged MAC: 25ca30b0ae76a291d918c2a28c52aa8d
# [+] Determined key-size: 6
# 
# <---------->
