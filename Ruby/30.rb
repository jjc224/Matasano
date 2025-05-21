# Challeng 30: break an MD4 keyed MAC using length-extension.

require_relative 'matasano_lib/monkey_patch'

class MD4
  BLOCKSIZE = 64

  attr_reader :digest, :hex_digest

  # 32-bit cyclic left-rotation.
  # (Generic version added to monkey patch.)
  private def left_rotate(value, shift)
    (value << shift & 0xffffffff) | value >> (32 - shift)
  end

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
    message += "\0" * (56 - (message.size & 63) & 63)  # 56 = 448 / 8, and 63 = 512 / 8 - 1. (Readable equivalent for the latter would be '% 64'.)

    # Append ml, the original message length, as an (unsigned) 64-bit little-endian integer. Thus, the total length is a multiple of 512 bits.
    message += [ml].pack('Q<')

    # Process the message in successive 512-bit chunks:
    message.bytes.each_slice(BLOCKSIZE).each do |chunk|
      # Break chunk into sixteen 32-bit (unsigned) little-endian words x[i], 0 ≤ i ≤ 15.
      x = chunk.pack('C*').unpack('V16')

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
        a = left_rotate(a + f[b, c, d] + x[i],     3)
        d = left_rotate(d + f[a, b, c] + x[i + 1], 7)
        c = left_rotate(c + f[d, a, b] + x[i + 2], 11)
        b = left_rotate(b + f[c, d, a] + x[i + 3], 19)
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
        a = left_rotate(a + g[b, c, d] + x[i]      + 0x5A827999, 3)
        d = left_rotate(d + g[a, b, c] + x[i + 4]  + 0x5A827999, 5)
        c = left_rotate(c + g[d, a, b] + x[i + 8]  + 0x5A827999, 9)
        b = left_rotate(b + g[c, d, a] + x[i + 12] + 0x5A827999, 13)
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
        a = left_rotate(a + h[b, c, d] + x[i]      + 0x6ED9EBA1, 3)
        d = left_rotate(d + h[a, b, c] + x[i + 8]  + 0x6ED9EBA1, 9)
        c = left_rotate(c + h[d, a, b] + x[i + 4]  + 0x6ED9EBA1, 11)
        b = left_rotate(b + h[c, d, a] + x[i + 12] + 0x6ED9EBA1, 15)
      end

      # Add this chunk's hash to result so far:
      h0 = (h0 + a) & 0xffffffff
      h1 = (h1 + b) & 0xffffffff
      h2 = (h2 + c) & 0xffffffff
      h3 = (h3 + d) & 0xffffffff
    end

    # Produce the final unsigned 128-bit (little-endian) hash/digest:
    @digest     = [h0, h1, h2, h3].pack('V4')
    @hex_digest = @digest.to_hex
  end


  def self.digest(message)
    new(message).digest
  end

  def self.hex_digest(message)
    new(message).hex_digest
  end
end

# MD4 keyed MAC (susceptible to length-extension attacks).
class MD4_MAC
  attr_reader :digest, :hex_digest

  def initialize(key, message, ml = nil, h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476)
    md4 = MD4.new(key + message, ml, h0, h1, h2, h3)

    @digest     = md4.digest
    @hex_digest = md4.hex_digest
  end

  def self.digest(key, message)
    new(key, message).digest
  end

  def self.hex_digest(key, message)
    new(key, message).hex_digest
  end

  def self.verify(key, message, digest)
    new(key, message).digest == digest
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
  message += "\0" * (56 - (message.size & 63) & 63)  # 56 = 448 / 8, and 63 = 512 / 8 - 1. (Readable equivalent for the latter would be '% 64'.)
  message += [ml].pack('Q<')
end

# Now, take the MD4 secret-prefix MAC of the message you want to forge -- this is just a MD4 hash -- and break it into 32 bit MD4 registers (MD4 calls them "a", "b", "c", etc.).
def extract_final_state(digest)
  # Check if a hex digest is passed instead and decode it (i.e., MD4_MAC.hex_digest -> MD4_MAC.digest).
  digest = digest.unhex if digest.is_a?(String) && digest.size == 40

  # Reverse the final step in MD4 to retrieve the internal state such that you can clone the state, ultimately allowing us to suffix a payload.
  # I.e., this gives us our four 32-bit MD4 registers, which will be fixated for forging.
  digest.unpack('V4')  # => [h0, h1, h2, h3]
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

    # With the registers 'fixated', hash the additional data you want to forge.
    registers  = extract_final_state(mac)
    md4_mac    = MD4_MAC.new('', payload, (key_size + forged_message.size) * 8, *registers)
    forged_mac = md4_mac.digest

    if oracle.verify(forged_message, forged_mac)
      return [forged_message, forged_mac, key_size]
    end
  end

  raise 'MD4 length-extension attack failed.'
end

# Forge a variant of this message that ends with ';admin=true'.
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
# [+] Original MAC: a4f6b9780d18335d4e87adfa5918ee2d
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 6e0565537b2881d9ea5020f429e8e413
# [+] Determined key-size: 7
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: ab6329a80b22fc8cf57beeef51dfaa1a
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 457e91ee664c5ee93c32f0628496107b
# [+] Determined key-size: 9
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 5791cb5d0e531388962b8d400da608bd
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: b9390a3e9eca81ec5ecdc0a0d926247e
# [+] Determined key-size: 6
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 248bf6793a0a21c5a7bd392e7f065dde
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 43490683d0d24b6098a29b3e94be8f4f
# [+] Determined key-size: 5
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 8f11e4203dc4bff9096b835a39b14593
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: c1e7cb8f3065db8ff29c55e1b3118fdb
# [+] Determined key-size: 14
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 52d4b3f45a2e06b379994a630e8e6682
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: a490896e9c12b21ca3464aeb2e838e31
# [+] Determined key-size: 9
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 66581e208c405557f9fb2ddcf3f262ca
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 705d453727d639ee6445f122cafe9393
# [+] Determined key-size: 5
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 854d7a01d3eacce03bcbd4187dbb177d
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 44c31220ee7ec98ee96f5f76ab0870c3
# [+] Determined key-size: 7
