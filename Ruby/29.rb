# Challenge 29: break a SHA-1 keyed MAC using length-extension.

# Secret-prefix SHA-1 MACs are trivially breakable.
#
# The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".
# Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.
#
# To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding.
# We call this "glue padding". The final message you actually forge will be:
#
# SHA-1(key || original-message || glue-padding || new-message)
#
# (where the final padding on the whole constructed message is implied)
#
# Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.
# This sounds more complicated than it is in practice.

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

# SHA-1 keyed MAC (susceptible to length-extension attacks).
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

  # Returns a new SHA-1 MAC digest with a random key.
  def generate_digest(message)
    SHA1_MAC::digest(@key, message)
  end

  # Performs MAC verification given a message and its digest under a secret key only known by the oracle.
  def verify(message, digest)
    SHA1_MAC::verify(@key, message, digest)
  end
end

# To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using.
# This should take you 5-10 minutes.
#   -> (More like 10 seconds rofl.)
def pad(message)
  ml = message.size * 8

  message += 0x80.chr
  message += "\0" * (56 - (message.size & 63) & 63)  # 56 = 448 / 8, and 63 = 512 / 8 - 1. (Readable equivalent for the latter would be '% 64'.)
  message += [ml].pack('Q>')
end

# Now, take the SHA-1 secret-prefix MAC of the message you want to forge -- this is just a SHA-1 hash -- and break it into 32 bit SHA-1 registers (SHA-1 calls them 'a', 'b', 'c', etc.).
def extract_final_state(digest)
  # Check if a hex digest is passed instead and decode it (i.e., SHA1_MAC.hex_digest -> SHA1_MAC.digest).
  digest = digest.unhex if digest.is_a?(String) && digest.size == 40

  # Reverse the final step in SHA-1 to retrieve the internal state for cloning state, ultimately allowing us to suffix a payload.
  # I.e., recover the five 32-bit SHA-1 registers.
  digest.unpack('N5')  # => [h0, h1, h2, h3, h4]
end

# Mount length-extension attack on an oracle (class Oracle).
def length_extension_attack(mac, message, payload, oracle)
  # We will assume up to a 256-bit key (for no real reason other than demonstration).
  (0..32).each do |key_size|
    # The forged message is constructed as SHA1(key || original-message || glue-padding || new-message).
    # The key need not be the true key, as we only care about the key-size, as per the way Merkle-Damgard constructed digests are padded.
    # Hence, we can use any key for the glue-padding, so long as the guessed key-size is correct.
    forged_message = pad('A' * key_size + message)[key_size..-1] + payload

    # With the registers 'fixated', hash the additional data you want to forge.
    registers  = extract_final_state(mac)
    sha1_mac   = SHA1_MAC.new('', payload, (key_size + forged_message.size) * 8, *registers)
    forged_mac = sha1_mac.digest

    if oracle.verify(forged_message, forged_mac)
      return [forged_message, forged_mac, key_size]
    end
  end

  raise 'SHA-1 length-extension attack failed.'
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
# -----------------------------------------------------------------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys002] [master ⚡] [~/Projects/Matasano/Ruby]> for i in {1..8}; do ruby 29.rb && echo "\n<---------->\n"; done
#
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: b4f3578abd2e4ba0457584ab9000fe22b9a77949
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: e56eecfc1f00c209c522d19278d62229e6d36614
# [+] Determined key-size: 9
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 8f2040da510c967e9a3ef850d8b7f3504c366579
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 47a94ed6475ca7d30a21099035cd6b3478a23ef1
# [+] Determined key-size: 8
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: cd534a2b0b45ea9d5c82d89bc5cb3e0d83813c50
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: fafc8de18ba09dcbb8275f7d6077b3d7066da2bc
# [+] Determined key-size: 6
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: fdbf9700da27883d3244b17ea8a2b9e1861f6292
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: f82f93b3170b82f43f638abaec275ba6b258a095
# [+] Determined key-size: 5
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 2568cb57f24600aa0e30eb8c2788165af08d30f4
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 8c97f02f14aef10e64af4d3a2826bb22eadb876f
# [+] Determined key-size: 8
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: 460876aac3f84351e61ca51c0379eb25533299a0
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 47defdba7c8c4b1def131e8d02fa16b49157318d
# [+] Determined key-size: 6
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: b4b9585306863895367cf86b975cae3842bf0094
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: 226bf902e3c192221d616be2317e1c2cb2dd1469
# [+] Determined key-size: 13
# 
# <---------->
# 
# [+] Original message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon
# [+] Original MAC: ad2f7564ce78f5ffc49779d29d4f0df948f8afe6
# 
# [+] Forged message: comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true
# [+] Forged MAC: e2046fae5b7afd8d46234958d2360b2401a81fbf
# [+] Determined key-size: 7
