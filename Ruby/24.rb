# Challenge 24: Create the MT19937 stream cipher and break it.

require          'securerandom'
require_relative 'matasano_lib/mt19937'
require_relative 'matasano_lib/monkey_patch'

ORACLE_INPUT = 'A' * 14
USERNAME     = 'SomeSillyName'

# You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream.
# XOR each byte of plaintext with each successive byte of keystream.

# Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.
def crypt(input, key)
  mt         = MatasanoLib::MT19937.new(key)  # key and seed are synonymous in this context.
  keystream  = []
  ciphertext = ''

  (0...input.size).each do |i|
    keystream  << (mt.extract_number & 0xff)
    ciphertext << (input[i].ord ^ keystream[i])
  end

  ciphertext
end

# Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.
def encryption_oracle(input = ORACLE_INPUT)
  key    = SecureRandom.random_number(0xffff + 1)  # The interval is [0, 0xffff + 1) = [0, 0xffff], which is a number up to 16 bits.
  prefix = SecureRandom.random_bytes(rand(0..64))

  crypt(prefix + input, key)
end

# From the ciphertext, recover the "key" (the 16 bit seed).
#
# Brute-force the 16-bit seed.
# Decrypt the ciphertext and compare it with the partial known plaintext.
def brute_mt19937_u16(ciphertext, known_plaintext = ORACLE_INPUT)
  (0..0xffff).each { |key| return key if crypt(ciphertext, key)[-known_plaintext.size..-1] == known_plaintext }
  raise 'brute_mt19937_u16(): unable to recover key.'
end

# Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.
def password_token(user = USERNAME)
  key       = Time.now.to_i
  prefix    = SecureRandom.random_bytes(rand(0..32))
  plaintext = "#{prefix};#{user};#{user}@site.com"

  crypt(plaintext, key)
end

# Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
def crack_password_token(token, user = USERNAME, time_window = 500)  # time_window is in seconds (epoch).
  current_time = Time.now.to_i
  (current_time - time_window..current_time).each { |key| return key if crypt(token, key).include?(user) }
  raise 'crack_password_token(): unable to recover token.'
end

ciphertext = encryption_oracle
token      = password_token

puts "[-] Ciphertext: #{ciphertext.to_hex}"
puts '[-] Attempting to recover key (16-bit MT19937 seed).'
puts "[+] Recovered key: #{brute_mt19937_u16(ciphertext)}"
puts
puts "[-] Attempting to crack password_token('#{USERNAME}') = '#{token.to_hex}'"
puts "[+] Recovered key from #{USERNAME}'s password token: #{crack_password_token(token)}"

# Output
# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys002] [master ⚡] [~/Projects/Matasano/Ruby]> ruby 24.rb
# [-] Ciphertext: c2bc46707d6c02c3a3c2aac386c38ac38326c39a6ec282c2b30d6ac2aec284c38ec29a681c367fc3b35e33c287420fc29476c2aa67c386c3a91a12c2b03802c3912e25c393096d2a
# [-] Attempting to recover key (16-bit MT19937 seed).
# [+] Recovered key: 24436
# 
# [-] Attempting to crack password_token('SomeSillyName') = '20c38bc288c282c2a7c2a8c29977c399c288c3b72603c3815cc29ac2a6c38ac295c3b64d70c293c3ae2f79c296c38a5fc3952111c3a3333e3258173ac29742'
# [+] Recovered key from SomeSillyName's password token: 1545739461
