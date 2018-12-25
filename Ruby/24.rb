# Challenge 24: Create the MT19937 stream cipher and break it.

require          'securerandom'
require_relative 'matasano_lib/mt19937'

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
def password_token(user)
  key       = Time.now.to_i
  prefix    = SecureRandom.random_bytes(rand(0..64))
  plaintext = "#{prefix};#{user};#{user}@cryptopals.com"

  crypt(plaintext, key)
end

# Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
def crack_password_token(token, user, time_window = 500)  # time_window is in seconds (epoch).
  current_time = Time.now.to_i
  (current_time - time_window..current_time).each { |key| return key if crypt(token, key).include?(user) }
end

puts "[+] Recovered key: #{brute_mt19937_u16(encryption_oracle)}"
puts "[+] Recovered password token of user '#{USERNAME}': #{crack_password_token(password_token(USERNAME), USERNAME)}"

# Output
# ------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys002] [master ⚡] [~/Projects/Matasano/Ruby]> ruby 24.rb
# [+] Recovered key: 63980
# [+] Recovered password token of user 'SomeSillyName': 1545725231
