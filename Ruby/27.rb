# Challenge 27: recover the key from CBC with IV = key.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/pkcs7'
require_relative 'matasano_lib/xor'

include MatasanoLib
include MatasanoLib::AES_128

AES_KEY = 'd41d19c407130e53228994fa192dcaf7'.unhex

# Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.
# Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.
# Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

# The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values).
# Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).
AsciiComplianceError = Class.new(StandardError)

def is_ascii_compliant?(input)
  input.bytes.all? { |x| x <= 127 }  # Extended ASCII codes ([128, 255]) are the "high-ASCII values" which should raise an exception.
end

def encrypt_request(input)
  input = "comment1=cooking%20MCs;userdata=" << input.gsub(/([;=])/, '\'\1\'') << ";comment2=%20like%20a%20pound%20of%20bacon"
  input = PKCS7.pad(input)

  AES_128.encrypt(input, AES_KEY, :mode => :CBC, :iv => AES_KEY)
end

def is_admin?(input)
  plaintext = AES_128.decrypt(input, AES_KEY, :mode => :CBC, :iv => AES_KEY)

  raise(AsciiComplianceError, plaintext) unless is_ascii_compliant?(plaintext)

  # This will never be executed due to the exception above (with a solution to the challenge given).
  # This code, from challenge #16, will remain here to add to the entire meaning of the simulated application.
  # As without it, this would be a completely simulated exploit (i.e., there is no application).
  data_pair = Hash[plaintext.split(';').map { |x| x.split('=') }]
  data_pair['admin']
end

# Use your code to encrypt a message that is at least 3 blocks long:
# AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
ciphertext = encrypt_request('<user data>')

# Modify the message (you are now the attacker):
# C_1, C_2, C_3 -> C_1, 0, C_1
evil = ciphertext[0, BLOCKSIZE] + "\0" * BLOCKSIZE + ciphertext[0, BLOCKSIZE]

# Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.
# As the attacker, recovering the plaintext from the error, extract the key: P'_1 XOR P'_3.
begin
  is_admin?(evil)
rescue AsciiComplianceError => e
  # Decryption will occur like so:
  #   1. P3 = D(C1) ^ 0
  #   2. P2 = D(0)  ^ C1
  #   3. P1 = D(C1) ^ IV
  #
  # As stated, recovering the key is as simple as computing P1 XOR P3.
  # Let's delve into the mathematics of this to see why.
  #
  # P1 ^ P3 = (D(C1) ^ IV) ^ (D(C1) ^ 0)
  #         = (D(C1) ^ D(C1)) ^ (IV ^ 0)  <-- Associativity, commutativity.
  #         = 0 ^ (IV ^ 0)                <-- Cancellation law.
  #         = (0 ^ 0) ^ IV                <-- Cancellation law.
  #         = 0 ^ IV                      <-- Identity law.
  #         = IV
  #
  # As key = IV, we can hence recover the key by recovering the IV.
  puts "Key: #{XOR.crypt(e.message[0, BLOCKSIZE], e.message[BLOCKSIZE * 2, BLOCKSIZE])}"
end

# Output:
# ----------------------------------------------------------
# [josh@jizzo:~/Projects/Matasano/Ruby on master] ruby 27.rb
# Key: d41d19c407130e53228994fa192dcaf7
