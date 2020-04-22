# Challenge 15: PKCS#7 padding validation

require_relative 'matasano_lib/pkcs7'

# Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
# If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
def pkcs7_validate_and_strip(str)
  raise 'Bad padding.' unless MatasanoLib::PKCS7.valid(str)
  MatasanoLib::PKCS7.strip(str)
end

# For this particular instance of PKCS#7, we have a blocksize of 16 bytes under 128-bit AES.
# I see no reason to import the library for AES_128::BLOCKSIZE alone.
msg = 'A' * (16 - 1)

(1..16).each do |i|
  input    = MatasanoLib::PKCS7.pad(msg)
  padding  = input[-i..-1]
  stripped = pkcs7_validate_and_strip(input)

  # Such an error will result in the program crashing and an exit code of 1 being returned.
  raise "Invalid padding detected (%s)." % [padding.inspect] unless MatasanoLib::PKCS7.valid(msg + padding)  # pkcs7_validate_and_strip() already computes this: this is for logic's sake.
  msg = msg[0...-1]
end

# We have tested all possible padding bytes given the manipulated input string.
# A lack of an exception and an exit code of 0 shows that PKCS#7 validation/stripping is functional.
