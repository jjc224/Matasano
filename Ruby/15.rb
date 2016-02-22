# Challenge 15: PKCS#7 padding validation
require_relative 'matasano_lib/pkcs7'

# Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
# If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.
def pkcs7_validate_and_strip(str)
	raise 'Bad padding.' unless MatasanoLib::PKCS7.valid(str)
	MatasanoLib::PKCS7.strip(str)
end

msg   = 'jaz0r'
input = MatasanoLib::PKCS7.pad(msg)

# p pkcs7_validate_and_strip(input)           # "jaz0r"
# p pkcs7_validate_and_strip(input[0..-1])    # Bad padding. (RuntimeError)

# input[-1] = input[-1].next
# p pkcs7_validate_and_strip(input)           # Bad padding. (RuntimeError)
