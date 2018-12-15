# Challenge 1: convert hex to base64.
require 'base64'

def hex_to_base64(hex)
	Base64.strict_encode64([hex].pack('H*'))    # Decode hex; base64 encode raw bytes.
end

puts hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')

# Output: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
