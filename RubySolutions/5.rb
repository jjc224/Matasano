plaintext  = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
ciphertext = ''
key        = 'ICE'

plaintext.split('').each_with_index do |c, i|
	ciphertext << "%02x" % (c.bytes[0] ^ key[i % 3].bytes[0])
end

puts ciphertext
