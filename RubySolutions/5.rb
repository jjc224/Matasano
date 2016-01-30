# Challenge 5: implement repeating-key XOR cipher.
# Encrypt it, under the key "ICE", using repeating-key XOR.
# In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

def xor_encrypt(plaintext, key)
	ciphertext = String.new

	plaintext.chars.each_with_index do |c, i|
		ciphertext << "%02x" % (c.bytes[0] ^ key[i % key.length].bytes[0])
	end

	ciphertext
end

puts xor_encrypt("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE')
# Output: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
