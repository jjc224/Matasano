# Challenge 12: byte-at-a-time AES-128-ECB decryption (simple)

require 'base64'
require_relative 'matasano_lib/aes_128_ecb'

$ORACLE_KEY = MatasanoLib::AES_128_ECB.random_key

# AES-128-ECB(your-string || unknown-string, random-key)
def encryption_oracle(plaintext)
	unknown_str  = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG'
	unknown_str += 'Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll'
	unknown_str += 'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ'
	unknown_str += 'pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

	plaintext += Base64.decode64(unknown_str)
	MatasanoLib::AES_128_ECB.encrypt(plaintext, $ORACLE_KEY)
end

# 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
def determine_blocksize(char = 'A')
	input     = char
	curr_size = encryption_oracle(input).length
	
	loop do
		input << char
		break if encryption_oracle(input).length > curr_size
	end
	
	encryption_oracle(input).length - curr_size 
end

# 2. Detect that the function is using ECB. You already know, but do this step anyways.
blocksize   = determine_blocksize
input       = 'A' * blocksize * 4
cipher_mode = MatasanoLib::AES_128_ECB.detect_mode(input)

# 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
# 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
# 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
# 6. Repeat for the next byte.
decrypted  = ''
secret_len = encryption_oracle('').length    # If we don't put anything in the oracle, then that must be how much we roughly need to decrypt.
input      = 'A' * (secret_len - 1)
num_blocks = secret_len / blocksize

puts "[+] Detected blocksize: #{blocksize}"
puts "[+] Detected cipher mode: #{cipher_mode}"
puts "[+] There appears to be up to #{num_blocks} blocks of data to decrypt (#{secret_len} bytes)."
puts "[+] Decrypting..."

# At worst case, we will have secret_len iterations (best case being secret_len - blocksize).
# This is due to the way padding is done.
0.upto(secret_len - 1) do |i|
	dictionary = {}

	# Populate the hash table (dictionary) with all 256 possible bytes.
	(0..255).each do |c|
		char = c.chr

		# A's + decrypted data thus far + next possible byte.
		# # secret_len = blocksize * num_blocks.
		block = encryption_oracle(input + decrypted + char)[0...secret_len]

		# Key = ciphertext, value = next possible byte of secret.
		# Possible to experience collisions (i.e. not 1-1 mapping), but fairly unlikely. Let's hope not.
		dictionary[block] = char
	end
					
	block = encryption_oracle(input)[0...secret_len]
	
	# If nothing was found, we're most likely done (or something unexpected occurred).
	if dictionary[block].nil?
		puts "[+] Done.", "\n"
		break
	end

	input.slice!(0)                   # Reduce the A's by one, shifting left.
	decrypted << dictionary[block]    # Append decrypted data for next iteration (and, ideally, output).
end

puts decrypted

# Output
# ~/C/M/Ruby> time ruby 12.rb
# ----------------------------------------------------------------------
# [+] Detected blocksize: 16
# [+] Detected cipher mode: ECB
# [+] There appears to be up to 9 blocks of data to decrypt (144 bytes).
# [+] Decrypting...
# [+] Done.
# 
# Rollin' in my 5.0
# With my rag-top down so my hair can blow
# The girlies on standby waving just to say hi
# Did you stop? No, I just drove by
#
#         0.60 real         0.55 user         0.02 sys
