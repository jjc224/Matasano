# Challenge 14: byte-at-a-time AES-128-ECB decryption (harder)

require          'base64'
require          'securerandom'
require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'

$ORACLE_PREFIX = SecureRandom.random_bytes(rand(0..64))
$ORACLE_KEY    = MatasanoLib::AES_128.random_key

# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
def encryption_oracle(plaintext)
	unknown_str  = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIG'
	unknown_str += 'Rvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll'
	unknown_str += 'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQ'
	unknown_str += 'pEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

	plaintext = $ORACLE_PREFIX + plaintext + Base64.decode64(unknown_str)
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

def determine_prefix_length
	blocksize  = determine_blocksize
	input      = 'A' * blocksize * 3  # 48 A's.
	ciphertext = encryption_oracle(input)
	blocks     = ciphertext.chunk(blocksize).to_hex
	index      = 0

	# Obtain the index of the first duplicate block.
	# This is used to help us determine the amount of blocks roughly (due to input -- *offset*) our input begins.
	blocks.each_with_index do |block, i|
		left  = blocks[i - 1] unless i == 0
		right = blocks[i]     unless i == blocks.size

		if left == right
			index = i  # We want the right hand.
			break
		end
	end

	# We now need to reduce the A's until the block is no longer a duplicate.
	# This will then be used as an offset (see loop above), which give us the length of the prefix.
	loop do
		ciphertext = encryption_oracle(input)
		blocks     = ciphertext.chunk(blocksize).to_hex
		dup_count  = blocks.size - blocks.uniq.size
		duplicates = dup_count > 0

		break if !duplicates || input.empty?
		input.slice!(0)
	end

	# p [index, blocks[0..index]]
	# Example of input reduction
	# [4, ["1896aa3475f4aa7bbe70045e62bde564", "870a7dafa56c199f3bb73cb320cc658b", "29281d041f6e4b3392a82ccf630eb6be", "9d29753f9995838ae0a3cbd8349582bf", "9d29753f9995838ae0a3cbd8349582bf"]]
	# [4, ["1896aa3475f4aa7bbe70045e62bde564", "870a7dafa56c199f3bb73cb320cc658b", "29281d041f6e4b3392a82ccf630eb6be", "9d29753f9995838ae0a3cbd8349582bf", "53fd8002ac13393dfc4b286c3c641088"]]

	# -1 amount of A's due to it finally looking structurally like: XXXAAA...|AAAA...|AAAA...Y
	# Where Y represents the first byte of the target-bytes.
	(index + 1) * blocksize - input.length - 1
end

# 2. Detect that the function is using ECB. You already know, but do this step anyways.
blocksize   = determine_blocksize
input       = 'A' * blocksize * 4
cipher_mode = MatasanoLib::AES_128_COMMON.detect_mode(input)

# 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
# 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
# 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
# 6. Repeat for the next byte.
decrypted = ''

prefix_len     = determine_prefix_length
prefix_pad_len = (blocksize - (prefix_len % blocksize))  # The random prefix needs to be aligned on a block boundary, so pad it if needed.
prefix_len    += prefix_pad_len

secret_len = encryption_oracle('').length  # If we don't put anything in the oracle, then that must be how much we roughly need to decrypt.
input      = 'A' * (secret_len + prefix_pad_len - 1)
num_blocks = secret_len / blocksize

puts "[+] Detected blocksize: #{blocksize}"
puts "[+] Detected cipher mode: #{cipher_mode}"
puts "[+] Detected prefix length: #{prefix_len}"
puts "[+] There appears to be up to #{num_blocks} blocks of data to decrypt (#{secret_len} bytes)."
puts "[+] Decrypting..."

# At worst case, we will have secret_len iterations (best case being secret_len - blocksize).
# This is due to the way padding is done.
0.upto(secret_len - 1) do |i|
	dictionary = {}

	# Populate the hash table (dictionary) with all 256 possible ciphertexts => bytes.
	(0..255).each do |c|
		char = c.chr

		# A's + decrypted data thus far + next possible byte.
		# secret_len = blocksize * num_blocks.
		# Now reads starting at the end of the random prefix up to secret_len inclusively.
		block = encryption_oracle(input + decrypted + char)[prefix_len, secret_len]

		# Key = ciphertext, value = next possible byte of secret.
		# Possible to experience collisions (i.e. not 1-1 mapping), but fairly unlikely. Let's hope not.
		dictionary[block] = char
	end

	block = encryption_oracle(input)[prefix_len, secret_len]

	# If nothing was found, we're most likely done (or something unexpected occurred).
	break if dictionary[block].nil?

	input.slice!(0)                 # Reduce the A's by one, shifting left.
	decrypted << dictionary[block]  # Append decrypted data for next iteration (and, ideally, output).

	break if decrypted.length == secret_len
end

puts '[+] Done.', "\n"
puts decrypted

# Output
# -----------------------------------------------------------------------
# ~/C/M/Ruby> time ruby 14.rb
# [+] Detected blocksize: 16
# [+] Detected cipher mode: ECB
# [+] Detected prefix length: 16
# [+] There appears to be up to 10 blocks of data to decrypt (160 bytes).
# [+] Decrypting...
# [+] Done.
#
# Rollin' in my 5.0
# With my rag-top down so my hair can blow
# The girlies on standby waving just to say hi
# Did you stop? No, I just drove by
