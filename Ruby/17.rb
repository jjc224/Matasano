# Challenge 17: CBC padding oracle attack.

# Solution broken down via bottom-up, dynamic programming: "simplifying a complicated problem by breaking it down into simpler sub-problems in a recursive manner."
# Explanation below.

# IV  = Initialization vector.
# P   = Plaintext.
# C   = Ciphertext.
# C'  = Payload ciphertext.
# P'  = Garbage plaintext resulted by padding_oracle(C', IV).
# Pn  = The n'th block of plaintext.
# Cn  = The n'th block of ciphertext.
# P'n = The n'th block of ciphertext.
# E   = Encryption function: AES-128-CBC in this case.
# D   = Decryption function: AES-128-CBC in this case.

# Note that C0 = IV.

# These equations are under the assumption that encryption/decryption is under CBC mode.
# --------------------------------------------------------------------------------------
# P'2 = D(C2) ^ C'
# C2  = E(P2 ^ C1)
# P'2 = D(E(P2 ^ C1)) ^ C'
# P'2 = P2 ^ C1 ^ C'  (as D(E(x)) = x)
# P2  = P'2 ^ C1 ^ C' (as per commutativity)
# C'  = P'2 ^ P2 ^ C1 (as per commutativity)
# --------------------------------------------------------------------------------------

# Given the ciphertext C and the corresponding IV encrypted with 128-bit AES under CBC mode, find the plaintext block P.

# Let us assume we have only two sets of plaintext/ciphertext blocks: {C1, C2}.
# We want to the find the last byte of P2.
# Note that some of P2 will contain some amount of padding. This is important, as we can determine with high probability what that byte is.
#
# We know that P'2 = D(C2) ^ C' and C2 = E(P2 ^ C1), as per how CBC mode encrypts on blocks.
# Substituting C2 into P'2 = D(C2) ^ C we get: P'2 = D(E(P2 ^ C1)) ^ C'.
# Hence, P'2 = P2 ^ C1 ^ C', as D(E(x)) = x for any x (E and D are inverse functions of one another).
# So, we can find P2 by substituting for P'2 for P2: P2 = P'2 ^ C1 ^ C'.
#
# Now that we know how to mathematically derive the blocks, we can begin targetting particular bytes.
# Firstly, we want to flip the last byte in C' such that C'[-1] = P'2[-1] (0x01 in PKCS#7).
# This will give us the values necessary to determine P2 = P'2 ^ C1 ^ C'.
# Once we know the next bytes in P2 and C'.
#
# Breaking this is just a matter of running this recursively by taking a bottom-up dynamic programming approach to:
#     1. Take the next last byte in the given block (C2).
#     2. Manufacture a payload ciphertext C' such that it will use x for all x in [0, 255] on a block boundary position n.
#     3. The payload becomes C' || C2 so that the last byte in C2 is flipped by C' to assume the value of P'2[i] from C'[i]: P'2[i] = D(C2[i]) ^ C'[i].
#     4. Hence, we can assume that P'2[n] is the desired padding byte with high probability.
#     5. Therefore, we have enough information now to solve for the last byte in the given plaintext block P2: P2[i] = P'2[i] ^ C1[i] ^ C'[i].
#
#     Now that we have a function to decrypt the last byte.
#     All that needs to be done is implement a function which mounts this byte-decrypting function such that it decrypts a whole block.
#     Finally, we mount another function such that it will decrypt all blocks in C.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/aes_128_common'
require_relative 'matasano_lib/pkcs7'

AES_KEY   = '0f40cc1380ee2f11467db661d7cc4748'.unhex
BLOCKSIZE = MatasanoLib::AES_128_COMMON.blocksize    # 16 bytes (128-bit keys).

# The first function should select at random one of the following 10 strings.
# Then, generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.
def random_ciphertext
	rand_strings = [
		'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
		'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
		'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
		'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
		'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
		'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
		'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
		'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
		'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
		'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
	]

	str = rand_strings.sample.decode64
	iv  = 'YELLOW SUBMARINE'
	enc = MatasanoLib::AES_128.encrypt(str, AES_KEY, :CBC, iv: iv)

	# Provide the caller the ciphertext and IV.
	[enc, iv]
end

# The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
def padding_oracle(ciphertext, iv)
	plaintext = MatasanoLib::AES_128.decrypt(ciphertext, AES_KEY, :CBC, iv: iv)
	MatasanoLib::PKCS7.valid(plaintext)
end


# The following routines are each designed to solve a sub-problem bottom-up.

# Return the last byte of last block of plaintext (P2) and the last byte of the first block of ciphertext (C1).
# Prepends the decrypted P2 and C1 bytes into 'known_p2' and 'known_evil_c1', respectively.
def decrypt_last_byte(enc, iv, known_p2, known_evil_c1)
	# Padding table. This seems like a more generic choice. Regardless of the values, we can index the correct pad byte using 'pos'.
	# Since this is PKCS#7 padding, we would simply do 'pads = *(0x01..0x10)'. However this recursive solution allows for any padding scheme.
	# Moreover, we really could make just use 'pos' for most calculations. Howver, there are benefits to this generalization.
	pads = [
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10
	]

	bytes_found = known_p2.size             # The amount of bytes discovered are the amount of bytes in the solution (P2) thus far (|P2| = |C'|).
	pos         = known_evil_c1.size + 1    # Position of next bytes of C1 and C' blocks.

	blocks = enc.chunk(BLOCKSIZE)
	c1     = blocks[-2].bytes

	pad_byte = pads[pos - 1]    # The padding byte we want happens at position pos on a block boundary.

	known_evil_p2 = [pad_byte] * bytes_found      # An array of the known bytes in P'2 (an array of the known padding bytes in P2).
	known_c1      = c1[-bytes_found..-1]          # An array of the known bytes in P1.

	prefix        = [0] * (BLOCKSIZE - pos)
	known_evil_c1 = known_evil_p2.zip(known_p2, known_c1).map { |pp2, p2, c1| pp2 ^ p2 ^ c1 }    # C' = P'2 ^ P2 ^ C1

	0.upto(255) do |i|
		evil_c1 = prefix + [i] + known_evil_c1    # C' (payload)

		payload = evil_c1.pack('C*') + blocks[-1]    # C' || C2: payload prepended before the final block to flip the bytes upon CBC decryption.
		valid_padding = padding_oracle(payload, iv)

		# If we have valid padding, then we can assume P'2 with high probability and then determine P2.
		if valid_padding
			# The pos'th last byte of C1 and C' (the pad byte P'2 was decided earlier).
			c1_byte      = c1[-pos]
			evil_c1_byte = evil_c1[-pos]

			p2 = pad_byte ^ c1_byte ^ evil_c1_byte    # P2 = P'2 ^ C1 ^ C'

			# Return the last byte of the known_p2 block (P2) and payload ciphertext block (C').
			# Prepended in reverse due to bottom-up, recursive nature of this algorithm.
			return [p2] + known_p2, [evil_c1_byte] + known_evil_c1
		end
	end
end

# Return the last decrypted block (P2).
# Prepends the discovered P2 and C' bytes into the byte arrays 'known_p2' and 'known_evil_c1', respectively.
def decrypt_last_block(enc, iv)
	known_p2      = [] * BLOCKSIZE
	known_evil_c1 = [] * BLOCKSIZE

	BLOCKSIZE.times { |i| known_p2, known_evil_c1 = decrypt_last_byte(enc, iv, known_p2, known_evil_c1) }

	known_p2
end

# Returns a given ciphertext vulnerable to the CBC padding oracle attack.
# Note that this utilizes various subroutines due to the bottom-up, dynamic programming approach taken to solve this problem.
def padding_oracle_attack(enc, iv)
	enc = iv + enc    # The ciphertext C. C0 = IV by definition. CBC mode decryption operates such that P[i] = D(C[i]) ^ C[i-1], so the last operation will be P1 = D(C1) ^ IV (hence 'enc = iv + enc').
	dec = []          # The plaintext P, the decrypted C via a CBC padding oracle attack.

	((enc.size / BLOCKSIZE) - 1).times do |i|
		block = (i == 0) ? enc : enc[0...-i * BLOCKSIZE]    # Essentially will slice off the next ciphertext block after decryption.
		dec   = decrypt_last_block(block, iv) + dec
	end

	puts MatasanoLib::PKCS7.strip(dec.pack('C*')) if dec
end

# Execute padding_oracle_attack(C, IV) such that the ciphertext C is an (AES-128-CBC) encrypted random string S with PKCS#7 padding (this can be trivially changed).
padding_oracle_attack(*random_ciphertext)

# [phizo@jizzo:~/Projects/Matasano/Ruby on master] time (for i in {1..10}; do ruby 17.rb; done)
# -------------------------------------------------------
# 000008ollin' in my five point oh
# 000006And a high hat with a souped up tempo
# 000007I'm on a roll, it's time to go solo
# 000005I go crazy when I hear a cymbal
# 000008ollin' in my five point oh
# 000009ith my rag-top down so my hair can blow
# 000001With the bass kicked in and the Vega's are pumpin'
# 000006And a high hat with a souped up tempo
# 000009ith my rag-top down so my hair can blow
# 000004Burning 'em, if you ain't quick and nimble
# ( for i in {1..10}; do; ruby 17.rb; done; )  5.23s user 0.05s system 99% cpu 5.289 total
