# Challenge 17: CBC padding oracle attack.

# Solved via dynamic programming: "simplifying a complicated problem by breaking it down into simpler sub-problems in a recursive manner."
# Bottom-up.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/aes_128_common'
require_relative 'matasano_lib/pkcs7'

$AES_KEY   = '0f40cc1380ee2f11467db661d7cc4748'.unhex
$BLOCKSIZE = 16

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
	enc = MatasanoLib::AES_128.encrypt(str, $AES_KEY, :CBC, iv: iv)

	#p ['str = ', str]

	# Provide the caller the ciphertext and IV.
	[enc, iv]
end

def all_ciphertext
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

	arr = []

	rand_strings.each do |str|
		str = str.decode64
		iv  = 'YELLOW SUBMARINE'
		enc = MatasanoLib::AES_128.encrypt(str, $AES_KEY, :CBC, iv: iv)

		arr.push([enc, iv])
	end

	arr
end

def padding_oracle(ciphertext, iv)
	plaintext = MatasanoLib::AES_128.decrypt(ciphertext, $AES_KEY, :CBC, iv: iv)
	MatasanoLib::PKCS7.valid(plaintext)
end

# P'2 = D(C2) ^ C'
# C2  = E(P2 ^ C1)
# P'2 = D(E(P2 ^ C1)) ^ C'
# P'2 = P2 ^ C1 ^ C'  (as D(E(x)) = x)
# P2  = P'2 ^ C1 ^ C' (as per commutativity)
# C'  = P'2 ^ P2 ^ C1 (as per commutativity)
def get_previous_byte(enc, iv, dec)
	blocks = enc.chunk($BLOCKSIZE)
	pos    = dec.size + 1    # Position of next byte that will be flipped by x for all x in [0, 255]) to a padding byte.

	flip = ''

	if dec.size > 0
		c1 = blocks[-2][-dec.size..-1]

		flip = dec.bytes.zip(c1.bytes)
		          .map { |p2, c1| [pos, p2, c1].inject(&:^) }    # C' = P'2 ^ P2 ^ C1 (as per commutativity)
		          .pack('C*')
	end

	prefix = "\0" * ($BLOCKSIZE - pos)

	0.upto(255) do |i|
		evil = prefix + i.chr + flip    # C' (payload).

		ciphertext    = evil + blocks[-1]    # C' || C2: payload prepended before the final block to flip the bytes upon CBC decryption.
		valid_padding = padding_oracle(ciphertext, iv)

		if valid_padding
			# The pos'th last bytes of the second-last ciphertext block and payload ciphertext (C1 and C').
			# NOTE: We take C1 because C2 is padding.
			ciphertext = blocks[-2][-pos].ord
			evil       = evil[-pos].ord

			# The pos'th last byte of the current plaintext block (P2).
			plaintext = pos ^ ciphertext ^ evil    # P2 = P'2 ^ C1 ^ C' (as per commutativity)

			# Return P2.
			return plaintext.chr + dec
		end
	end
end

def get_last_block(enc, iv)    # TODO: fix.
	dec = ''

	$BLOCKSIZE.times { |i| dec = get_previous_byte(enc, iv, dec) }

	dec
end

#def decipher(enc, iv)    # TODO: fix.
#	enc, iv = random_ciphertext
#
#	knownP = ''
#
#	enc = iv + enc    # TODO
#
#	(enc.size / $BLOCKSIZE - 1).times do |i|    # TODO
#		st = (i == 0) ? enc : enc[0...-i * $BLOCKSIZE]
#		p ['block # = ', i]
#		knownP = get_last_block(enc, iv) + knownP
#	end
#
#	MatasanoLib::PKCS7.strip(knownP)
#end

def decipher(enc, iv)
	arr = all_ciphertext

	arr.each_with_index do |(enc, iv), i|
		enc = iv + enc
		dec = ''

		((enc.size / $BLOCKSIZE) - 1).times do |i|
			block = (i == 0) ? enc : enc[0...-i * $BLOCKSIZE]    # Next $BLOCKSIZE bytes to decipher (starting from the end).
			dec   = get_last_block(block, iv) + dec
		end

		puts MatasanoLib::PKCS7.strip(dec) if dec
	end

	#MatasanoLib::PKCS7.strip(knownP)
end


decipher(*random_ciphertext)    # TODO: fix.
