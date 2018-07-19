# Challenge 17: CBC padding oracle attack.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/pkcs7'

$AES_KEY = '0f40cc1380ee2f11467db661d7cc4748'.unhex

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

	# Provide the caller the ciphertext and IV.
	[enc, iv]
end

def padding_oracle(ciphertext, iv)
	plaintext = MatasanoLib::AES_128.decrypt(ciphertext, $AES_KEY, :CBC, iv: iv)
	MatasanoLib::PKCS7.valid(plaintext)
end

def get_previous_byte(iv, enc)
	blocksize  = 16
	enc, iv    = random_ciphertext

	blocks = enc.chunk(16)
	dec    = ''
	pos    = dec.size + 1
	prefix = "\0" * (16 - pos)

	while i <= 0xff
		evil = "\0" * (blocksize - dec.size - 1) << i.chr << "\0" * dec.size

		if dec.size == 1
			evil[-1] = (pos ^ byte ^ blocks[-2][-1].ord).chr
		end

		ciphertext    = evil + enc[-blocksize..-1]    # 'evil' a block before the final block, to tamper with the padding.
		valid_padding = padding_oracle(ciphertext, iv)

		# P'2 = D(C2) ^ C'
		# C2  = E(P2 ^ C1)
		# P'2 = D(E(P2 ^ C1)) ^ C'
		# P'2 = P2 ^ C1 ^ C' (as D(E(x)) = x)
		# P2  = P'2 ^ C1 ^ C' (as per commutativity)
		# C'  = P'2 ^ P2 ^ C1 (as per commutativity)
		if valid_padding
			byte = pos ^ blocks[-2][-pos].ord ^ evil[-pos].ord

			dec.prepend(byte.chr)    # TODO: slow.
			p dec.bytes

			i = 1
			exit if dec.size == 2
		end

		i += 1
	end
end


