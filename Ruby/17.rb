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

def get_previous_byte(iv, enc, dec, cpp)
#	pos    = knownI.size + 1
#	prefix = "\0" * (16 - pos)
#
#	1.upto(255) do |i|
#		c1  = enc.size > 16 ? enc[-32...-16] : iv
#		c1p = prefix + i.chr + knownI.bytes.map { |i| (i ^ pos).chr }.join
#		sp  = enc[0...-32] + c1p + enc[-16..-1]
#
#		if padding_oracle(sp, iv)
#			iPrev = i ^ pos
#			pPrev = c1[-pos].ord ^ iPrev
#
#			return iPrev.chr + knownI, pPrev.chr + knownP
#		end
#	end

	byte = 0

	# P'2 = D(C2) ^ C'
	# C2  = E(P2 ^ C1)
	# P'2 = D(E(P2 ^ C1)) ^ C'
	# P'2 = P2 ^ C1 ^ C' (as D(E(x)) = x)
	# P2  = P'2 ^ C1 ^ C' (as per commutativity)
	# C'  = P'2 ^ P2 ^ C1 (as per commutativity)
	1.upto(255) do |i|
		blocks = enc.chunk(16)
		pos    = dec.size + 1

		#evil = "\0" * (blocksize - dec.size - 1) << i.chr << "\0" * dec.size
		prefix = "\0" * (16 - pos)
		evil   = prefix + i.chr + cpp

		#evil   = prefix + i.chr + MatasanoLib::XOR.crypt(dec, pos.chr).unhex

		ciphertext    = evil + blocks[-1]    # 'evil' a block before the final block, to tamper with the padding.
		valid_padding = padding_oracle(ciphertext, iv)    #

		if valid_padding
			byte = pos ^ blocks[-2][-pos].ord ^ evil[-pos].ord    # P2 = P'2 ^ C1 ^ C' (as per commutativity)

			return byte.chr + dec, evil[-pos] + cpp
		end

		#byte = evil
	end

	#p byte
end

def get_last_block(iv, enc)
	enc, iv = random_ciphertext

	dec = ''
	cpp = ''

	2.times do |i|
		dec, cpp = get_previous_byte(iv, enc, dec, cpp)
	end

	dec
end

p get_last_block(*random_ciphertext)

#def get_last_block(iv, enc)
#	knownI = ''
#	knownP = ''
#
#	(0...16).each do
#		knownI, knownP = get_previous_byte(iv, enc, knownI, knownP)
#	end
#
#	knownP
#end
#
#def decipher(iv, enc)
#	knownP = ''
#
#	(enc.size / 16).times do |i|
#		st = (i == 0) ? enc : enc[0...-i * 16]
#		knownP = get_last_block(iv, enc) + knownP
#	end
#
#	MatasanoLib::PKCS7.strip(knownP)
#end

