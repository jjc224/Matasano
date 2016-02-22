# Challenge 17: CBC padding oracle attack.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128_cbc'
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
	enc = MatasanoLib::AES_128_CBC.encrypt(str, $AES_KEY, iv)

	# Provide the caller the ciphertext and IV.
	[enc, iv]
end

def padding_oracle(ciphertext, iv)
	plaintext = MatasanoLib::AES_128_CBC.decrypt(ciphertext, $AES_KEY, iv)
	p plaintext.chunk(16)
	MatasanoLib::PKCS7.valid(plaintext)
end

blocksize = 16
enc, iv   = random_ciphertext


0.upto(255) do |i|
	ciphertext = "\0" * (blocksize - 1) << i.chr
	ciphertext << enc

	result = padding_oracle(ciphertext, iv)

	puts "#{i}: #{result.to_s}"
end
