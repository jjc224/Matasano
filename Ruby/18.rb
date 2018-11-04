# Challenge 18: implement AES-128-CTR, the stream cipher mode.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/aes_128_common'
require_relative 'matasano_lib/xor'

# NOTE: nonce and IV are synonymous apparently in this context.
def aes_128_ctr(input, key, nonce = 0, format = 'QQ<')    # Default format: 64-bit unsigned little-endian [nonce, block counter].
	blocks      = input.chunk(MatasanoLib::AES_128::BLOCKSIZE)
	ciphertext  = ''
	cipher_opts = {mode: :ECB, padded: false}

    (0...blocks.size).each do |i|
		keystream     = [nonce, i].pack(format)
		enc_keystream = MatasanoLib::AES_128.encrypt(keystream, key, cipher_opts)

		ciphertext << MatasanoLib::XOR.crypt(blocks[i], enc_keystream).unhex
	end

	ciphertext
end

enc = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode64
key = 'YELLOW SUBMARINE'

puts aes_128_ctr(enc, key)

# Output
# ----------------------------------------------------
# jjc224@jizzo ~/C/M/Ruby> ruby 18.rb
# Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby
