require_relative 'monkey_patch'
require_relative 'aes_128_common'
require_relative 'aes_128_ecb'
require_relative 'xor'
require_relative 'pkcs7'

module MatasanoLib
	module AES_128_CBC
		class << self
			include AES_128_COMMON

			@@blocksize = 16

			def encrypt(plaintext, key, opts = {})
				opts         = {iv: "\0" * @@blocksize} if opts.empty?
				plaintext    = PKCS7.pad(plaintext)
				plain_blocks = plaintext.chunk(@@blocksize)
				xor_plain    = XOR.crypt(plain_blocks[0], opts[:iv]).unhex
				prev_block   = AES_128.encrypt(xor_plain, key, :ECB, padded: false)
				ciphertext   = prev_block

				# Neglect the first block and iterate through the rest.
				plain_blocks.shift
				plain_blocks.each do |curr_block|
					xor_plain  = XOR.crypt(curr_block, prev_block).unhex
					prev_block = AES_128_ECB.encrypt(xor_plain, key)

					ciphertext << prev_block
				end

				ciphertext
			end

			def decrypt(enc, key, opts = {})
				opts       = {iv: "\0" * @@blocksize} if opts.empty?
				enc_blocks = enc.chunk(@@blocksize)
				dec_block  = AES_128.decrypt(enc_blocks[0], key, :ECB, padded: false)
				plaintext  = XOR.crypt(dec_block, opts[:iv]).unhex
				prev_block = enc_blocks[0]

				# Neglect the first block and iterate through the rest.
				enc_blocks.shift
				enc_blocks.each do |curr_block|
					dec_block = AES_128.decrypt(curr_block, key, :ECB)
					plaintext << XOR.crypt(dec_block, prev_block).unhex

					prev_block = curr_block
				end

				#PKCS7.strip(plaintext)
				plaintext
			end
		end
	end
end