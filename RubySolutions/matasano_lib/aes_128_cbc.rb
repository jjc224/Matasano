require_relative 'aes_128_common'
require_relative 'aes_128_ecb'
require_relative 'xor'
require_relative 'pkcs7'

module MatasanoLib
	module AES_128_CBC
		class << self
			include AES_128_COMMON

			@@blocksize = 16

			def encrypt(plaintext, key, iv = "\0" * @@blocksize)
					plaintext = PKCS7.pad(plaintext)

					plain_blocks = plaintext.scan(/.{1,#{@@blocksize}}/m)
					xor_plain    = [XOR.crypt(plain_blocks[0], iv)].pack('H*')
					prev_block   = AES_128_ECB.encrypt(xor_plain, key)
					ciphertext   = prev_block

					# Neglect the first block and iterate through the rest.
					plain_blocks.shift
					plain_blocks.each do |curr_block|
						xor_plain  = [XOR.crypt(curr_block, prev_block)].pack('H*')
						prev_block = AES_128_ECB.encrypt(xor_plain, key)

						ciphertext << prev_block
					end

					ciphertext
			end

			def decrypt(enc, key, iv = "\0" * @@blocksize)
					enc_blocks = enc.scan(/.{1,#{@@blocksize}}/m)
					dec_block  = AES_128_ECB.decrypt(enc_blocks[0], key)
					plaintext  = [XOR.crypt(dec_block, iv)].pack('H*')
					prev_block = enc_blocks[0]

					# Neglect the first block and iterate through the rest.
					enc_blocks.shift
					enc_blocks.each do |curr_block|
						dec_block = AES_128_ECB.decrypt(curr_block, key)
						plaintext << [XOR.crypt(dec_block, prev_block)].pack('H*')

						prev_block = curr_block
					end

					PKCS7.strip(plaintext)
			end
		end
	end
end
