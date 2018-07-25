require_relative 'monkey_patch'
require_relative 'aes_128_common'
require_relative 'aes_128_ecb'
require_relative 'xor'

module MatasanoLib
	module AES_128_CRT

		include AES_128_COMMON

		class << self
			def crypt(input, key, opts = {nonce: 0, format: 'QQ<'})    # Default format: 64-bit unsigned little-endian [nonce, block counter].
				blocks     = input.chunk(BLOCKSIZE)
				ciphertext = ''

				for i in 0...blocks.size
					keystream     = [opts[:nonce], i].pack(opts[:format])
					enc_keystream = AES_128.encrypt(keystream, key, :mode => :ECB, :padded => false)

					ciphertext << XOR.crypt(blocks[i], enc_keystream).unhex
				end

				ciphertext
			end
		end
	end
end
