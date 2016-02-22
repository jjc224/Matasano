require_relative 'monkey_patch'
require_relative 'aes_128_common'
require_relative 'aes_128_ecb'
require_relative 'xor'

module MatasanoLib
	module AES_128_CRT
		class << self
			include AES_128_COMMON

			def crypt(input, key, opts = {})    # Default format: 64-bit unsigned little-endian [nonce, block counter].
				opts        = {nonce: 0, format: 'QQ<'} if opts.empty?
				blocks      = input.chunk(@blocksize)
				ciphertext  = ''

				for i in 0...blocks.size
					keystream     = [opts[:nonce], i].pack(opts[:format])
					enc_keystream = AES_128.encrypt(keystream, key, :ECB, padded: false)

					ciphertext << XOR.crypt(blocks[i], enc_keystream).unhex
				end

				ciphertext
			end
		end
	end
end
