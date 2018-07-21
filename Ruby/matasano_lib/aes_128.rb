require_relative 'aes_128_ecb'
require_relative 'aes_128_cbc'
require_relative 'aes_128_crt'

module MatasanoLib
	module AES_128
		class << self
			include AES_128_COMMON

			def encrypt(plaintext, key, mode, opts = {})
				ciphertext = case mode
					         when :ECB then AES_128_ECB.encrypt(plaintext, key, opts)
					         when :CBC then AES_128_CBC.encrypt(plaintext, key, opts)
					         when :CRT then AES_128_CRT.crypt(plaintext, key, opts)
					     end

				ciphertext
			end

			def decrypt(ciphertext, key, mode, opts = {})
				plaintext = case mode
					        when :ECB then AES_128_ECB.decrypt(ciphertext, key, opts)
					        when :CBC then AES_128_CBC.decrypt(ciphertext, key, opts)
					        when :CRT then AES_128_CRT.crypt(ciphertext, key, opts)
					    end

				plaintext
			end
		end
	end
end
