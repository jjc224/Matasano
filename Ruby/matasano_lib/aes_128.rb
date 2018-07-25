require          'securerandom'
require_relative 'aes_128_ecb'
require_relative 'aes_128_cbc'
require_relative 'aes_128_ctr'
require_relative 'aes_128_common'

module MatasanoLib
	module AES_128

        include AES_128_COMMON

        class << self
            extend MatasanoLib::AES_128_COMMON

			def encrypt(plaintext, key, opts = {})
                raise "No block cipher mode specified." unless opts[:mode]

				ciphertext = case opts[:mode]
					         when :ECB then AES_128_ECB.encrypt(plaintext, key, opts)
					         when :CBC then AES_128_CBC.encrypt(plaintext, key, opts)
					         when :CRT then AES_128_CRT.crypt(plaintext, key, opts)
					         end

				ciphertext
			end

			def decrypt(ciphertext, key, opts = {})
                raise "No block cipher mode specified." unless opts[:mode]

				plaintext = case opts[:mode]
					        when :ECB then AES_128_ECB.decrypt(ciphertext, key, opts)
					        when :CBC then AES_128_CBC.decrypt(ciphertext, key, opts)
					        when :CRT then AES_128_CRT.crypt(ciphertext, key, opts)
					        end

				plaintext
			end

			def random_key
				SecureRandom.random_bytes
			end
		end

	end
end
