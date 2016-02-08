require 'openssl'
require_relative 'pkcs7'
require_relative 'aes_128_common'

module MatasanoLib
	module AES_128_ECB
		class << self
			include AES_128_COMMON

			def encrypt(plaintext, key = random_key)
				cipher = OpenSSL::Cipher.new('AES-128-ECB')
					    
				cipher.encrypt
				cipher.key = key 
				cipher.padding = 0

				plaintext = PKCS7.pad(plaintext)
				cipher.update(plaintext) + cipher.final
			end

			def decrypt(enc, key)
				cipher = OpenSSL::Cipher.new('AES-128-ECB')
					    
				cipher.decrypt
				cipher.key = key 
				cipher.padding = 0
							    
				PKCS7.strip(cipher.update(enc) + cipher.final)
			end
		end
	end
end
