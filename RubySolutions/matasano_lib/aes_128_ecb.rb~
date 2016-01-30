require 'openssl'

module MatasanoLib
	module AES_128_ECB
		class << self
			def encrypt(plaintext, key)
				cipher = OpenSSL::Cipher.new('AES-128-ECB')
					    
				cipher.encrypt
				cipher.key = key 
							    
				cipher.update(plaintext) + cipher.final
			end

			def decrypt(enc, key)
				cipher = OpenSSL::Cipher.new('AES-128-ECB')
					    
				cipher.decrypt
				cipher.key = key 
				cipher.padding = 0 
							    
				cipher.update(enc) + cipher.final
			end
		end
	end
end