require 'openssl'
require_relative 'aes_128_common'
require_relative 'pkcs7'

module MatasanoLib
	module AES_128_ECB
		class << self
			def encrypt(plaintext, key = random_key, opts = {})
                opts[:padded] = true if opts[:padded].nil?
				cipher = OpenSSL::Cipher.new('AES-128-ECB')

				cipher.encrypt
				cipher.key = key
				cipher.padding = 0

				# Nasty hack: to change.
				using_cbc = caller[0].include?('aes_128_cbc')
				return cipher.update(plaintext) if using_cbc

				plaintext = PKCS7.pad(plaintext) if opts[:padded]
				cipher.update(plaintext) + cipher.final
			end

			def decrypt(enc, key, opts = {})
                opts[:padded] = true if opts[:padded].nil?
				cipher = OpenSSL::Cipher.new('AES-128-ECB')

				cipher.decrypt
				cipher.key = key
				cipher.padding = 0

				# Nasty hack: to change.
				using_cbc = caller[0].include?('aes_128_cbc')
				return cipher.update(enc) if using_cbc

				plaintext = cipher.update(enc) + cipher.final
				opts[:padded] ? PKCS7.strip(plaintext) : plaintext
			end
		end
	end
end
