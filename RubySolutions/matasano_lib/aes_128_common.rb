require 'securerandom'

module MatasanoLib
	module AES_128_COMMON
		def random_key
			SecureRandom.random_bytes
		end
	end
end
