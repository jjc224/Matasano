require 'securerandom'

module MatasanoLib
	module AES_128_COMMON
		def random_key
			SecureRandom.random_bytes
		end

		def detect_mode(ciphertext)    # Expecting hex formatted ciphertext.
			blocks      = ciphertext.scan(/.{1,32}/)    # Split into 16-byte blocks; working with hex, so 32 characters.
			blocks_dups = {}
			
			# Iterate through the unique elements.
			# Store the count of each duplicate element in a hash for output.
			blocks.uniq.select do |block|
				count = blocks.count(block)
				blocks_dups[block] = count if count > 1
			end
			
			blocks_dups.empty? ? 'CBC' : 'ECB'
		end
	end
end
