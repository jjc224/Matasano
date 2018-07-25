module MatasanoLib
	module AES_128_COMMON

        BLOCKSIZE = 16

		class << self
            # Expects a hex-encoded ciphertext.
			def detect_mode(ciphertext)
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

			def determine_blocksize(char = 'A')
				input     = char
				curr_size = yield(input).length

				loop do
					input << char
					break if yield(input).length > curr_size
				end

				yield(input).length - curr_size
			end
		end

	end
end
