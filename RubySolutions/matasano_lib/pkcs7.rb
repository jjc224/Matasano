module MatasanoLib
	module PKCS7
		class << self
			@@blocksize = 16

			def pad(str, blocksize = @@blocksize)
				padding = blocksize - (str.length % blocksize)
				str << padding.chr * padding
			end

			def strip(str, blocksize = @@blocksize)
				padding   = str[-1]
				pad_start = str.length - padding.ord

				# Return the string if it does not end with a padding character.
				# return str unless padding.between?(0.chr, @@blocksize.chr)

				# Raise an exception if the anticipated padding does not conform to PKCS#7.
				# raise 'Bad padding.' + " #{str[pad_start..-1].unpack('H*')}" if str[pad_start..-1] != padding * padding.ord

				# My bad, man, didn't mean to fuck with your string. Here you go. Sorry for any inconvenience.
				return str if str[pad_start..-1] != padding * padding.ord
				str[0..pad_start - 1]
			end
		end
	end
end
