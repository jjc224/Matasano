module MatasanoLib
	module PKCS7
		class << self
			@@blocksize = 16

			def pad(str, blocksize = @@blocksize)
				padding = blocksize - (str.length % blocksize)
				str << padding.chr * padding
			end

			def valid(str)
				padding   = str[-1]
				pad_start = str.length - padding.ord

				return str[pad_start..-1] == padding * padding.ord
			end

			def strip(str, blocksize = @@blocksize)
				padding   = str[-1]
				pad_start = str.length - padding.ord

				# My bad, man, didn't mean to fuck with your string. Here you go. Sorry for any inconvenience.
				return str unless valid(str)
				str[0..pad_start - 1]
			end
		end
	end
end
