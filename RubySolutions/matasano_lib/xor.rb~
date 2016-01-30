module MatasanoLib
	module XOR
		class << self
			# 
			def hex(a, b)
				raise "Unequal buffers passed." if a.length != b.length
				(a.hex ^ b.hex).to_s(16)
			end

			# Can be used for either encryption or decryption (as per the way XOR operates).
			def crypt(plaintext, key)
				ciphertext = String.new

				plaintext.chars.each_with_index do |c, i|
					ciphertext << "%02x" % (c.bytes[0] ^ key[i % key.length].bytes[0])
				end 

				ciphertext
			end

			# Brute forces enc against charset: a 'scoring' function.
			# Returns a hash with the highest score.
			def brute(enc, charset)
				solution_data = {'score' => 0}
				
				# Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
				# 'ABC' => /A|B|C/i
				regexpr = Regexp.union(charset.chars)
				regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)
				
				(1..255).each do |c|
					attempt_key = c.chr
					xor_key     = (attempt_key * (enc.length / 2)).unpack('H*')[0]     # Repeat single-key to match size of ciphertext for XOR'ing.
					ret_hex     = MatasanoLib::XOR.hex(enc, xor_key)
					plaintext   = [ret_hex].pack('H*')
					score       = plaintext.scan(regexpr).size    # Scans through the plaintext applying the regex; returns the number of matches.
				
					# Update solution data to match more promising solution (higher score).
					if score > solution_data['score']
						solution_data['score']      = score
						solution_data['key']        = attempt_key
						solution_data['ciphertext'] = ret_hex
						solution_data['plaintext']  = plaintext
					end
				end

				return nil if solution_data['score'] == 0
				solution_data
			end
		end
	end
end