# Challenge 3: break single-byte XOR cipher by devising a method of 'scoring' a piece of English plaintext (character frequency as a metric).
# Highest score is the most promising solution.

def xor_hex(a, b)
	raise "Unequal buffers passed." if a.length != b.length
	(a.hex ^ b.hex).to_s(16)
end

def xor_brute(enc, charset)
	frequencies = {
		            ' ' => 0.13,
		            'E' => 0.1202, 'T' => 0.0910, 'A' => 0.0812, 'O' => 0.0768, 'I' => 0.0731,
		            'N' => 0.0695, 'S' => 0.0628, 'R' => 0.0602, 'H' => 0.0592, 'D' => 0.0432,
		            'L' => 0.0398, 'U' => 0.0288, 'C' => 0.0271, 'M' => 0.0261, 'F' => 0.0230,
		            'Y' => 0.0211, 'W' => 0.0209, 'G' => 0.0203, 'P' => 0.0182, 'B' => 0.0149,
		            'V' => 0.0111, 'K' => 0.0069, 'X' => 0.0017, 'Q' => 0.0011, 'J' => 0.0010,
		            'Z' => 0.0007
	              }

	solution_data = {'score' => 0}

	(1..255).each do |c|
		attempt_key = c.chr
		xor_key     = (attempt_key * (enc.length / 2)).unpack('H*')[0]     # Repeat single-key to match size of ciphertext for XOR'ing.
		ret_hex     = xor_hex(enc, xor_key)
		plaintext   = [ret_hex].pack('H*')
		score       = 0

		plaintext.split('').map do |c|
			c.capitalize!
			score += frequencies[c] unless frequencies[c].nil?
		end

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

def output_solution(solution = {}, opts = {})
	puts "Key: #{solution['key']}"
	puts "Ciphertext: #{solution['ciphertext']}"
	puts "Plaintext: #{solution['plaintext']}"

	puts "Score: #{solution['score']}" if opts[:with_score]
end

enc           = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
charset       = 'ETAOIN SHRDLU'    # Frequency analysis: 12 most common characters in the English language.
solution_data = xor_brute(enc, charset)

output_solution(solution_data) unless solution_data.nil?

# Output:
# --------------------------------------------------------------------------------
# Key: X
# Ciphertext: 436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e
# Plaintext: Cooking MC's like a pound of bacon
# --------------------------------------------------------------------------------
