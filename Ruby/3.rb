# Challenge 3: break single-byte XOR cipher by devising a method of 'scoring' a piece of English plaintext (character frequency as a metric).
# Highest score is the most promising solution.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/xor'

def xor_brute(enc, charset)
	solution_data = {score: 0}

	# Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
	# 'ABC' => /A|B|C/i
	regexpr = Regexp.union(charset.chars)
	regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)

	(1..255).each do |i|
		attempt_key = i.chr
		xor_key     = (attempt_key * (enc.length / 2)).to_hex     # Repeat single-key to match size of ciphertext for XOR'ing.
		ret_hex     = MatasanoLib::XOR.hex(enc, xor_key)
		plaintext   = ret_hex.unhex
		score       = plaintext.scan(regexpr).size / plaintext.length.to_f    # Returns the number of matches and normalises the result.

		# Update solution data to match more promising solution (higher score).
		if score > solution_data[:score]
			solution_data[:score]      = score
			solution_data[:key]        = attempt_key
			solution_data[:ciphertext] = ret_hex
			solution_data[:plaintext]  = plaintext
		end
	end

	raise 'No solution.' if solution_data[:score].zero?
	solution_data
end

def output_solution(solution = {}, opts = {})
	puts "Key: #{solution[:key]}"
	puts "Ciphertext: #{solution[:ciphertext]}"
	puts "Plaintext: #{solution[:plaintext]}"

	puts "Score: #{solution[:score]}" if opts[:with_score]
end

enc           = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
charset       = 'ETAOIN SHRDLU'    # Frequency analysis: 12 most common characters in the English language.
solution_data = xor_brute(enc, charset)

output_solution(solution_data)

# Output:
# --------------------------------------------------------------------------------
# Key: X
# Ciphertext: 436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e
# Plaintext: Cooking MC's like a pound of bacon
# --------------------------------------------------------------------------------
