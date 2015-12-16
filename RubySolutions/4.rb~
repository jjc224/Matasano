require 'open-uri'

def xor_hex(a, b)
	return if a.length != b.length
	(a.hex ^ b.hex).to_s(16)
end

def xor_brute(enc, charset)
	solution_data = {'score' => 0}
	
	(1..255).each do |c|
		attempt_key = c.chr
		xor_key     = (attempt_key * (enc.length / 2)).unpack('H*')[0]     # Repeat single-key to match size of ciphertext for XOR'ing.
		ret_hex     = xor_hex(enc, xor_key)
		plaintext   = [ret_hex].pack('H*')
		
		# Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
		# 'ABC' => /A|B|C/i
		regexpr = Regexp.union(charset.split(''))
		regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)
	
		score = plaintext.scan(regexpr).size    # Scans through the plaintext applying the regex; returns the number of matches.
	
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

charset       = 'ETAOIN SHRDLU'    # Frequency analysis: 12 most common characters in the English language.
solution_data = {'score' => 0}

open('http://cryptopals.com/static/challenge-data/4.txt') do |f|
	f.each_line do |line|
		line.strip!
		temp = xor_brute(line, charset)

		if temp['score'] > solution_data['score']
			solution_data = temp
		end
	end
end

output_solution(solution_data)
