# Challenge 5: break/decrypt repeating-key XOR cipher.
# Steps taken:
# 	1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
# 	2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits.
# 	3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
#
# 	4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values.
# 	   Or take 4 KEYSIZE blocks instead of 2 and average the distances.
#
# 	5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# 	6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
# 	7. Solve each block as if it was single-character XOR. You already have code to do this.
# 	8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

require 'open-uri'
require 'base64'

def xor_hex(a, b)
	raise "Unequal buffers passed." if a.length != b.length
	(a.hex ^ b.hex).to_s(16)
end

def hamming_distance(a, b)
	raise "Unequal buffers passed." if a.length != b.length
	ret = String.new

	a.bytes.each_with_index do |a_byte, i|
		ret << (a_byte ^ b.bytes[i]).to_s(2)
	end

	ret.count('1')    # Return the number of set bits (the number of differing bits, as per XOR).
end

def xor_brute(enc, charset)
	solution_data = Array.new
	
	# Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
	# 'ABC' => /A|B|C/i
	regexpr = Regexp.union(charset.split(''))
	regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)
	
	(1..255).each do |c|
		attempt_key = c.chr
		xor_key     = (attempt_key * (enc.length / 2)).unpack('H*')[0]     # Repeat single-key to match size of ciphertext for XOR'ing.
		ret_hex     = xor_hex(enc, xor_key)
		plaintext   = [ret_hex].pack('H*')
		score       = plaintext.scan(regexpr).size    # Scans through the plaintext applying the regex; returns the number of matches.
		
		current_data = {'score' => 0}

		# Update solution data to match more promising solution (higher score).
		#if score > current_data[c - 1]['score']
			current_data['score']      = score
			current_data['key']        = attempt_key
			current_data['ciphertext'] = ret_hex
			current_data['plaintext']  = plaintext

			solution_data << current_data
		#end
	end

	solution_data
end

def output_solution(solution = {}, opts = {})
	return print solution['key'] if opts[:key_only]

	puts "Key: #{solution['key']}"
	puts "Ciphertext: #{solution['ciphertext']}"
	puts "Plaintext: #{solution['plaintext']}"

	puts "Score: #{solution['score']}" if opts[:with_score]
end

charset       = 'ETAOIN SHRDLU'    # Frequency analysis: 12 most common characters in the English language.
# solution_data = {'score' => 0}

#enc = ['0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'].pack('H*')
enc      = Base64.decode64(open('http://cryptopals.com/static/challenge-data/6.txt') { |f| f.read }.strip!)
hamdists = Hash.new

(2..40).each do |keysize|
	# See step 3.
	distance = hamming_distance(enc[0..keysize], enc[keysize..keysize * 2])
	hamdists[keysize] = (distance.to_f / keysize).round(2)
end

keysize           = 6 #hamdists.sort_by { |keysize, dist| dist }.first[0]    # Step 4.
enc_blocks        = enc.scan(/.{1,#{keysize}}/)    # Raw chunks each of size [1, keysize] (step 5).
transposed_blocks = [''] * keysize

# Transpose blocks (step 6).
for i in (0..keysize) do
	enc_blocks.each do |block|
		unless block[i].nil? 
			transposed_blocks[i] += block[i]     # Why do I have to copy?
		end
	end
end

solution_keys = [''] * transposed_blocks.size

transposed_blocks.each_with_index do |block, i|
	solution_data = xor_brute(block.unpack('H*')[0], charset)
	solution_data = solution_data.max_by(keysize) { |h| h['score'] }

	#solution_data.map { |x| p x }
	#puts

	#for i in (0..solution_keys.size) do
		solution_data.each { |s| solution_keys[i] += s['key'] }
	#end

	#solution_data.each { |solution| output_solution(solution, :key_only => true) }
	#output_solution(xor_brute(block.unpack('H*')[0], charset))
end

p solution_keys#.permutation(3).to_a

thekey = 'SECRET'
mykey  = ''

for i in (0..enc.unpack('H*')[0].length / 2 - 1) do
	mykey.concat(thekey[i % thekey.length])
end

p xor_hex([enc].pack('H*'), [('X' * ([enc].pack('H*').length/2))].pack('H*'))

#hamdists.sort_by { |keysize, dist| dist }[0..2].each do |(keysize)|
#	p keysize
#end
#enc_blocks = enc[0..

#output_solution(solution_data)
