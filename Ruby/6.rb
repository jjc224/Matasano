# Challenge 6: break/decrypt repeating-key XOR cipher.

#	1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
#	2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits.
#	3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
#
#	4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values.
#	   Or take 4 KEYSIZE blocks instead of 2 and average the distances.
#
#	5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
#	6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
#	7. Solve each block as if it was single-character XOR. You already have code to do this.
#	8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

require_relative 'matasano_lib/url'
require_relative 'matasano_lib/xor'
require_relative 'matasano_lib/monkey_patch'

def hamming_distance(a, b)
	raise "Unequal buffers passed." if a.length != b.length
	ret = String.new

	a.bytes.each_with_index do |a_byte, i|
		ret << (a_byte ^ b.bytes[i]).to_s(2)
	end

	ret.count('1')    # Return the number of set bits (the number of differing bits, as per XOR).
end

enc      = Base64.decode64(open('http://cryptopals.com/static/challenge-data/6.txt') { |f| f.read }.strip!)
hamdists = Hash.new

# Step 3 and 4.
(2..40).each do |keysize|
	distance  = hamming_distance(enc[0..keysize], enc[keysize..keysize * 2])
	distance += hamming_distance(enc[keysize..keysize * 2], enc[keysize * 2..keysize * 3])
	distance += hamming_distance(enc[keysize..keysize * 3], enc[keysize * 2..keysize * 4])
	distance /= 3

	hamdists[keysize] = (distance.to_f / keysize)
end

keysize           = hamdists.sort_by { |keysize, dist| dist }.first[0]
enc_blocks        = enc.chunk(keysize)    # Raw chunks each of size 'keysize' (step 5).
transposed_blocks = [''] * keysize

# Transpose blocks (step 6).
for i in (0...keysize) do
	enc_blocks.each do |block|
		unless block[i].nil?
			transposed_blocks[i] += block[i]
		end
	end
end

key = String.new

# Step 7 and 8.
transposed_blocks.each_with_index do |block, i|
	key << MatasanoLib::XOR.brute(block, 'ETAOIN SHRDLU')[:key]
end

puts "Key: '" << key << "'\n\n"

# Decrypt and output.
puts MatasanoLib::XOR.crypt(enc, key).unhex

# Output
# -----------------------------------------------------------------
# Key: 'Terminator X: Bring the noise'
#
# I'm back and I'm ringin' the bell
# A rockin' on the mike while the fly girls yell
# In ecstasy in the back of me
# Well that's my DJ Deshay cuttin' all them Z's
# Hittin' hard and the girlies goin' crazy
# Vanilla's on the mike, man I'm not lazy.
#
# I'm lettin' my drug kick in
# It controls my mouth and I begin
# To just let it flow, let my concepts go
# My posse's to the side yellin', Go Vanilla Go!
#
# Smooth 'cause that's the way I will be
# And if you don't give a damn, then
# Why you starin' at me
# So get off 'cause I control the stage
# There's no dissin' allowed
# I'm in my own phase
# The girlies sa y they love me and that is ok
# And I can dance better than any kid n' play
#
# Stage 2 -- Yea the one ya' wanna listen to
# It's off my head so let the beat play through
# So I can funk it up and make it sound good
# 1-2-3 Yo -- Knock on some wood
# For good luck, I like my rhymes atrocious
# Supercalafragilisticexpialidocious
# I'm an effect and that you can bet
# I can take a fly girl and make her wet.
#
# I'm like Samson -- Samson to Delilah
# There's no denyin', You can try to hang
# But you'll keep tryin' to get my style
# Over and over, practice makes perfect
# But not if you're a loafer.
#
# You'll get nowhere, no place, no time, no girls
# Soon -- Oh my God, homebody, you probably eat
# Spaghetti with a spoon! Come on and say it!
#
# VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
# Intoxicating so you stagger like a wino
# So punks stop trying and girl stop cryin'
# Vanilla Ice is sellin' and you people are buyin'
# 'Cause why the freaks are jockin' like Crazy Glue
# Movin' and groovin' trying to sing along
# All through the ghetto groovin' this here song
# Now you're amazed by the VIP posse.
#
# Steppin' so hard like a German Nazi
# Startled by the bases hittin' ground
# There's no trippin' on mine, I'm just gettin' down
# Sparkamatic, I'm hangin' tight like a fanatic
# You trapped me once and I thought that
# You might have it
# So step down and lend me your ear
# '89 in my time! You, '90 is my year.
#
# You're weakenin' fast, YO! and I can tell it
# Your body's gettin' hot, so, so I can smell it
# So don't be mad and don't be sad
# 'Cause the lyrics belong to ICE, You can call me Dad
# You're pitchin' a fit, so step back and endure
# Let the witch doctor, Ice, do the dance to cure
# So come up close and don't be square
# You wanna battle me -- Anytime, anywhere
#
# You thought that I was weak, Boy, you're dead wrong
# So come on, everybody and sing this song
#
# Say -- Play that funky music Say, go white boy, go white boy go
# play that funky music Go white boy, go white boy, go
# Lay down and boogie and play that funky music till you die.
#
# Play that funky music Come on, Come on, let me hear
# Play that funky music white boy you say it, say it
# Play that funky music A little louder now
# Play that funky music, white boy Come on, Come on, Come on
# Play that funky music
