# Challenge 2: write a function that takes two equal-length buffers and produces their XOR combination.
def xor_hex(a, b)
	return if a.length != b.length
	(a.hex ^ b.hex).to_s(16)
end

puts xor_hex('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')
# Output: 746865206b696420646f6e277420706c6179
