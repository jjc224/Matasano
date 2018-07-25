# Challenge 16: CBC bit-flipping.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128_cbc'
require_relative 'matasano_lib/pkcs7'

$AES_KEY = 'd41d19c407130e53228994fa192dcaf7'.unhex

def encrypt_request(input)
	input = "comment1=cooking%20MCs;userdata=" << input.gsub(/([;=])/, '\'\1\'') << ";comment2=%20like%20a%20pound%20of%20bacon"
	input = MatasanoLib::PKCS7.pad(input)

	MatasanoLib::AES_128_CBC.encrypt(input, $AES_KEY)
end

def is_admin?(input)
	plaintext = MatasanoLib::AES_128_CBC.decrypt(input, $AES_KEY)
	data_pair = Hash[plaintext.split(';').map { |x| x.split('=') }]

	data_pair['admin']
end

# If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for.
# We'll have to break the crypto to do that.
#
# Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.
#
# You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:
#	1. Completely scrambles the block the error occurs in.
#	2. produces the identical 1-bit error(/edit) in the next ciphertext block.

blocksize = MatasanoLib::AES_128_COMMON.determine_blocksize { |input| encrypt_request(input) }

evil = 'A' * (blocksize + 5) << '~admin|true'
enc = encrypt_request(evil)

# p enc.chunk(blocksize).to_hex
# [
#  "d43127c243b7e37095907e2e7e24a5f3",
#  "27e47ee74491bb26d7f7b37b306c38b1",
#  "707972b94b8bb4562e52a6672050a9ad",    # Block to tamper (16 A's).
#  "28bf63d04c448e9b5197b76466a40e59",    # Block containing 'AAAAA~admin|true'. We want to flip the bytes to get 'AAAAA;admin=true'
#  "3b61e66d838859cb842cd20e7ebfec4e",
#  "1c09dd450bd4089756e215354966c32a",
#  "e9c38d12211febaa371db9cedb3d4314",
#  "7a1a3bba5b9ac185aa43cd5079dc35e3"
# ]

# C = Ciphertext byte to tamper.
# P = Plaintext of byte adjacent to C on a block boundary.
# A = Unknown byte.
#
# We know that P = C ^ A, which means A = C ^ P.
# Let A' = (A ^ C ^ P) = (A ^ A) = 0, then we can set A' = (A' ^ X) = X for any desired X.
flipper = ->(c, p, a) { (c.bytes[0] ^ p.ord ^ a.ord).chr }

enc[32 + 5]  = flipper.call(enc[32 + 5],  '~', ';')
enc[32 + 11] = flipper.call(enc[32 + 11], '|', '=')

puts is_admin?(enc) ? '[+] Welcome, admin!' : "[-] User just ain't good enough."

# Output:
# ~/C/M/Ruby> ruby 16.rb
# ----------------------
# [+] Welcome, admin!

# Additionally, not that I (or you) are allowed to know, the paired data becomes, in this case:
# {"comment1"=>"cooking%20MCs", "userdata"=>"\xE4j\x03\xE9\xE4i\x8BN\x8Eu\xDD\xF3\xBEj\xF1/AAAAA", "admin"=>"true", "comment2"=>"%20like%20a%20pound%20of%20bacon"}
