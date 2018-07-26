# Challenge 26: CTR bit-flipping.

# Since this is really just identical to CBC bit-flipping, aside that the mathematics for crypting in CTR mode differ and thus I need to exemplify this previous attack on a CTR-encrypted cookie.
#
# I first made sure to realize that while CTR is a stream cipher mode, it does so by using block cipher mode with a keystream to neglect the need for padding.
# This allowed me to conjure up the same sort of method of breaking this:
#   1. Break into 128-bit blocks.
#   2. Flip the bytes in the right blocks (and block boundary)
#
#   The mathematics are all defined in the block cipher mode.
#   It's all a matter of understanding how XOR operations in CTR take place for encryption/decryption and using it to your advantage.

# TODO: if I have the time, write the solution more nicely (and touch up MT1993 stuff).

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/pkcs7'

BLOCKSIZE = MatasanoLib::AES_128::BLOCKSIZE    # 16 bytes.
$AES_KEY  = 'd41d19c407130e53228994fa192dcaf7'.unhex

def encrypt_request(input)
	input = "comment1=cooking%20MCs;userdata=" << input.gsub(/([;=])/, '\'\1\'') << ";comment2=%20like%20a%20pound%20of%20bacon"
	MatasanoLib::AES_128.encrypt(input, $AES_KEY, :mode => :CTR)
end

def is_admin?(input)
	plaintext = MatasanoLib::AES_128.decrypt(input, $AES_KEY, :mode => :CTR)
	data_pair = Hash[plaintext.split(';').map { |x| x.split('=') }]

    p data_pair
	data_pair['admin']
end

# 1. Flip the byte on the same C/K/P blocks. Don't XOR the block before like in CBC.
#
# You need to take the known evil plain and evil bytes C' and P' (which you do know; you facilitated in their creation).
# You can calculate the key-stream byte K = P' ^ C'. Then you know C = P ^ K (e.g. ';' ^ K in first instance).
#
# C = P ^ K
#   = P ^ (P' ^ C')
#   = P ^ P' ^ C' (as per associativity)
to_flip = '~admin|true'    # We want to flip this into ';admin=true'.
evil    = 'A' * (BLOCKSIZE + 5) << to_flip
enc     = encrypt_request(evil)
cp_idx  = 32 + BLOCKSIZE + 5    # 32 bytes to ignore the first key-value, the next an offset to '~admin|true'. These values work on a block boundary, XOR'd against C and/or K.

def flip_bytes(enc, p, pp, cp_idx)
    c = p.ord ^ pp.ord ^ enc[cp_idx].ord    # c = p ^ pp ^ cp
end

enc[cp_idx]     = flip_bytes(enc, ';', '~', cp_idx).chr
enc[cp_idx + 6] = flip_bytes(enc, '=', '|', cp_idx + 6).chr

enc[cp_idx]     = flip_bytes(enc, ';', '~', cp_idx).chr
enc[cp_idx + 6] = flip_bytes(enc, '=', '|', cp_idx + 6).chr

puts is_admin?(enc) ? '[+] Welcome, admin!' : "[-] User just ain't good enough."

