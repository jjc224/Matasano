# Challenge 13: ECB cut-and-paste.
require_relative 'matasano_lib/aes_128_ecb'
require_relative 'matasano_lib/monkey_patch'

# Key/value parser of form: foo=bar&baz=qux&zap=zazzle
def kv_parser(data)
	parsed    = "{\n"
	format_kv = ->(kv) { kv.gsub(/(.*)=(.*)/, '\1: \'\2\'') }
	kv_pairs  = data.split('&')

	kv_pairs.map.with_index do |kv, i|
		parsed << "\t"
		parsed << format_kv.call(kv)
		parsed << ',' if i.next < kv_pairs.size
		parsed << "\n"
	end

	parsed << '}'
end

def profile_for(email)
	'email=' << email.tr('&=', '') << '&uid=10&role=user'
end

def encrypt_profile(email, key)
	MatasanoLib::AES_128_ECB.encrypt(profile_for(email), key)
end

def decrypt_profile(enc_profile, key)
	MatasanoLib::AES_128_ECB.decrypt(enc_profile, key)
end

# It takes 9 bytes to produce 3 blocks, with no input resulting in 2 blocks.
# This means that there are 32 - 9 = 23 bytes mixed in with the input.
# The format is easily deduced by the characters disallowed for email and the output of the parser.
# We need blocks structured as: email=AAA... | admin | ...role= | user.
# We need to then swap/cut-and-paste block two ('admin') with the last block ('user').
# To get 'admin' in its own block, all we need to do is pad 0x0b.
# After that, craft our naughty ciphertext and decrypt it!

# irb(main):004:0> ('email=AAAAAAAAAAadmin' + "\x0b" * 11 + 'AAA&uid=10&role=user').scan(/.{1,16}/)
# => ["email=AAAAAAAAAA", "admin\v\v\v\v\v\v\v\v\v\v\v", "AAA&uid=10&role=", "user"]
# Ciphertext: ["ce05355f1f7d71a4266fe8277f77f73f", "30e3074d6e2e7f5b0fc4c78fe03be512", "c3d06713dce2fb5b31d3f425a770e1d5", "877fdb4ffe25eba02313e2e311b9c7e6"]

# Harcoded test:
# attack = [
#              'ce05355f1f7d71a4266fe8277f77f73f', '30e3074d6e2e7f5b0fc4c78fe03be512',
#              'c3d06713dce2fb5b31d3f425a770e1d5', '30e3074d6e2e7f5b0fc4c78fe03be512'    # This final block is the 'admin' block, replacing 'user'.
#          ]

key         = 'ee78012a6846ef0470fb6e87f9d5fd7b'.unhex
admin_block = '30e3074d6e2e7f5b0fc4c78fe03be512'.unhex
email       = 'soz@jaz0r.com'     # Previously: 'AAAAAAAAAA' << 'admin' << "\x0b" * 11 + 'AAA'
enc_email   = encrypt_profile(email, key)

blocksize  = MatasanoLib::AES_128_COMMON.determine_blocksize { |input| encrypt_profile(input, key) }
attack     = enc_email[0...-blocksize] << admin_block
ciphertext = attack.chunk(blocksize).to_hex
dec_email  = decrypt_profile(attack, key)

puts "Ciphertext: #{ciphertext}", "\n"
puts 'Parsed profile:', kv_parser(dec_email)

# Output:
# ------------------------------------------------------------------------------------------------------------------------
# ~/C/M/Ruby> ruby 13.rb
# Ciphertext: ["34dbb50a5b4236edd6f7bfec694ddad8", "4e185db1466566ea36b990845254fb97", "30e3074d6e2e7f5b0fc4c78fe03be512"]
#
# Parsed profile:
# {
#	email: 'soz@jaz0r.com',
#	uid: '10',
#	role: 'admin'
# }
