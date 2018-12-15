# Challenge 11: implement an AES-128-ECB/CBC detection oracle.

require          'securerandom'
require_relative 'matasano_lib/aes_128_ecb'
require_relative 'matasano_lib/aes_128_cbc'

# Generates a random 128-bit AES key.
def random_aes_key
    SecureRandom.random_bytes
end

def aes_rand_encrypt(plaintext)
    rand_str  = ->(n) { SecureRandom.random_bytes(rand(n)) }
    plaintext = rand_str.call(5..10) << plaintext << rand_str.call(5..10)
    ecb_mode  = rand(2).odd?  # Sure is odd to use ECB mode. ;o

    if ecb_mode
        puts "[+] Encrypting under ECB.\n\n"
        MatasanoLib::AES_128.encrypt(plaintext, random_aes_key, :mode => :ECB)
    else
        puts "[+] Encrypting under CBC.\n\n"
        MatasanoLib::AES_128.encrypt(plaintext, random_aes_key, :mode => :CBC, :iv => random_aes_key)  # "use random IVs each time for CBC"
    end
end

def detect_aes_mode(ciphertext)               # Expecting hex formatted ciphertext.
    blocks      = ciphertext.scan(/.{1,32}/)  # Split into 16-byte blocks; working with hex, so 32 characters.
    blocks_dups = {}

    # Iterate through the unique elements.
    # Store the count of each duplicate element in a hash for output.
    blocks.uniq.select do |block|
        count = blocks.count(block)
        blocks_dups[block] = count if count > 1
    end

    blocks_dups.empty? ? 'CBC' : 'ECB'
end

input = "I need the same 16-byte blocks. I need the same 16-byte blocks. I need the same 16-byte blocks."
enc   = aes_rand_encrypt(input).unpack('H*').to_s
mode  = detect_aes_mode(enc)

puts "Ciphertext: #{enc}\n\nDetected mode: #{mode}"

# Output:
# ------------------------------------------------------------------------------------------------------
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under CBC.
# 
# 	Ciphertext: ["6f947cbfafbc7d3bafc2bbbbb0bd2e72437b36876230cd2c4f9bf37507089004a87a717a57a9bd3960118e47c28d49ea437b36876230cd2c4f9bf375070890044e00c084e8420c0ae84590d33757f724437b36876230cd2c4f9bf37507089004743e23c7c9fcca85f8e65058c627deb1437b36876230cd2c4f9bf375070890045b7551d9d60867dc4607e2df45f44cac437b36876230cd2c4f9bf37507089004eb440eab75dbeb1b381ac49f5f7b4d32437b36876230cd2c4f9bf37507089004f17b087c1fe5fa2c0f3bd202c4b60945437b36876230cd2c4f9bf37507089004"]
# 
# Detected mode: CBC
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under ECB.
# 
# 	Ciphertext: ["0947c1a86c6b92d8d37bf3682ebc69755237c06690ee9122ae506bfc660f76385c83e34b33c2f9f8238816853018f8375237c06690ee9122ae506bfc660f76385c83e34b33c2f9f8238816853018f8375237c06690ee9122ae506bfc660f7638e5d9efdfe0a610a26551b57094906fb6"]
# 
# Detected mode: ECB
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under ECB.
# 
# 	Ciphertext: ["9fdea53f9c0dc61460cf35cec39b6f4073f5617f12baa96a8c08eaeee5c279d994b7df67b1eb571e6d5b355f7209323a73f5617f12baa96a8c08eaeee5c279d994b7df67b1eb571e6d5b355f7209323a73f5617f12baa96a8c08eaeee5c279d9fa0d5e6542d97d2956220376cf2a00986a24549c6b985feb49fcc4a36010d8b5"]
# 
# Detected mode: ECB
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under CBC.
# 
# 	Ciphertext: ["4a8714250b2deecc4abcb7e5d82f63b00790faf0295c6096b7b3a0f3b60ebb80848a5993c720a0e0f1d0900ca3113f4d0790faf0295c6096b7b3a0f3b60ebb80a361e7d2f8f3064cbbe5da615d2ffe8a0790faf0295c6096b7b3a0f3b60ebb800bd0380c17b5587311a8e99ac813b0300790faf0295c6096b7b3a0f3b60ebb80a53708238effa5e44caa5af3e3fd04be0790faf0295c6096b7b3a0f3b60ebb801438fd6537647b7b7359e786fc1762b90790faf0295c6096b7b3a0f3b60ebb800deecdfbfb6087e43e11eb92f093a4260790faf0295c6096b7b3a0f3b60ebb80"]
# 
# Detected mode: CBC
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under CBC.
# 
# 	Ciphertext: ["96d798551628947d1e6aa689b350e16338faa185d8957a0fec44c396c42a25ba6fff88dc37a9637071e13c3a6e8ae56038faa185d8957a0fec44c396c42a25ba4b04a7d6fa7aaef24da2efa1d7e21c5738faa185d8957a0fec44c396c42a25bab4c3f5ed760bcbfb8a2afc92778263a638faa185d8957a0fec44c396c42a25ba7a15bf5f460c288d73218df29034bdf438faa185d8957a0fec44c396c42a25ba07595bde235e4126705687dc9786921e38faa185d8957a0fec44c396c42a25ba3073824349a9a63dd83139dbd77b4d6f38faa185d8957a0fec44c396c42a25ba"]
# 
# Detected mode: CBC
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under CBC.
# 
# 	Ciphertext: ["00cc2a742c96ec9c3d820f088b961517d2eb0df4ec2b47e7ce15ddcf78032eeea0a6d7b8601388c275b637d41c4b9aa7d2eb0df4ec2b47e7ce15ddcf78032eeea4aad01026ffcc4a4651389600f45b62d2eb0df4ec2b47e7ce15ddcf78032eee0cfd481c0e1dfd9c8d40c9a8dfbf9cb6d2eb0df4ec2b47e7ce15ddcf78032eeed986b7406b849939cffffb7fe6d264c0d2eb0df4ec2b47e7ce15ddcf78032eeec414fad8b720301667aa610c5f0458c8d2eb0df4ec2b47e7ce15ddcf78032eeecff927c9d7cc12620ae45c66f16a27c4d2eb0df4ec2b47e7ce15ddcf78032eee"]
# 
# Detected mode: CBC
#
# ~/C/M/Ruby> ruby 11.rb 
# [+] Encrypting under ECB.
# 
# 	Ciphertext: ["02920e0667e298fabb7eb030b06e98529c97217c10e06badbceffbdecc686224f1b02ff69498c3d37fcad374f91b33569c97217c10e06badbceffbdecc686224f1b02ff69498c3d37fcad374f91b33569c97217c10e06badbceffbdecc686224ec187a97484a3f751de2e5e8efa154ff631a5a5d424fafe2eccddbc781f7d1e4"]
# 
# Detected mode: ECB
