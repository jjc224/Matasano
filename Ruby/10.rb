# Challenge 10: implement CBC mode (AES-128).

require_relative 'matasano_lib/url'
require_relative 'matasano_lib/xor'
require_relative 'matasano_lib/aes_128_ecb'

def pkcs7_strip(str)
  padding   = str[-1]
  pad_start = str.length - padding.ord

  return str if str[pad_start..-1] != padding * padding.ord
  str[0..pad_start - 1]
end

def aes_cbc_decrypt(enc, key, iv = "\0" * 16)  # 16 byte blocks (128-bit cipher).
  enc_blocks = enc.scan(/.{1,16}/m)
  dec_block  = MatasanoLib::AES_128_ECB.decrypt(enc_blocks[0], key)
  plaintext  = [MatasanoLib::XOR.crypt(dec_block, iv)].pack('H*')
  prev_block = enc_blocks[0]

  # Neglect the first block and iterate through the rest.
  enc_blocks.shift
  enc_blocks.each do |curr_block|
    dec_block = MatasanoLib::AES_128_ECB.decrypt(curr_block, key)
    plaintext << [MatasanoLib::XOR.crypt(dec_block, prev_block)].pack('H*')

    prev_block = curr_block
  end

  pkcs7_strip(plaintext)
end

enc = MatasanoLib::URL.decode64('http://cryptopals.com/static/challenge-data/10.txt')
key = 'YELLOW SUBMARINE'

puts aes_cbc_decrypt(enc, key)

# Output:
# ----------------------------------------------
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
