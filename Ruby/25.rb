# Challenge 25: break random access read/write AES-CTR.

require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/url'
require_relative 'matasano_lib/monkey_patch'

include MatasanoLib

# irb(main):003:0> MatasanoLib::AES_128::random_key
# => "/\x82\x82\xC8\"\xEE\\i_\x1F\x06\xA0\xAC;\x06)"
AES_KEY = '971fe7b9c17f4ad77fef00d8b487c413'.unhex

# Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).
def encryption_oracle
  # From an early-on AES-128-ECB exercise. 'YELLOW SUBMARINE' is the 128-bit key.
  ciphertext = URL::decode64('http://cryptopals.com/static/challenge-data/25.txt')
  plaintext  = AES_128.decrypt(ciphertext, 'YELLOW SUBMARINE', mode: :ECB)

  AES_128.encrypt(plaintext, AES_KEY, mode: :CTR)
end

ciphertext = encryption_oracle

# Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".
def edit(ciphertext, key, offset, new_text)
  plaintext = AES_128.decrypt(ciphertext, key, mode: :CTR)
  plaintext[offset % plaintext.size, new_text.size] = new_text[0..plaintext.size]  # Modulo so it wraps around to imitate a fixed-size buffer, such as a disk.

  AES_128.encrypt(plaintext, key, mode: :CTR)
end

# Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".
def write_to_disk(offset, new_text)
  edit(encryption_oracle, AES_KEY, offset, new_text)
end


# Recover the original plaintext.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Food for thought:
# A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# This is trivially broken: all I need to do is edit the "disk data" (saved ciphertext) to all zeroes and let it re-encrypt, as 0 ^ keystream[i] = keystream[i].
# Once I have the AES-encrypted keystream, all I need to do is XOR the original ciphertext with that to acquire the plaintext.
# Furthermore, since CTR mode turns a block cipher into a stream cipher, I can decrypt it all at once rather than in 128-bit chunks/blocks.

keystream = write_to_disk(0, "\0" * ciphertext.size)
plaintext = XOR.crypt(ciphertext, keystream).unhex

puts plaintext

# Output:
# ----------------------------------------------------------
# [josh@jizzo:~/Projects/Matasano/Ruby on master] ruby 25.rb
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
