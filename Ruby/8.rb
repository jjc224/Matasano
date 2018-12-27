# Challenge 8: detect AES in ECB mode given a set of hex-encoded ciphertexts.
require_relative 'matasano_lib/url'

MatasanoLib::URL.read_each_line('http://cryptopals.com/static/challenge-data/8.txt') do |line|
  blocks      = line.scan(/.{1,32}/)  # Split into 16-byte blocks; working with hex, so 32 characters.
  blocks_dups = Hash.new

  # Iterate through the unique elements.
  # Store the count of each duplicate element in a hash for output.
  blocks.uniq.select do |block|
    count = blocks.count(block)
    blocks_dups[block] = count if count > 1
  end

  unless blocks_dups.empty?
    puts "[ Determined AES-128-ECB ciphertext ]"
    puts "#{line}\n\n"

    puts "[ Common 16-byte blocks ]"
    blocks_dups.each_with_index { |(k, v), i| puts "\t#{i.next}. \"#{k}\" occurs #{v} times."}
  end
end

# Output:
# ------------------------------------------------------------------------------
# [ Determined AES-128-ECB ciphertext ]
# 19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
#
# [ Common 16-byte blocks ]
# 	1. "08649af70dc06f4fd5d2d69c744cd283" occurs 4 times.
