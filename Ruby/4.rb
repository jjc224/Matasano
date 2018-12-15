# Challenge 4: detect single-character XOR cipher amongst a file of 60 possible ciphertexts.
# Additionally, let's break it. ;)

require_relative 'matasano_lib/url'
require_relative 'matasano_lib/xor'

def output_solution(solution = {}, opts = {})
    puts "Key: #{solution[:key]}"
    puts "Ciphertext: #{solution[:ciphertext]}"
    puts "Plaintext: #{solution[:plaintext]}"

    puts "Score: #{solution[:score]}" if opts[:with_score]
end

charset       = 'ETAOIN SHRDLU'  # Frequency analysis: 12 most common characters in the English language.
solution_data = {score: 0}

MatasanoLib::URL.read_each_line('http://cryptopals.com/static/challenge-data/4.txt') do |line|
    temp = MatasanoLib::XOR.brute(line.unhex, charset)

    if temp[:score] > solution_data[:score]
        solution_data = temp
    end
end

output_solution(solution_data) unless solution_data.nil?

# Output:
# ------------------------------------------------------------------------
# Key: 5
# Ciphertext: 4e6f77207468617420746865207061727479206973206a756d70696e670a
# Plaintext: Now that the party is jumping
# ------------------------------------------------------------------------
