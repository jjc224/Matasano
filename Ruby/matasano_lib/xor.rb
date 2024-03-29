require_relative 'monkey_patch'

module MatasanoLib
  module XOR
    class << self
      # Operates XOR on two hex strings, and returns the result in hex format.
      def hex(a, b)
        raise "Unequal buffers passed." if a.size != b.size
        (a.hex ^ b.hex).to_s(16)
      end

      # Return the number of set bits (the number of differing bits, as per XOR).
      def hamming_distance(a, b)
        raise "Unequal buffers passed." if a.length != b.length
        a.bytes.zip(b.bytes).map { |a, b| (a ^ b).to_s(2) }.join.count('1')
      end

      # Can be used for either encryption or decryption (as per the way XOR operates).
      def crypt(plaintext, key)
        ciphertext = String.new

        plaintext.chars.each_with_index do |c, i|
          ciphertext << "%02x" % (c.bytes[0] ^ key[i % key.length].bytes[0])
        end

        ciphertext
      end

      # Brute forces enc against charset: a 'scoring' function.
      # Returns a hash with the highest score.
      def brute(enc, charset)
        solution_data = {score: 0}

        # Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
        # 'ABC' => /A|B|C/i
        regexpr = Regexp.union(charset.chars)
        regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)

        (0..255).each do |i|
          key_char  = i.chr
          xor_key   = (key_char * enc.length).to_hex  # Repeat single-key to match size of ciphertext for XOR'ing.
          dec_hex   = hex(enc.to_hex, xor_key)
          plaintext = dec_hex.unhex
          score     = plaintext.scan(regexpr).size / plaintext.length.to_f  # Returns the number of matches and normalises the result.

          # Update solution data to match more promising solution (higher score).
          if score > solution_data[:score]
            solution_data[:score]      = score
            solution_data[:key]        = key_char
            solution_data[:ciphertext] = enc.to_hex
            solution_data[:plaintext]  = plaintext
          end
        end

        #raise 'No solution.' if solution_data[:score] == 0
        solution_data
      end
    end
  end
end
