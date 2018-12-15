# Challenge 23: clone an MT19937 RNG from its output.


# The internal state of MT19937 consists of 624 32-bit integers.
# For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is big.
# 
# Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.
# The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.
# 
# To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order.
# There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number.
# So, you'll need code to invert the "right" and the "left" operation.
# 
# Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.
# 
# The new "spliced" generator should predict the values of the original.


require_relative 'matasano_lib/mt19937'

def untemper(y)
  # The necessary coefficients of MT19937 (32-bit):
  w, n, m, r = 32, 624, 397, 31
  a = 0x9908B0DF
  u, d = 11, 0xFFFFFFFF
  s, b = 7, 0x9D2C5680
  t, c = 15, 0xEFC60000
  l = 18

  # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX = y
  # 000000000000000000XXXXXXXXXXXXXX = y >> 18
  #
  # We can observe quite easily that for y ^ (y >> n), the first n bits of y will be retained, as a right-shift of n bits causes the result to have n 0-bits prepended and x ^ 0 = x for all x.
  # Let S = 18 be the shift, then since S ≥ 32 - S (= 14), the lower 32 - S bits can all trivially be restored all at once.
  y ^= (y >> l)

  # irb(main):002:0> ('%0*b' % [32, 0xEFC60000]).scan(/.{1,15}/)
  # => ["111011111100011", "000000000000000", "00"]
  #
  # As can be observed, the mask creates the same situation as above:
  #   The lower 17 bits can all trivially be restored all at once. While the shift gives 15 zero lower bits, the mask effectively makes it 17.
  #   17 ≥ 32 - 17 = 15
  y ^= ((y << t) & c)

  # The mask, @@b = 0x9D2C5680:
  #   irb(main):010:0> ('%0*b' % [32, 0x9D2C5680]).scan(/.{1,8}/)
  #   => ["10011101", "00101100", "01010110", "10000000"]
  #
  # We need to get the next 7 bits consecutively until we fill all 32:
  y ^= ((y << s) & 0x1680)      # The next 7 bits are 0101101. Hence, we need a bitmask of ["0101101", "0000000"] to XOR against.
  y ^= ((y << s) & 0xC4000)     # The next 7 bits are 1100010. Hence, we need a bitmask of ["0110001", "0000000", "0000000"] to XOR against.
  y ^= ((y << s) & 0xD200000)   # The next 7 bits are 1010010. Hence, we need a bitmask of ["1101001", "0000000", "0000000", "0000000"] to XOR against.
  y ^= ((y << s) & 0x90000000)  # The next 7 bits are 1001000. Hence, we need a bitmask of ["1001", "0000000", "0000000", "0000000", "0000000"] to XOR against.

  # Same thing. 11 bits at a time.
  y ^= ((y >> u) & 0xFFC00000)  # ["11111111110", "00000000000", "0000000000"]
  y ^= ((y >> u) & 0x3FF800)    # ["00000000001", "11111111110", "0000000000"]
  y ^= ((y >> u) & 0x7FF)       # ["00000000000", "00000000001", "1111111111"]
end

def clone_mt19937(mt)
  mt_clone = MatasanoLib::MT19937.new(0).tap do |clone|
    624.times do |i|
      clone.state[i] = mt.untemper(mt.extract_number)
    end
  end
end

mt_rand       = MatasanoLib::MT19937.new(0x1337)
mt_rand_clone = clone_mt19937(mt_rand)

# Test clone was successful.
10_000.times do
  raise 'MT19937 cloning failed!' unless mt_rand.extract_number == mt_rand_clone.extract_number
end

puts 'Winner! Here, have a few:'
puts

10.times do
  printf("[%s, %10s]\n", mt_rand.extract_number, mt_rand_clone.extract_number)
end

# Output
# ------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys005] [master ⚡] [~/Projects/Matasano/Ruby]> ruby 23.rb
# Winner! Here, have a few:
# 
# [3720904052, 3720904052]
# [3576649650, 3576649650]
# [919419452,  919419452]
# [1642496979, 1642496979]
# [2885456077, 2885456077]
# [1232031229, 1232031229]
# [3674379477, 3674379477]
# [2588028296, 2588028296]
# [1429259843, 1429259843]
# [1799426814, 1799426814]
