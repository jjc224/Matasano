# Challenge 21: implement the MT19937 Mersenne Twister RNG.

class MT19937
  attr_accessor :state

  # The necessary coefficients of MT19937 (32-bit):
  @@w, @@n, @@m, @@r = 32, 624, 397, 31
  @@a = 0x9908B0DF
  @@u, @@d = 11, 0xFFFFFFFF
  @@s, @@b = 7, 0x9D2C5680
  @@t, @@c = 15, 0xEFC60000
  @@l = 18

  LOWER_MASK = (1 << @@r) - 1  # The binary number representation of 'r' 1's.
  UPPER_MASK = ((1 << @@w) - 1) & ~LOWER_MASK

  # Initialize the generator with a seed.
  def initialize(seed = nil)
    if seed.nil?
      @index = @@n + 1
      return
    end

    @state    = Array.new(@@n)
    @index    = @@n
    @state[0] = seed
    f         = 1812433253  # The value for f for MT19937 (32-bit).

    # Loop over each element.
    for i in 1..(@@n - 1)
      @state[i] = ((1 << @@w) - 1) & (f * (@state[i - 1] ^ (@state[i - 1] >> (@@w - 2))) + i)
    end
  end

  def temper(y)
    y ^= ((y >> @@u) & @@d)
    y ^= ((y << @@s) & @@b)
    y ^= ((y << @@t) & @@c)
    y ^= (y >> @@l)
  end

  # Extract a tempered value based on state[index] calling twist() every n numbers.
  def extract_number
    if @index >= @@n
      raise 'Generator was never seeded.' if @index > @@n  # Alternatively, seed with constant value; 5489 is used in reference C code.
      twist()
    end

    y = @state[@index]
    y = temper(y)

    @index += 1

    ((1 << @@w) - 1) & y
  end

  def twist
    for i in 0..(@@n - 1)
      x         = (@state[i] & UPPER_MASK) + (@state[(i + 1) % @@n] & LOWER_MASK)
      xA        = x >> 1
      xA       ^= @@a if x & 1
      @state[i] = @state[(i + @@m) % @@n] ^ xA
    end

    @index = 0  # Not meant as return.
  end
end

mt = MT19937.new(0x1337)
p [mt.extract_number, mt.extract_number, mt.extract_number]

# Output:
# -----------------------------------------------------------
# [jjc224@jizzo:~/Projects/Matasano/Ruby on master] ruby 21.rb
# [2614645925, 2804711513, 720410643]
