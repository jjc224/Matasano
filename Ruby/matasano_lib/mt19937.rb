module MatasanoLib
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

    # Solution for #23 (cloning an MT19937 instance): not part of the actual MT19937 implementation.
    # Inverts the temper() function, which is part of the actual implementation (a routine which provides diffusion).
    def untemper(y)
      # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX = y
      # 000000000000000000XXXXXXXXXXXXXX = y >> 18
      #
      # We can observe quite easily that for y ^ (y >> n), the first n bits of y will be retained, as a right-shift of n bits causes the result to have n 0-bits prepended and x ^ 0 = x for all x.
      # Let S = 18 be the shift, then since S ≥ 32 - S (= 14), the lower 32 - S bits can all trivially be restored all at once.
      y ^= (y >> @@l)

      # irb(main):002:0> ('%0*b' % [32, 0xEFC60000]).scan(/.{1,15}/)
      # => ["111011111100011", "000000000000000", "00"]
      #
      # As can be observed, the mask creates the same situation as above:
      #   The lower 17 bits can all trivially be restored all at once. While the shift gives 15 zero lower bits, the mask effectively makes it 17.
      #   17 ≥ 32 - 17 = 15
      y ^= ((y << @@t) & @@c)

      # The mask, @@b = 0x9D2C5680:
      #   irb(main):010:0> ('%0*b' % [32, 0x9D2C5680]).scan(/.{1,8}/)
      #   => ["10011101", "00101100", "01010110", "10000000"]
      #
      # We need to get the next 7 bits consecutively until we fill all 32:
      y ^= ((y << @@s) & 0x1680)      # The next 7 bits are 0101101. Hence, we need a bitmask of ["0101101", "0000000"] to XOR against.
      y ^= ((y << @@s) & 0xC4000)     # The next 7 bits are 1100010. Hence, we need a bitmask of ["0110001", "0000000", "0000000"] to XOR against.
      y ^= ((y << @@s) & 0xD200000)   # The next 7 bits are 1010010. Hence, we need a bitmask of ["1101001", "0000000", "0000000", "0000000"] to XOR against.
      y ^= ((y << @@s) & 0x90000000)  # The next 7 bits are 1001000. Hence, we need a bitmask of ["1001", "0000000", "0000000", "0000000", "0000000"] to XOR against.

      # Same thing. 11 bits at a time.
      y ^= ((y >> @@u) & 0xFFC00000)  # ["11111111110", "00000000000", "0000000000"]
      y ^= ((y >> @@u) & 0x3FF800)    # ["00000000001", "11111111110", "0000000000"]
      y ^= ((y >> @@u) & 0x7FF)       # ["00000000000", "00000000001", "1111111111"]
    end
  end
end
