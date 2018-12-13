# Challenge 23: clone an MT19937 RNG from its output.

# The coefficients of necessary MT19937 (32-bit):
$w, $n, $m, $r = 32, 624, 397, 31
$a = 0x9908B0DF
$u, $d = 11, 0xFFFFFFFF
$s, $b = 7, 0x9D2C5680
$t, $c = 15, 0xEFC60000
$l = 18

$mt = Array.new($n)
$index = $n + 1

LOWER_MASK = (1 << $r) - 1    # The binary number representation of 'r' 1's.
UPPER_MASK = ((1 << $w) - 1) & ~LOWER_MASK

# Initialize the generator with a seed.
def seed_mt(seed)
  $index = $n
  $mt[0] = seed
  f      = 1812433253    # The value for f for MT19937 (32-bit).

  # Loop over each element.
  for i in 1..($n - 1)
    $mt[i] = ((1 << $w) - 1) & (f * ($mt[i - 1] ^ ($mt[i - 1] >> ($w - 2))) + i)
  end
end

def temper(y)
  #p "Temper:   #{[y, y.to_s(2)]}"

  y ^= ((y >> $u) & $d)
  y ^= ((y << $s) & $b)
  y ^= ((y << $t) & $c)
  y ^= (y >> $l)

  y
end

# Extract a tempered value based on MT[index] calling twist() every n numbers.
def extract_number
  if $index >= $n
    raise "Generator was never seeded." if $index > $n    # Alternatively, seed with constant value; 5489 is used in reference C code.
    p 'twist()'
    twist()
  end

  y = $mt[$index]
  y = temper(y)
  #untemper(y)

  $index += 1

  ((1 << $w) - 1) & y
end

def twist
  for i in 0..($n - 1)
    x      = ($mt[i] & UPPER_MASK) + ($mt[(i + 1) % $n] & LOWER_MASK)
    xA     = x >> 1
    xA    ^= $a if x & 1
    $mt[i] = $mt[(i + $m) % $n] ^ xA
  end

  $index = 0    # Not meant as return.
end

# For y ^ (y >> n), the first n bits of y will be retained, as a right-shift of n bits causes the result to have n 0-bits prepended and x ^ 0 = x for all x.
def r_unshift_xor(y, shift, mask = 0xFFFFFFFF)
  i = 0

  while i * shift < 32
    y ^= ((y >> shift) & mask)
    i += 1
  end

  y
end

def l_unshift_xor(y, shift, mask = 0xFFFFFFFF)
  i = 0

  while i * shift < 32
    y ^= ((y << shift) & mask)
    i += 1
  end

  y
end

def untemper(y)
  y ^= (y >> $l)
  y ^= ((y << $t) & $c)
  7.times { y ^= ((y << $s) & $b) }
  3.times { y ^= ((y >> $u) & $d) }

  #p "Untemper: #{[y, y.to_s(2)]}"

  y
end

# Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.
# The new "spliced" generator should predict the values of the original.
seed_mt(0x1337)

clone_state = []

624.times do |i|
  clone_state[i] = untemper(extract_number)
end

seed_mt(0x1337)
10.times { |i| p [extract_number, clone_state[i]] }

#p [extract_number, extract_number, extract_number]
#p [extract_number, extract_number, extract_number]
#p [extract_number, extract_number, extract_number]
