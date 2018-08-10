# Challenge 22: crack an MT19937 seed.

# The coefficients of necessary MT19937 (32-bit):
$w, $n, $m, $r = 32, 624, 397, 31
$a = 0x9908B0DF
$u, $d = 11, 0xFFFFFFFF
$s, $b = 7, 0x9D2C5680
$t, $c = 15, 0xEFC60000
$l = 18

$mt = Array.new($n)
$index = $n + 1

LOWER_MASK = (1 << $r) - 1  # The binary number representation of 'r' 1's.
UPPER_MASK = ((1 << $w) - 1) & ~LOWER_MASK

# Initialize the generator with a seed.
def seed_mt(seed)
  $index = $n
  $mt[0] = seed
  f      = 1812433253  # The value for f for MT19937 (32-bit).

  # Loop over each element.
  for i in 1..($n - 1)
    $mt[i] = ((1 << $w) - 1) & (f * ($mt[i - 1] ^ ($mt[i - 1] >> ($w - 2))) + i)
  end
end

# Extract a tempered value based on MT[index] calling twist() every n numbers.
def rand_mt
  if $index >= $n
    raise "Generator was never seeded." if $index > $n  # Alternatively, seed with constant value; 5489 is used in reference C code.
    twist()
  end

  y = $mt[$index]
  y = y ^ ((y >> $u) & $d)
  y = y ^ ((y << $s) & $b)
  y = y ^ ((y << $t) & $c)
  y = y ^ (y >> $l)

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

  $index = 0  # Not meant as return.
end

# Write a routine that performs the following operation:
#
#   1. Wait a random number of seconds between, I don't know, 40 and 1000.
#   2. Seeds the RNG with the current Unix timestamp
#   3. Waits a random number of seconds again.
#   4. Returns the first 32 bit output of the RNG.
#
# You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.
# From the 32 bit RNG output, discover the seed.

# An insecure implementation of MT19937.
# Suppose it is a blackbox function (it's a greybox function ;~)).
def blackbox_mt19937
  sleep(rand(4..7))
  seed_mt(Time.now.to_i)
  sleep(rand(4..7))

  rand_mt  # Already returns a 32-bit int masked by 0xffffffff ((1 << $w) - 1).
end

def crack_blackbox_mt19937
  # As we are seeding with the current time padded between two intervals of time, it is simply a matter of brute-forcing the seed between that interval (when it's short like in this case).
  # We know that the seed is in the interval [t1, t2]. t2 - t1 also gives us an estimation of how long the function ran for.
  t1 = Time.now.to_i
  r  = blackbox_mt19937
  t2 = Time.now.to_i

  interval = (t1..t2).to_a  # It doesn't hurt to check for t1 and t2. May as well make it an inclusive interval.
  index    = interval.index { |seed| seed_mt(seed); r == rand_mt }

  interval[index] unless index.nil?
end

puts "Seed: #{crack_blackbox_mt19937.to_s}"  # This would output 'Seed: nil' on failure.

# Output:
#------------------------------------ ----------------------------
# [phizo@jizzo:~/Projects/Matasano/Ruby on master] time ruby 22.rb
# Seed: 2173666697
# ruby 22.rb  0.16s user 0.00s system 0% cpu 18:50.16 total
#
# NOTE: speed is solely due to the random interval of time runtime is put to sleep.
