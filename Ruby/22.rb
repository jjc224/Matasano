# Challenge 22: crack an MT19937 seed.

require_relative 'matasano_lib/mt19937'

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
  sleep(rand(40..1000))
  mt = MatasanoLib::MT19937.new(Time.now.to_i)
  sleep(rand(40..1000))

  mt.extract_number  # Already returns a 32-bit int masked by 0xffffffff ((1 << $w) - 1).
end

def crack_blackbox_mt19937
  # As we are seeding with the current time padded between two intervals of time, it is simply a matter of brute-forcing the seed between that interval (when it's short like in this case).
  # We know that the seed is in the interval [t1, t2]. t2 - t1 also gives us an estimation of how long the function ran for.
  t1 = Time.now.to_i
  r  = blackbox_mt19937
  t2 = Time.now.to_i

  interval = (t1..t2).to_a  # It doesn't hurt to check for t1 and t2. May as well make it an inclusive interval.
  index    = interval.index { |seed| mt = MatasanoLib::MT19937.new(seed); r == mt.extract_number }

  interval[index] unless index.nil?
end

puts "Seed: #{crack_blackbox_mt19937.to_s}"  # This would output 'Seed: nil' on failure.

# Output:
# -----------------------------------------------------------------
# [jjc224@jizzo:~/Projects/Matasano/Ruby on master] time ruby 22.rb
# Seed: 1544870366
# ruby 22.rb  0.16s user 0.00s system 0% cpu 18:50.16 total
#
# NOTE: speed is solely due to the random interval of time runtime is put to sleep.
