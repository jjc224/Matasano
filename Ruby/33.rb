# Challenge 33: implement Diffie-Hellman.

# Implementation of the memory-efficient, fast modular exponentiation algorithm known as "exponentiation by squaring" (right-to-left binary method).
# Computes `(base ** exp) % mod` (particularly useful for bignums).
def mod_exp(base, exp, mod)
  return 0 if mod == 1

  result = 1
  base %= mod

  while exp > 0
    result = (result * base) % mod if exp.even?

    exp >>= 1
    base = (base * base) % mod
  end

  result
end

class Diffie_Hellman
  DEFAULT_G = 2
  DEFAULT_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406

  attr_reader :public_key

  def initialize(p = DEFAULT_P, g = DEFAULT_G)
    @p = p
    @g = g
    @a = rand(1...p)

    @public_key = mod_exp(@g, @a, @p)
  end

  def shared_key(other_pubkey)
    mod_exp(other_pubkey, @a, @p)
  end
end

dh1 = Diffie_Hellman.new
dh2 = Diffie_Hellman.new

p dh1.shared_key(dh2.public_key) == dh2.shared_key(dh1.public_key)

# Output:
# ------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys012] [~/Projects/Matasano/Ruby]> ruby 33.rb
# true
