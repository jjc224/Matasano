# Challenge 34: implement a MITM key-fixing attack on Diffie-Hellman with parameter injection.
require 'securerandom'
require 'openssl'

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/digest'
require_relative 'matasano_lib/aes_128'

class Diffie_Hellman
  DEFAULT_G = 2
  DEFAULT_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

  attr_reader :p, :g, :public_key, :session_key

  def initialize(p = DEFAULT_P, g = DEFAULT_G)
    @p = p
    @g = g
    @a = secure_random_bignum(@p + 1)

    # A = g^a mod p
    @public_key = mod_exp(@g, @a, @p)
  end

  def set_session_key(other_pubkey)
    raise 'set_session_key(other_pubkey) error: public key argument is invalid.' unless other_pubkey.is_a?(Integer)
    @session_key = mod_exp(other_pubkey, @a, @p)
  end

  private

  # @a = SecureRandom.rand(1...@p) would be okay for challenge purposes; but, for extremely large p's, it introduces bias (not uniformly distributed).
  # May as well do it right with OpenSSL::BN.
  def secure_random_bignum(max)
    OpenSSL::BN.rand_range(OpenSSL::BN.new(max.to_s)).to_i
  end

  # Implementation of the memory-efficient, fast modular exponentiation algorithm known as "exponentiation by squaring" (right-to-left binary method).
  # Computes `(base ** exp) % mod` (particularly useful for bignums).
  #
  # TODO: consider moving to a separate module for re-use.
  def mod_exp(base, exp, mod)
    return 0 if mod == 1

    result = 1
    base %= mod

    while exp > 0
      result = (result * base) % mod if exp.odd?

      exp >>= 1
      base = (base * base) % mod
    end

    result
  end
end

class EchoBot
  attr_reader :username

  def initialize(username)
    @username = username
  end

  def transmit(recipient_obj, message)
    puts "#{@username} -> #{recipient_obj.username}: #{message.inspect}."
    puts
  end
end

class Oracle
  # AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  def self.encrypt_message(message, dh_shared_key)
    key = derive_aes_key(dh_shared_key)
    iv  = SecureRandom.random_bytes

    MatasanoLib::AES_128.encrypt(message, key, iv: iv, mode: :CBC) + iv
  end

  # Generates the SHA-1 key used for AES later (AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv).
  # Consumes the DH session key.
  def self.derive_aes_key(dh_shared_key)
    dh_shared_key = dh_shared_key.to_s  # Convert to string for SHA-1 consumption, as it will be integer.
    MatasanoLib::Digest::SHA1.digest(dh_shared_key)[0, 16]
  end

  private_class_method :derive_aes_key
end

# Simulates the intended communication flow (no middleman).
# Note: unused / used for initial testing.
def simulate_intended
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')

  alice_dh = Diffie_Hellman.new
  bob_dh   = Diffie_Hellman.new(alice_dh.p, alice_dh.g)

  # A->B: Send "p", "g", "A"
  alice.transmit(bob, [alice_dh.p, alice_dh.g, alice_dh.public_key])
  bob_dh.set_session_key(alice_dh.public_key)

  # B->A: Send "B"
  bob.transmit(alice, bob_dh.public_key)
  alice_dh.set_session_key(bob_dh.public_key)

  raise 'Session key failure.' unless alice_dh.session_key == bob_dh.session_key

  # A->B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)

  alice.transmit(bob, alice_msg_enc.to_hex)

  # B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  bob_msg     = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"
  bob_msg_enc = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  bob.transmit(alice, bob_msg_enc.to_hex)
end

# Simulates the MITM attack.
def simulate_attack
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')
  mallory = EchoBot.new('Mallory')  # Malicious middleman.

  mallory_intercepted_msgs = []

  alice_dh = Diffie_Hellman.new
  bob_dh   = Diffie_Hellman.new(alice_dh.p, alice_dh.g)

  # A->M: Send "p", "g", "A"
  alice.transmit(mallory, [alice_dh.p, alice_dh.g, alice_dh.public_key])

  # M->B: Send "p", "g", "p"
  # Note: this is key-fixing aspect of the attack (on Bob).
  mallory.transmit(bob, [alice_dh.p, alice_dh.g, alice_dh.p])
  bob_dh.set_session_key(alice_dh.p)

  # B->M: Send "B"
  # Note: this is also p per the key-fixing attack.
  bob.transmit(mallory, bob_dh.public_key)

  # M->A: Send "p"
  # Note: this is key-fixing aspect of the attack (on Alice).
  mallory.transmit(alice, bob_dh.p)   # Could also be alice_dh.p sent; doesn't matter here since p is the same. But this is logically consistent with key exchange.
  alice_dh.set_session_key(bob_dh.p)  # Could also be alice_dh.p sent; doesn't matter here since p is the same. But this is logically consistent with key exchange.

  raise 'Session key failure.' unless alice_dh.session_key == bob_dh.session_key

  # A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)

  alice.transmit(mallory, alice_msg_enc.to_hex)
  mallory_intercepted_msgs.push(alice_msg_enc)

  # M->B: Relay that to B
  mallory.transmit(bob, alice_msg_enc.to_hex)

  # B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  # NOTE: I'm going to assume "A's msg" is actually meant to be B's message to A, as that is what makes sense.
  bob_msg     = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"
  bob_msg_enc = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  bob.transmit(mallory, bob_msg_enc.to_hex)
  mallory_intercepted_msgs << bob_msg_enc

  # M->A: Relay that to A
  mallory.transmit(alice, bob_msg_enc.to_hex)

  # Commentary.
  puts 'Communications complete. Decrypting.'
  puts
  puts 'Mallory knows the shared session key is 0 due to g^a ≡ p^a ≡ 0 (mod p).'
  puts "Derived AES key from SHA-1('0')[0:16]: #{MatasanoLib::Digest::SHA1.digest('0')[0, 16].to_hex}"
  puts

  # Decrypt Alice and Bob's intercepted, encrypted messages.
  mallory_intercepted_msgs.each_with_index do |enc, i| 
    puts "Decrypted message #{i + 1}: #{mallory_decrypt(enc)}"
  end
end

# Attacker's decryption routine based on knowledge of underlying algorithm and application of the key-fixing attack.
def mallory_decrypt(encrypted_message)
  # 'M should be able to decrypt the messages. "A" and "B" in the protocol -- the public keys, over the wire -- have been swapped out with "p".' 
  # 'Do the DH math on this quickly to see what that does to the predictability of the key.'

  # 'Decrypt the messages from M's vantage point as they go by.'

  # Since we have used parameter injection to set each public key to use the modulus p:
  #   `g^a mod p` becomes `p^a mod p`, which will always result to zero for any p per modulo exponentiation.
  # Hence, we reliably know that the session key s = 0 on both ends, and therefore the shared AES key is SHA1('0')[0:16] = unhex('b6589fc6ab0dc82cf12099d1c2d40ab9')
  known_session_key = '0'
  known_aes_key     = MatasanoLib::Digest::SHA1.digest(known_session_key)[0, 16]

  # We also know by protocol the IV is either appended or prepended. 
  # (Mallory has determined it is appended and taken them from the ciphertext.)
  iv = encrypted_message.byteslice(-16..-1)

  # Strip the IVs appended to each ciphertext in preparation for decryption.
  encrypted_message = encrypted_message.byteslice(0...-16)

  # Decrypt the message and return it.
  MatasanoLib::AES_128.decrypt(encrypted_message, known_aes_key, iv: iv, mode: :CBC)
end

simulate_attack

# 'Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack.' 
# 'But do the parameter injection attack; it's going to come up again.'

# Output
# ------------------------------------------------------------------------------------------------------------------------------------------
# josh@lsd ~/Projects/Matasano/Ruby master !8 ?19                                                                                                                                                                                  08:22:43 PM
# ❯ ruby 34.rb
# Alice -> Mallory: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170
# 325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2, 223
# 44143436599197018226157844377125209878153453012877546112745572019000617772522202871941411778027848763297133962288813991955684726980150317769191171504227627104363363485408351217621926477405445013010009597668705867101772781347489096781316500130856
# 77025653762156622703409912505017439340098241424047691849131475897297689687884405570147726199081479308860594047390023487546741023431066225234916133551183074968469441497327917662911223860941665045021389048406018861017].
# 
# Mallory -> Bob: [241031242692103258855207602219756607485695054850245994265411694195810883168261222889009385826134161467322714147790401219650364895705058263194273070680500922306273474534107340669624601458936165977404102716924945320037872943417032
# 5843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2, 24103
# 12426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193
# 776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919].
# 
# Bob -> Mallory: 1705573940854658252830746315069415488019311579559382964880358403652227535758950562167151452501269612175564837517027566698537748634049787843536418667405145810260129568956656801412068010855913708154707740444593415600542262572229716
# 981023202103774016548073297174159415448650053249257257790732768745685845628483077830564728748964885195439477773557247507734807816134541862122289614095364571949096998106699169930065130616951046387138836610491824494739638983860498430331.
# 
# Mallory -> Alice: 24103124269210325885520760221975660748569505485024599426541169419581088316826122288900938582613416146732271414779040121965036489570505826319427307068050092230627347453410734066962460145893616597740410271692494532003787294341703
# 25843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919.
# 
# Alice -> Mallory: "d3093ac56d556a615c30258933fecd2bed7b6e7510066013f20555ac656f8605765520d12f16e4d01073eec1d5271cc4fd45afd5f734fa904e69f5e7ad819f54".
# 
# Mallory -> Bob: "d3093ac56d556a615c30258933fecd2bed7b6e7510066013f20555ac656f8605765520d12f16e4d01073eec1d5271cc4fd45afd5f734fa904e69f5e7ad819f54".
# 
# Bob -> Mallory: "0a9b849e71585c2c9ee23011dc088c34c31dd0e73221440ed8a006a960027d5e7a79c121b0a444e2d9ea84b611ded3c325ae9d33300e32a716cdbc74f42df17f624902ba4f70cd4f3e2b3ebf1d23c5cc".
# 
# Mallory -> Alice: "0a9b849e71585c2c9ee23011dc088c34c31dd0e73221440ed8a006a960027d5e7a79c121b0a444e2d9ea84b611ded3c325ae9d33300e32a716cdbc74f42df17f624902ba4f70cd4f3e2b3ebf1d23c5cc".
# 
# Communications complete. Decrypting.
# 
# Mallory knows the shared session key is 0 due to g^a ≡ p^a ≡ 0 (mod p).
# Derived AES key from SHA-1('0')[0:16]: b6589fc6ab0dc82cf12099d1c2d40ab9
# 
# Decrypted message 1: Hola Bobby boy, how are ya bruz?
# Decrypted message 2: Yooo! Alice, my girl, you still ridin' those gnarly waves?
