# Challenge 20: break fixed-nonce CTR mode statistically.
#
# I intuitively took this statistical approach which you were meant to do in this challenge in the previous instead (break via subsitutions).
# I'll be reusing this code as my solution for the next one. I see no point in tediously rewriting a "suboptimal solution" as cryptopals put it.
#
# Another bottom-up, dynamic programming approach to solving this puzzle. It simplified the process greatly.

# FIXME: Just noticed there is a small bug per the output (possibly an off-by-one issue).

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'
require_relative 'matasano_lib/xor'

# Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.
AES_KEY = '4d79fe4bcacbd950db9b20bfc656259c'.unhex

# In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts.
PLAINTEXTS = [
  'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
  'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
  'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
  'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
  'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
  'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
  'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
  'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
  'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
  'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
  'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
  'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
  'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
  'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
  'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
  'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
  'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
  'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
  'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
  'U2hlIHJvZGUgdG8gaGFycmllcnM/',
  'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
  'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
  'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
  'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
  'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
  'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
  'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
  'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
  'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
  'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
  'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
  'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
  'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
  'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
  'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
  'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
]

# Transpose the ciphertext C into its own respective column (i.e. select every i'th character from every block of C).
# Each byte in the column is correspondently XOR'd with the most probable evil plaintext byte to produce the relevant keystream byte K = C ^ P'. We know this because P = C ^ K, naturally.
# The most probable K for (P', C) will be returned.
def decrypt_next_byte(ciphertexts, i)
  column = ciphertexts.map { |c| c[i] || '' }.join

  solution = MatasanoLib::XOR.brute(column, 'ETAOIN SHRDLU,.')
  solution[:key]
end

def decrypt_keystream(ciphertexts)
  keystream = ''

  ciphertexts.map.with_index do |c, i|
    candidate_key = decrypt_next_byte(ciphertexts, i)     # Do '(c.max_by(&:size).size).times' if necessary (code seems to be highly robust and derives the same, correct key for every instance).
    keystream << candidate_key unless candidate_key.nil?  # In which case, you will want to append the most common key in from the array of candidate keys to keystream instead.
  end

  keystream
end

def break_fixed_nonce_ctr
  ciphertexts = PLAINTEXTS.map { |enc| MatasanoLib::AES_128.encrypt(enc.decode64, AES_KEY, mode: :CTR) }
  keystream   = decrypt_keystream(ciphertexts)

  ciphertexts.map { |enc| MatasanoLib::XOR.crypt(enc, keystream).unhex }
end

break_fixed_nonce_ctr.each { |p| p p }

# Output
# ---------------------------------------------------
# "i have met them at close of day"
# "coming with vivid faces"
# "from counter or desk among grey"
# "eighteenth-century houses."
# "i have passed with a nod of the ,e\x06e"
# "or polite meaningless words,"
# "or have lingered awhile and said"
# "polite meaningless words,"
# "and thought before I had done"
# "of a mocking tale or a gibe"
# "to please a companion"
# "around the fire at the club,"
# "being certain that they and I"
# "but lived where motley is worn:"
# "all changed, changed utterly:"
# "a terrible beauty is born."
# "that woman's days were spent"
# "in ignorant good will,"
# "her nights in argument"
# "until her voice grew shrill."
# "what voice more sweet than hers"
# "when young and beautiful,"
# "she rode to harriers?"
# "this man had kept a school"
# "and rode our winged horse."
# "this other his helper and friend"
# "was coming into his force;"
# "he might have won fame in the en ,"
# "so sensitive his nature seemed,"
# "so daring and sweet his thought."
# "this other man I had dreamed"
# "a drunken, vain-glorious lout."
# "he had done most bitter wrong"
# "to some who are near my heart,"
# "yet I number him in the song;"
# "he, too, has resigned his part"
# "in the casual comedy;"
# "he, too, has been changed in hisdt\x12s\x02A"
# "transformed utterly:"
# "a terrible beauty is born."
