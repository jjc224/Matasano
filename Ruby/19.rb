# Challenge 19: break fixed-nonce CTR mode using substitions.

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/aes_128'

# Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.
$RAND_KEY = '4d79fe4bcacbd950db9b20bfc656259c'.unhex

# In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts.
ciphertexts = [
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

ciphertexts.map! { |enc| MatasanoLib::AES_128.encrypt(enc.decode64, $RAND_KEY, :CRT) }

# Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been encrypted against the same keystream. This is very bad.
# Understanding that, like most stream ciphers (including RC4, and obviously any block cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a single XOR operation, it should be plain that: CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
# And since the keystream is the same for every ciphertext: CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
# say!")
#
# Attack this cryptosystem piecemeal: guess letters, use expected English language frequence to validate guesses, catch common English trigrams, and so on.

freq = Hash.new(0)

ciphertexts.each do |txt|
	txt.chars.to_hex.each { |byte| freq[byte] += 1 }
end

freq.sort_by(&:last).reverse.map.with_index do |x, i|
	end_of_row = i.next % 6 == 0

	print x
	print end_of_row ? "\n" : "\t"
end

# ["70", 35]	["39", 25]	["b0", 24]	["f1", 20]	["6c", 20]	["e4", 19]
# ["7c", 19]	["ab", 18]	["e3", 17]	["23", 16]	["04", 15]	["41", 15]
# ["f9", 14]	["14", 14]	["f8", 14]	["00", 14]	["ff", 13]	["76", 13]
# ["b9", 13]	["78", 13]	["74", 12]	["77", 12]	["0a", 12]	["3c", 12]
# ["6d", 11]	["90", 11]	["a3", 11]	["b2", 11]	["6a", 11]	["6e", 11]
# ["09", 11]	["d6", 11]	["22", 11]	["93", 10]	["71", 10]	["66", 10]
# ["f7", 10]	["e7", 10]	["96", 10]	["e2", 9]	["6b", 9]	["d3", 9]
# ["b6", 9]	["79", 9]	["0e", 9]	["72", 8]	["75", 8]	["31", 8]
# ["f5", 8]	["e5", 8]	["24", 7]	["a5", 7]	["bf", 7]	["be", 7]
# ["97", 7]	["0f", 7]	["4f", 7]	["6f", 7]	["0d", 7]	["35", 7]
# ["9a", 7]	["68", 6]	["67", 6]	["b4", 6]	["80", 6]	["34", 6]
# ["13", 6]	["81", 5]	["62", 5]	["46", 5]	["07", 5]	["01", 5]
# ["1d", 5]	["d7", 5]	["7b", 5]	["a4", 5]	["98", 5]	["9e", 5]
# ["fd", 5]	["7d", 5]	["18", 5]	["9b", 5]	["9f", 5]	["9d", 5]
# ["fe", 5]	["06", 5]	["08", 5]	["91", 5]	["b3", 4]	["60", 4]
# ["bb", 4]	["53", 4]	["d1", 4]	["5d", 4]	["de", 4]	["15", 4]
# ["73", 4]	["87", 4]	["16", 4]	["86", 4]	["f4", 4]	["5c", 4]
# ["7f", 4]	["ea", 4]	["5a", 4]	["02", 4]	["3f", 4]	["c2", 4]
# ["b8", 4]	["d5", 4]	["84", 4]	["32", 4]	["1a", 3]	["55", 3]
# ["59", 3]	["0b", 3]	["51", 3]	["92", 3]	["d4", 3]	["e8", 3]
# ["ba", 3]	["7a", 3]	["b5", 3]	["82", 3]	["d9", 3]	["47", 3]
# ["e0", 3]	["3e", 3]	["03", 3]	["fb", 3]	["c3", 3]	["27", 3]
# ["9c", 3]	["19", 2]	["5b", 2]	["38", 2]	["4d", 2]	["df", 2]
# ["56", 2]	["c9", 2]	["ee", 2]	["fc", 2]	["dd", 2]	["0c", 2]
# ["e9", 2]	["ec", 2]	["a0", 2]	["40", 2]	["f2", 2]	["36", 2]
# ["69", 2]	["43", 2]	["64", 2]	["42", 2]	["f3", 2]	["94", 2]
# ["d8", 2]	["c4", 2]	["50", 2]	["83", 2]	["3d", 2]	["25", 2]
# ["7e", 2]	["99", 1]	["95", 1]	["bc", 1]	["63", 1]	["1c", 1]
# ["a6", 1]	["a2", 1]	["20", 1]	["ed", 1]	["1b", 1]	["52", 1]
# ["12", 1]	["85", 1]	["e6", 1]	["2c", 1]	["4b", 1]	["f6", 1]
# ["30", 1]	["2f", 1]	["a7", 1]	["57", 1]	["cd", 1]	["cc", 1]
# ["ef", 1]	["33", 1]	["37", 1]	["29", 1]	["aa", 1]

