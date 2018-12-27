# Challenge 9: implement PKCS#7 padding.

def pkcs7_pad(str, blocksize)
  padding = blocksize - (str.length % blocksize)
  str << padding.chr * padding
end

puts pkcs7_pad('YELLOW SUBMARINE', 20)
