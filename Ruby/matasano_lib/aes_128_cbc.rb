require_relative 'monkey_patch'
require_relative 'aes_128'
require_relative 'xor'
require_relative 'pkcs7'

module MatasanoLib
  module AES_128_CBC

    class << self
      def encrypt(plaintext, key, opts = {})
        opts[:iv]    = "\0" * AES_128::BLOCKSIZE unless opts[:iv]
        plaintext    = PKCS7.pad(plaintext)
        plain_blocks = plaintext.chunk(AES_128::BLOCKSIZE)
        xor_plain    = XOR.crypt(plain_blocks[0], opts[:iv]).unhex
        prev_block   = AES_128.encrypt(xor_plain, key, :mode => :ECB, :padded => false)
        ciphertext   = prev_block

        # Neglect the first block and iterate through the rest.
        plain_blocks.shift
        plain_blocks.each do |curr_block|
          xor_plain  = XOR.crypt(curr_block, prev_block).unhex
          prev_block = AES_128.encrypt(xor_plain, key, :mode => :ECB, :padded => false)

          ciphertext << prev_block
        end

        ciphertext
      end

      def decrypt(enc, key, opts = {})
        opts[:iv]  = "\0" * AES_128::BLOCKSIZE unless opts[:iv]
        enc_blocks = enc.chunk(AES_128::BLOCKSIZE)
        dec_block  = AES_128.decrypt(enc_blocks[0], key, :mode => :ECB, :padded => false)
        plaintext  = XOR.crypt(dec_block, opts[:iv]).unhex
        prev_block = enc_blocks[0]

        # Neglect the first block and iterate through the rest.
        enc_blocks.shift
        enc_blocks.each do |curr_block|
          dec_block = AES_128.decrypt(curr_block, key, :mode => :ECB)
          plaintext << XOR.crypt(dec_block, prev_block).unhex

          prev_block = curr_block
        end

        #PKCS7.strip(plaintext)
        plaintext
      end
    end

  end
end
