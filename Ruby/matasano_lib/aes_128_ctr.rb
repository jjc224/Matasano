require_relative 'monkey_patch'
require_relative 'aes_128'
require_relative 'xor'

module MatasanoLib
  module AES_128_CTR

    class << self
      def crypt(input, key, opts = {})  # Default format: 64-bit unsigned little-endian [nonce, block counter].
        opts       = {nonce: 0, format: 'QQ<'} unless (opts[:nonce] && opts[:format])  # TODO: make better.
        blocks     = input.chunk(AES_128::BLOCKSIZE)
        ciphertext = ''

        for i in 0...blocks.size
          counter   = [opts[:nonce], i].pack(opts[:format])
          keystream = AES_128.encrypt(counter, key, :mode => :ECB, :padded => false)

          ciphertext << XOR.crypt(blocks[i], keystream).unhex
        end

        ciphertext
      end
    end
  end
end

# C_K = AES-128-ECB(K, $AES_KEY, :padded => false)
