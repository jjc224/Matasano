require_relative 'monkey_patch'
require_relative 'aes_128'
require_relative 'xor'

module MatasanoLib
    module AES_128_CRT

        class << self
            def crypt(input, key, opts = {})    # Default format: 64-bit unsigned little-endian [nonce, block counter].
                opts       = {nonce: 0, format: 'QQ<'} unless (opts[:nonce] && opts[:format])    # TODO: better.
                blocks     = input.chunk(AES_128::BLOCKSIZE)
                ciphertext = ''

                for i in 0...blocks.size
                    keystream     = [opts[:nonce], i].pack(opts[:format])
                    enc_keystream = AES_128.encrypt(keystream, key, :mode => :ECB, :padded => false)

                    ciphertext << XOR.crypt(blocks[i], enc_keystream).unhex
                end

                ciphertext
            end
        end
    end
end
