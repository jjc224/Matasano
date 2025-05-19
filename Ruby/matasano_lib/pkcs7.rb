module MatasanoLib
  module PKCS7
    class << self
      @@blocksize = 16

      def pad(str, blocksize = @@blocksize)
        padding = blocksize - (str.length % blocksize)
        str + padding.chr * padding
      end

      def valid(str)
        pad_char = str[-1]
        padding  = pad_char * pad_char.ord

        # Confirm the last byte of `str` is within the range of valid PKCS #7 values and `str` ends with a sequence of that value.
        # (Leans on short-circuit evaluation of left operand.)
        pad_char.ord.between?(1, @@blocksize) && str.end_with?(padding)
      end

      def strip(str, blocksize = @@blocksize)
        # My bad, man, didn't mean to fuck with your string. Here you go. Sorry for any inconvenience.
        return str unless valid(str)

        pad_char  = str[-1]
        pad_start = str.length - pad_char.ord

        str[0..pad_start - 1]
      end
    end
  end
end
