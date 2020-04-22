require 'open-uri'
require 'base64'

module MatasanoLib
  module URL
    class << self
      def read_each_line(url)
        open(url) do |f|
          f.each_line do |line|
            line.strip!
            yield(line)
          end
        end
      end

      def decode64(url)
        Base64.decode64(URI.open(url) { |f| f.read }.strip!)
      end
    end
  end
end
