class String
	def chunk(size)
		scan(/.{1,#{size}}/m)
	end

	def to_hex
		unpack('H*')[0]
	end

	def unhex
		[self].pack('H*')
	end

	def encode64
		[self].pack('m')
	end

	def decode64
		unpack('m')[0]
	end
end

class Array
	def to_hex
		map { |x| x.unpack('H*')[0] }
	end

	def unhex
		map { |x| [x].pack('H*') }
	end

	def encode64
		map { |x| [x].pack('m') }
	end

	def decode64
		map { |x| x.unpack('m')[0] }
	end
end