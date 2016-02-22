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
end

class Array
	def to_hex
		map { |x| x.unpack('H*')[0] }
	end

	def unhex
		map { |x| [x].pack('H*') }
	end
end
