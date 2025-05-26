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
    [self].pack('m0')
  end

  def decode64
    unpack('m0')[0]
  end
end

class Integer
  def to_hex
    self.to_s(16)
  end

  def left_rotate(shift, n = 32)
    mask = (1 << n) - 1
    ((self << shift) & mask) | ((self & mask) >> (n - shift))
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
    map { |x| [x].pack('m0') }
  end

  def decode64
    map { |x| x.unpack('m0')[0] }
  end

  def median
    return nil if empty?

    sorted = sort
    mid    = size / 2

    if size.even?
      (sorted[mid - 1] + sorted[mid]).to_f / 2
    else
      sorted[mid]
    end
  end
end
