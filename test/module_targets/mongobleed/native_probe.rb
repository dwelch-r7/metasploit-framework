# frozen_string_literal: true

require 'base64'
require 'json'
require 'socket'
require 'timeout'
require 'zlib'

# Published one-packet check, independent of Framework's client/parser:
# https://www.wiz.io/blog/mongobleed-cve-2025-14847-exploited-in-the-wild-mongodb
packet = ['2a0000000100000000000000dc070000dd0700003200000002789c636080028144064620050002ca0073'].pack('H*')
result = Timeout.timeout(5) do
  socket = TCPSocket.new(ARGV.fetch(0), Integer(ARGV.fetch(1), 10))
  begin
    socket.write(packet)
    header = socket.read(16)
    if header.nil? || header.length < 16
      { status: 'closed', response_base64: Base64.strict_encode64(header.to_s) }
    else
      length, _request, response_to, opcode = header.unpack('V4')
      raise ArgumentError, 'Native MongoDB response exceeds bound' unless length.between?(16, 1_048_576)

      body = socket.read(length - 16)
      raise EOFError, 'Native MongoDB response is incomplete' unless body && body.length == length - 16

      decoded = opcode == 2012 ? Zlib::Inflate.inflate(body.byteslice(9..)) : body
      {
        status: 'reply', opcode: opcode, response_to: response_to,
        response_base64: Base64.strict_encode64(header + body),
        decoded_base64: Base64.strict_encode64(decoded), bson_signature: decoded.include?('BSON')
      }
    end
  ensure
    socket.close
  end
end
puts JSON.generate(result)
