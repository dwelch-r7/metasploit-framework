# frozen_string_literal: true

require 'socket'
require 'base64'
require 'json'

# Independent Mode 6 reader, using the RFC 1305 Appendix B header layout.
# https://www.rfc-editor.org/rfc/rfc1305#appendix-B
module NativeNtpWire
  def self.query(host, port, version)
    sequence = 23
    request = [(version << 3) | 6, 2, sequence, 0, 0, 0, 0].pack('CCnnnnn')
    packets = []
    socket = UDPSocket.new
    socket.connect(host, port)
    socket.send(request, 0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
    loop do
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      break if remaining <= 0 || !IO.select([socket], nil, nil, remaining)

      bytes = socket.recv(65_535)
      packet = { 'base64' => Base64.strict_encode64(bytes), 'bytes' => bytes.bytesize }
      packets << packet
      next if bytes.bytesize < 12

      flags, operation, reply_sequence, status, association, offset, count = bytes.unpack('CCnnnnn')
      valid = (flags & 7) == 6 && ((flags >> 3) & 7) == version && (operation & 0x80) != 0 && (operation & 0x1f) == 2 && reply_sequence == sequence && association.zero? && count <= bytes.bytesize - 12
      packet.merge!('valid' => valid, 'error' => (operation & 0x40) != 0, 'more' => (operation & 0x20) != 0, 'offset' => offset, 'count' => count, 'status' => status)
      packet['text'] = bytes.byteslice(12, count).force_encoding(Encoding::UTF_8) if valid && !packet.fetch('error')
      break if valid && !packet.fetch('more')
      break if packets.length >= 8
    end
    ordered = packets.select { |packet| packet['text'] }.sort_by { |packet| packet.fetch('offset') }
    expected_offset = 0
    complete = !ordered.empty? && ordered.all? do |packet|
      contiguous = packet.fetch('offset') == expected_offset
      expected_offset += packet.fetch('count')
      contiguous
    end && !ordered.last.fetch('more')
    {
      'request_base64' => Base64.strict_encode64(request), 'request_bytes' => request.bytesize,
      'packets' => packets, 'complete' => complete,
      'text' => complete ? ordered.map { |packet| packet.fetch('text') }.join : nil,
      'response_bytes' => packets.sum { |packet| packet.fetch('bytes') }
    }
  ensure
    socket&.close
  end
end

puts JSON.pretty_generate(NativeNtpWire.query(ARGV.fetch(0), Integer(ARGV.fetch(1)), Integer(ARGV.fetch(2)))) if $PROGRAM_NAME == __FILE__
