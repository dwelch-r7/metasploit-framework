# frozen_string_literal: true

require 'base64'
require 'socket'

# Independent client for the documented eight-byte UDP header and ASCII protocol:
# https://github.com/memcached/memcached/blob/1.6.26/doc/protocol.txt
module NativeMemcachedWire
  def self.tcp(host, command)
    Socket.tcp(host, 11211, connect_timeout: 2) do |socket|
      socket.write(command)
      result = +''
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
      loop do
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        raise 'Native TCP response timed out' unless remaining.positive? && IO.select([socket], nil, nil, remaining)

        result << socket.readpartial(8192)
        break if result.start_with?('VERSION ') || result.end_with?("END\r\n")
      end
      result
    end
  end

  def self.udp(host, port, command, request_id: 0x4217, timeout: 2)
    request = [request_id, 0, 1, 0].pack('n4') + command
    packets = []
    refusal = nil
    socket = UDPSocket.new
    socket.connect(host, port)
    socket.send(request, 0)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
      break unless remaining.positive? && IO.select([socket], nil, nil, remaining)

      begin
        bytes = socket.recv(65_535)
      rescue Errno::ECONNREFUSED => e
        refusal = e.class.name
        break
      end
      raise 'Native UDP header is truncated' if bytes.bytesize < 8

      identifier, sequence, count, reserved = bytes.unpack('n4')
      raise 'Native UDP header differs' unless identifier == request_id && reserved.zero? && count.positive? && sequence < count
      raise 'Native UDP response exceeds bound' if count > 32 || packets.size >= 32
      raise 'Native UDP fragment is duplicated' if packets.any? { |packet| packet['sequence'] == sequence }

      packets << {
        'base64' => Base64.strict_encode64(bytes), 'bytes' => bytes.bytesize,
        'sequence' => sequence, 'count' => count
      }
      break if packets.size == count
    end
    ordered = packets.sort_by { |packet| packet.fetch('sequence') }
    complete = !ordered.empty? && ordered.map { |packet| packet['sequence'] } == (0...ordered.first['count']).to_a && ordered.map { |packet| packet['count'] }.uniq.size == 1
    text = ordered.map { |packet| Base64.strict_decode64(packet.fetch('base64')).byteslice(8..) }.join if complete
    {
      'request_base64' => Base64.strict_encode64(request), 'request_bytes' => request.bytesize,
      'packets' => packets, 'complete' => complete, 'text' => text,
      'response_bytes' => packets.sum { |packet| packet.fetch('bytes') }, 'refusal' => refusal
    }
  ensure
    socket&.close
  end
end
