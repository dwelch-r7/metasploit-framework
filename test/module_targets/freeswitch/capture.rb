# frozen_string_literal: true

require 'base64'
require 'json'
require 'socket'

# Reuse the Memcached lab's passive AF_PACKET approach for real TCP traffic.
# The existing Framework NET_RAW capability observes its own namespace only.
runtime = JSON.parse(File.read(ARGV.fetch(0)))
local = runtime.fetch('listener_host')
peers = runtime.fetch('module_endpoints').values.map { |endpoint| endpoint.fetch('host') }
protocol = [0x0003].pack('n').unpack1('S')
capture = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, protocol)
packets = []
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 75
port = Integer(ARGV.fetch(1))
$stdout.sync = true
puts 'FREESWITCH_CAPTURE_READY'
loop do
  remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise 'Owning packet observation timed out' unless remaining.positive?

  readable = IO.select([capture, $stdin], nil, nil, remaining)&.first || []
  if readable.include?($stdin)
    control = $stdin.gets
    raise 'Invalid capture control' unless control == "STOP\n"

    break
  end
  next unless readable.include?(capture)

  frame = capture.recv(65_535)
  next unless frame.bytesize >= 42 && frame.byteslice(12, 2).unpack1('n') == 0x0800 && frame.getbyte(23) == 6

  header = (frame.getbyte(14) & 15) * 4
  next unless header >= 20 && frame.bytesize >= 14 + header + 20

  source = frame.byteslice(26, 4).unpack('C4').join('.')
  destination = frame.byteslice(30, 4).unpack('C4').join('.')
  direction = if source == local && peers.include?(destination)
                'request'
              elsif destination == local && peers.include?(source)
                'response'
              end
  next unless direction

  offset = 14 + header
  source_port, destination_port, sequence = frame.byteslice(offset, 8).unpack('nnN')
  peer_port = direction == 'request' ? destination_port : source_port
  next unless peer_port == port

  tcp_header = (frame.getbyte(offset + 12) >> 4) * 4
  total = frame.byteslice(16, 2).unpack1('n')
  raise 'Captured TCP length differs' unless tcp_header >= 20 && total >= header + tcp_header && frame.bytesize >= 14 + total
  raise 'Owning capture exceeds packet bound' if packets.size >= 256

  payload = frame.byteslice(offset + tcp_header, total - header - tcp_header)
  packets << {
    'direction' => direction, 'source' => source, 'destination' => destination,
    'source_port' => source_port, 'destination_port' => destination_port,
    'sequence' => sequence, 'flags' => frame.getbyte(offset + 13),
    'frame_bytes' => frame.bytesize, 'payload_base64' => Base64.strict_encode64(payload)
  }
end
capture.close
puts JSON.generate('packets' => packets)
