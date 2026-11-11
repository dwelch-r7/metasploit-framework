# frozen_string_literal: true

require 'base64'
require 'json'
require 'socket'

# Passive capture in the owned Framework network namespace, using its ordinary
# NET_RAW capability. Observe actual module traffic without replacing sockets.
runtime = JSON.parse(File.read(ARGV.fetch(0)))
local = runtime.fetch('listener_host')
peers = runtime.fetch('module_endpoints').values.map { |endpoint| endpoint.fetch('host') }
protocol = [0x0003].pack('n').unpack1('S')
capture = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, protocol)
packets = []
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 20
$stdout.sync = true
puts 'MEMCACHED_CAPTURE_READY'
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
  next unless frame.bytesize >= 42 && frame.byteslice(12, 2).unpack1('n') == 0x0800 && frame.getbyte(23) == 17

  header = (frame.getbyte(14) & 15) * 4
  next unless header >= 20 && frame.bytesize >= 14 + header + 8

  source = frame.byteslice(26, 4).unpack('C4').join('.')
  destination = frame.byteslice(30, 4).unpack('C4').join('.')
  direction = if source == local && peers.include?(destination)
                'request'
              elsif destination == local && peers.include?(source)
                'response'
              end
  next unless direction

  offset = 14 + header
  source_port, destination_port, length = frame.byteslice(offset, 6).unpack('n3')
  peer_port = direction == 'request' ? destination_port : source_port
  next unless [11211, 11212].include?(peer_port)
  raise 'Captured UDP length differs' unless length >= 8 && frame.bytesize >= offset + length
  raise 'Owning capture exceeds packet bound' if packets.size >= 128

  payload = frame.byteslice(offset + 8, length - 8)
  packets << {
    'direction' => direction, 'source' => source, 'destination' => destination,
    'source_port' => source_port, 'destination_port' => destination_port,
    'frame_bytes' => frame.bytesize, 'udp_payload_bytes' => payload.bytesize,
    'udp_payload_base64' => Base64.strict_encode64(payload)
  }
end
capture.close
puts JSON.generate('packets' => packets)
