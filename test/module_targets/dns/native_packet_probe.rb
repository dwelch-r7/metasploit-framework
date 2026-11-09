# frozen_string_literal: true

# Run in the owned Framework container's network namespace. Ruby's standard
# resolver builds the native query; AF_PACKET records actual Ethernet lengths
# rather than deriving expectations from Framework's amplification calculation.
require 'base64'
require 'json'
require 'resolv'
require 'socket'

address = ARGV.fetch(0)
destination = Addrinfo.udp(address, 53)
udp = Socket.new(destination.afamily, Socket::SOCK_DGRAM, 0)
capture = nil
begin
  udp.connect(destination)
  local_port = udp.local_address.ip_port
  protocol = [0x0003].pack('n').unpack1('S') # ETH_P_ALL in network byte order.
  capture = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, protocol)
  message = Resolv::DNS::Message.new(0x4201)
  message.rd = 1
  domain = ARGV.fetch(1, 'module-target.test')
  raise ArgumentError, 'Unknown fixture domain' unless %w[module-target.test module-target.test.].include?(domain)

  message.add_question(domain, Resolv::DNS::Resource::IN::TXT)
  request = message.encode
  udp.send(request, 0)
  raise 'Native DNS response timed out' unless IO.select([udp], nil, nil, 3)

  response = udp.recv(4096)
  decoded = Resolv::DNS::Message.decode(response)
  raise 'Native TXT response differs' unless decoded.rcode.zero? && decoded.answer.any? { |_name, _ttl, record| record.is_a?(Resolv::DNS::Resource::IN::TXT) && record.strings.join == 'module-target-native-dns-proof' }

  frames = {}
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3
  until frames.keys.sort == %w[request response]
    remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    raise 'Native DNS packet capture timed out' if remaining <= 0 || !IO.select([capture], nil, nil, remaining)

    frame = capture.recv(4096)
    # Ethernet II has a 14-byte link header; IPv4 uses IHL (RFC 791 section 3.1),
    # while the IPv6 base header is 40 bytes (RFC 8200 section 3). These owned probes
    # have no IPv6 extensions or VLAN tags; UDP's header is 8 bytes (RFC 768).
    ether_type = frame.byteslice(12, 2).unpack1('n')
    if ether_type == 0x0800 && frame.getbyte(23) == 17
      offset = 14 + ((frame.getbyte(14) & 0x0f) * 4)
    elsif ether_type == 0x86dd && frame.getbyte(20) == 17
      offset = 14 + 40
    else
      next
    end
    source_port, destination_port, length = frame.byteslice(offset, 6).unpack('n3')
    next unless [source_port, destination_port].sort == [53, local_port].sort

    body = frame.byteslice(offset + 8, length - 8)
    kind = if body == request
             'request'
           elsif body == response
             'response'
           end
    frames[kind] = frame if kind
  end
  puts JSON.generate(
    family: frames.fetch('request').byteslice(12, 2).unpack1('n') == 0x86dd ? 'ipv6' : 'ipv4',
    socket_family: destination.ipv6? ? 'ipv6' : 'ipv4', address: address,
    request_dns_bytes: request.bytesize, response_dns_bytes: response.bytesize,
    request_frame_bytes: frames.fetch('request').bytesize, response_frame_bytes: frames.fetch('response').bytesize,
    request_frame_base64: Base64.strict_encode64(frames.fetch('request')),
    response_frame_base64: Base64.strict_encode64(frames.fetch('response'))
  )
ensure
  capture&.close
  udp.close
end
