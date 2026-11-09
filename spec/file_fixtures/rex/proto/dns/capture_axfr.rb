# frozen_string_literal: true

require 'socket'
require 'resolv'
require 'json'
require 'base64'

host, port, profile = ARGV
message = Resolv::DNS::Message.new(0x4212)
message.rd = 1
message.add_question('module-target.test', Resolv::DNS::Resource.get_class(252, 1))
request = message.encode
frames = []
Socket.tcp(host, Integer(port), connect_timeout: 3) do |socket|
  socket.write([request.bytesize].pack('n') + request)
  10.times do
    raise 'Native AXFR prefix timed out' unless IO.select([socket], nil, nil, 3)

    prefix = socket.read(2)
    break if prefix.nil? || prefix.empty?
    raise 'Native AXFR prefix incomplete' unless prefix.bytesize == 2

    length = prefix.unpack1('n')
    raise 'Native AXFR body timed out' unless IO.select([socket], nil, nil, 3)

    body = socket.read(length)
    raise 'Native AXFR body incomplete' unless body && body.bytesize == length

    parsed = Resolv::DNS::Message.decode(body)
    records = parsed.answer.map { |name, ttl, record| { name: name.to_s, ttl: ttl, type: record.class.name, text: record.inspect } }
    frames << { prefix_base64: Base64.strict_encode64(prefix), body_base64: Base64.strict_encode64(body), bytes: length, rcode: parsed.rcode, records: records }
    break if parsed.rcode != 0 || records.count { |record| record.fetch(:type).end_with?('::SOA') } >= 2
  end
end
if profile == 'open'
  raise 'Native AXFR records differ' unless frames.sum { |frame| frame[:records].size } == 13 && frames.sum { |frame| frame[:records].count { |record| record[:type].end_with?('::SOA') } } == 2
else
  raise 'Native refusal differs' unless frames.one? && frames.first[:rcode] == 5 && frames.first[:records].empty?
end
puts JSON.pretty_generate(host: host, port: port, profile: profile, request_base64: Base64.strict_encode64(request), frames: frames)
