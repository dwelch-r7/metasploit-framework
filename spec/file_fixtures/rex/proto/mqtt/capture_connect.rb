# frozen_string_literal: true

# Capture real broker replies independently from Framework and the mqtt gem.
# MQTT3.1 wire format: https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
require 'base64'
require 'json'
require 'net/http'
require 'socket'

runtime = JSON.parse(File.read(ARGV.fetch(0)))
string = ->(value) { [value.bytesize].pack('n') + value }
profiles = [
  ['accepted', 'open', nil],
  ['refused', 'auth', ['lab-mqtt-user', 'wrong-password']],
  ['no_response', 'unrelated', nil]
]
captures = profiles.map do |name, service, credentials|
  endpoint = runtime.fetch('endpoints').fetch(service)
  flags = credentials ? 0xc2 : 0x02
  body = string.call('MQIsdp') + [3, flags, 0, 30].pack('C4') + string.call('module-target-native')
  body += credentials.map { |value| string.call(value) }.join if credentials
  raise ArgumentError, 'Fixture CONNECT too large' unless body.bytesize < 128

  request = [0x10, body.bytesize].pack('C2') + body
  response = nil
  Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 3) do |socket|
    socket.write(request)
    response = socket.readpartial(4096) if IO.select([socket], nil, nil, 2)
  end
  {
    name: name, protocol: 'MQTT3.1', request_base64: Base64.strict_encode64(request),
    response_base64: response && Base64.strict_encode64(response), response_timed_out: response.nil?
  }
end
http = runtime.fetch('endpoints').fetch('unrelated')
client = Net::HTTP.new(http.fetch('host'), http.fetch('port'), nil)
client.read_timeout = 3
reply = client.get('/')
raise 'Unrelated native HTTP control failed' unless reply.code == '200'

puts JSON.pretty_generate(
  software: 'Eclipse Mosquitto 2.0.22 on Alpine 3.23.8; Apache HTTP 2.4.62',
  image: 'eclipse-mosquitto:2.0.22@sha256:81a6193ae693942a3231cd3ac52875b02b7e3a19da671b2fb4b55cc874c5b279',
  captures: captures, http_control: { status: reply.code.to_i, server: reply['Server'] }
)
