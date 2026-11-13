# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'socket'

runtime = JSON.parse(File.read(ARGV.fetch(0)))
host = runtime.fetch('module_endpoints').fetch('target').fetch('host')
records = {}
read_exact = lambda do |stream, size|
  data = ''.b
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 4
  while data.bytesize < size
    remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    raise IOError, 'Native OPC-UA frame deadline expired' unless remaining.positive? && IO.select([stream], nil, nil, remaining)

    data << stream.readpartial(size - data.bytesize)
  end
  data
end

[4840, 4841, 4842, 5840, 5842, 5841].each do |port|
  url = "opc.tcp://#{host}:#{port}".b
  body = [0, 65_535, 65_535, 0, 0, url.bytesize].pack('V*') + url
  hello = 'HELF'.b + [8 + body.bytesize].pack('V') + body
  row = { port: port, hello_base64: Base64.strict_encode64(hello) }
  Socket.tcp(host, port, connect_timeout: 3) do |stream|
    stream.write(hello)
    header = read_exact.call(stream, 8)
    size = header.byteslice(4, 4).unpack1('V')
    raise IOError, 'Native OPC-UA frame size exceeds bound' unless size.between?(8, 65_536)

    row[:header_base64] = Base64.strict_encode64(header)
    row[:declared_bytes] = size
    begin
      response = header + read_exact.call(stream, size - 8)
      row.merge!(response_base64: Base64.strict_encode64(response), response_sha256: Digest::SHA256.hexdigest(response), type: response.byteslice(0, 3), chunk: response.byteslice(3, 1))
      if response.start_with?('ACKF')
        raise IOError, 'Native ACK is not the complete 28-byte frame' unless response.bytesize == 28

        row[:ack] = %w[protocol_version receive_buffer send_buffer max_message max_chunks].zip(response.byteslice(8..).unpack('V5')).to_h
      elsif response.start_with?('ERRF')
        status, length = response.byteslice(8, 8).unpack('Vl<')
        raise IOError, 'Native ERR reason length differs' unless length == -1 || (length >= 0 && response.bytesize == 16 + length)

        row.merge!(status_code: format('0x%08X', status), reason: response.byteslice(16..).dup.force_encoding(Encoding::UTF_8))
      end
    rescue EOFError => e
      raise unless port == 5841

      row[:truncated] = e.class.name
    end
  end
  records[port.to_s] = row
end
raise IOError, 'Native ACK configurations differ' unless records.fetch('4840').fetch(:ack).values_at('protocol_version', 'receive_buffer', 'send_buffer') == [0, 65_535, 65_535] && records.fetch('4841').fetch(:ack).values_at('protocol_version', 'receive_buffer', 'send_buffer') == [0, 16_384, 16_384]
raise IOError, 'Fragmentation changed native ACK bytes' unless records.fetch('4840').fetch(:response_base64) == records.fetch('5840').fetch(:response_base64)
raise IOError, 'Fragmentation changed native ERR bytes' unless records.fetch('4842').fetch(:response_base64) == records.fetch('5842').fetch(:response_base64)
raise IOError, 'Configured server did not return its genuine error' unless records.fetch('4842').values_at(:type, :status_code, :reason) == ['ERR', '0x80020000', '']
raise IOError, 'Native truncated frame unexpectedly completed' unless records.fetch('5841').key?(:truncated)

Socket.tcp(host, 2525, connect_timeout: 3) do |stream|
  raise IOError, 'Native SMTP greeting timed out' unless IO.select([stream], nil, nil, 3)

  banner = stream.gets
  raise IOError, 'Unrelated service is not the native SMTP server' unless banner&.start_with?('220 ') && banner.include?('Python SMTP proxy version 0.3')

  records['smtp'] = { banner: banner }
end
begin
  Socket.tcp(host, 1, connect_timeout: 3).close
  raise IOError, 'Native refused port unexpectedly accepts connections'
rescue Errno::ECONNREFUSED
  records['refused'] = true
end
puts JSON.generate(status: 'native_passed', phase: ARGV.fetch(1), records: records)
