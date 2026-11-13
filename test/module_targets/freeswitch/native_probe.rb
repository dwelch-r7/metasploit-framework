# frozen_string_literal: true

require 'digest'
require 'json'
require 'socket'

# Original mod_event_socket framing and responses are independently calibrated
# against the pinned service; this client never substitutes for Framework I/O.
class FreeSwitchNativeClient
  attr_reader :frames

  def initialize(host, port)
    @socket = Socket.tcp(host, port, connect_timeout: 3)
    @buffer = ''.b
    @frames = []
  end

  def more
    raise 'Native event-socket response timed out' unless IO.select([@socket], nil, nil, 4)

    @buffer << @socket.readpartial(65_536)
    raise 'Native frame exceeds bound' if @buffer.bytesize > 65_536
  end

  def frame
    more until @buffer.include?("\n\n")
    header, @buffer = @buffer.split("\n\n", 2)
    fields = header.lines.to_h do |line|
      name, value = line.split(':', 2)
      [name.downcase, value.strip]
    end
    length = Integer(fields.fetch('content-length', '0'))
    raise 'Invalid native frame size' unless length.between?(0, 65_536)

    more while @buffer.bytesize < length
    body = @buffer.slice!(0, length)
    @frames << { headers: fields, body: body.dup.force_encoding(Encoding::UTF_8), body_sha256: Digest::SHA256.hexdigest(body) }
    @frames.last
  end

  def command(text)
    @socket.write(text.b + "\n\n")
    frame
  end

  def close
    @socket.close
  end
end

runtime = JSON.parse(File.read(ARGV.fetch(0)))
endpoint = runtime.fetch('module_endpoints').fetch('target')
mode = ENV.fetch('FREESWITCH_MODE')
password = ENV.fetch('FREESWITCH_PASSWORD')
records = []
if mode == 'unrelated'
  Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 3) do |stream|
    raise 'Missing native SSH banner' unless IO.select([stream], nil, nil, 4)

    banner = stream.gets
    raise 'Unrelated service is not genuine OpenSSH' unless banner&.start_with?('SSH-2.0-OpenSSH')

    records << { banner: banner }
  end
else
  passwords = mode == 'acl' ? [nil] : ['module-target-wrong-password', password]
  passwords.each do |candidate|
    client = FreeSwitchNativeClient.new(endpoint.fetch('host'), endpoint.fetch('port'))
    begin
      greeting = client.frame
      if mode == 'acl'
        raise 'Native ACL did not reject the client' unless greeting.fetch(:headers).fetch('content-type') == 'text/rude-rejection' && greeting.fetch(:body) == "Access Denied, go away.\n"
      else
        raise 'Native authentication request absent' unless greeting.fetch(:headers).fetch('content-type') == 'auth/request'

        reply = client.command("auth #{candidate}")
        expected = candidate == password ? '+OK accepted' : '-ERR invalid'
        raise 'Native password result differs' unless reply.fetch(:headers).fetch('reply-text') == expected

        if candidate == password
          version = client.command('api version')
          raise 'Native version differs' unless version.fetch(:body).include?('FreeSWITCH Version 1.10.10-release') && version.fetch(:body).include?('4cb05e7')
          raise 'Native module absent' unless client.command('api module_exists mod_event_socket').fetch(:body).strip == 'true'
          raise 'Native system output differs' unless client.command('api system printf native-freeswitch-control').fetch(:body) == 'native-freeswitch-control'
        end
      end
    ensure
      records << { password: candidate, frames: client.frames }
      client.close
    end
  end
end
begin
  Socket.tcp(endpoint.fetch('host'), 1, connect_timeout: 3).close
  raise 'Expected refused fixture port is accepting connections'
rescue Errno::ECONNREFUSED
  refused = true
end
puts JSON.generate(status: 'native_passed', mode: mode, phase: ARGV.fetch(1), records: records, refused_port: refused)
