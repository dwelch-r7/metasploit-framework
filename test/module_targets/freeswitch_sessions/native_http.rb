# frozen_string_literal: true

require 'digest'
require 'json'
require 'webrick'

host, port, source, journal = ARGV
bytes = File.binread(source)
server = WEBrick::HTTPServer.new(BindAddress: host, Port: Integer(port, 10), AccessLog: [], Logger: WEBrick::Log.new(File::NULL), StartCallback: -> { puts 'FS_NATIVE_HTTP_READY' })
server.mount_proc('/native') do |request, response|
  response.status = 200
  response['Content-Type'] = 'application/octet-stream'
  response.body = bytes
  File.open(journal, 'a') { |file| file.puts(JSON.generate(peer: request.remote_ip, method: request.request_method, path: request.path, bytes: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes))) }
end
$stdout.sync = true
control = Thread.new do
  value = $stdin.gets
  raise ArgumentError, 'Unexpected native HTTP control' unless value.nil? || value == "STOP\n"

  server.shutdown
end
server.start
control.kill
