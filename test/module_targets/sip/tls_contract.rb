# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'openssl'
require 'rex/socket'
require 'securerandom'
require 'socket'
require 'timeout'

host, port, certificate_path = ARGV
port = Integer(port)
certificate = OpenSSL::X509::Certificate.new(File.binread(certificate_path))
certificate_hash = Digest::SHA256.hexdigest(certificate.to_der)

def request_bytes(host, local)
  identifier = SecureRandom.hex(8)
  ["OPTIONS sip:1000@#{host} SIP/2.0", "Via: SIP/2.0/TLS #{local[0]}:#{local[1]};branch=z9hG4bK-#{identifier};rport", "From: <sip:native-probe@#{local[0]}>;tag=#{identifier}", "To: <sip:1000@#{host}>", "Call-ID: #{identifier}@#{local[0]}", 'CSeq: 1 OPTIONS', 'Content-Length: 0', '', ''].join("\r\n")
end

def ordinary_tls(host, port, certificate)
  context = OpenSSL::SSL::SSLContext.new
  context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  store = OpenSSL::X509::Store.new
  certificate ? store.add_cert(certificate) : store.set_default_paths
  context.cert_store = store
  raw = TCPSocket.new(host, port)
  ssl = OpenSSL::SSL::SSLSocket.new(raw, context)
  ssl.hostname = 'sip.module-target.test'
  ssl.sync_close = true
  Timeout.timeout(3) { ssl.connect }
  local = Socket.unpack_sockaddr_in(raw.getsockname)
  request = request_bytes(host, [local[1], local[0]])
  ssl.write(request)
  response = Timeout.timeout(3) { ssl.readpartial(65536) }
  raise 'Ordinary trusted TLS did not return real SIP 200' unless response.start_with?('SIP/2.0 200 ')

  { accepted: true, verify_mode: context.verify_mode, verify_result: ssl.verify_result, cipher: ssl.cipher, version: ssl.ssl_version, certificate_sha256: Digest::SHA256.hexdigest(ssl.peer_cert.to_der), request_base64: Base64.strict_encode64(request), response_base64: Base64.strict_encode64(response) }
rescue OpenSSL::SSL::SSLError => e
  raise unless !certificate && e.message.include?('certificate verify failed')

  { accepted: false, error_type: e.class.name, error: e.message, verify_mode: context.verify_mode }
ensure
  ssl&.close
  raw&.close
end

ordinary_rejected = ordinary_tls(host, port, nil)
raise 'System trust unexpectedly accepted the artificial certificate' if ordinary_rejected.fetch(:accepted)

ordinary_trusted = ordinary_tls(host, port, certificate)
raise 'Trusted endpoint certificate differs' unless ordinary_trusted.fetch(:certificate_sha256) == certificate_hash

socket = Rex::Socket::Tcp.create('PeerHost' => host, 'PeerPort' => port, 'SSL' => true, 'SSLVerifyMode' => 'PEER', 'Timeout' => 3)
begin
  local = socket.getsockname
  request = request_bytes(host, [local[1], local[2]])
  socket.put(request)
  response = socket.get_once(-1, 3)
  raise 'Rex PEER did not return real SIP 200' unless response&.start_with?('SIP/2.0 200 ')

  source_path, source_line = Rex::Socket::SslTcp.instance_method(:initsock_with_ssl_version).source_location
  rex = { accepted: true, verify_mode: socket.sslctx.verify_mode, peer_verified: socket.peer_verified, verify_result: socket.sslsock.verify_result, cipher: socket.sslsock.cipher, version: socket.sslsock.ssl_version, certificate_sha256: Digest::SHA256.hexdigest(socket.sslsock.peer_cert.to_der), request_base64: Base64.strict_encode64(request), response_base64: Base64.strict_encode64(response), gem_version: Gem.loaded_specs.fetch('rex-socket').version.to_s, source_path: source_path, source_line: source_line, source_sha256: Digest::SHA256.file(source_path).hexdigest, source_base64: Base64.strict_encode64(File.binread(source_path)), callback_source_location: socket.sslctx.verify_callback.source_location }
  raise 'Rex context did not select PEER' unless rex.fetch(:verify_mode) == OpenSSL::SSL::VERIFY_PEER
  raise 'Rex endpoint certificate differs' unless rex.fetch(:certificate_sha256) == certificate_hash

  puts JSON.pretty_generate(ordinary_rejected: ordinary_rejected, ordinary_trusted: ordinary_trusted, rex_peer: rex, ruby: RUBY_DESCRIPTION, openssl: OpenSSL::OPENSSL_VERSION)
ensure
  socket.close
end
