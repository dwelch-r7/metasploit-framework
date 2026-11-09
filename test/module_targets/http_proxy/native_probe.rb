# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
reports = []
at_exit { puts JSON.pretty_generate(requests: reports) }
expected = File.binread(File.join(__dir__, 'index.html'))

def request_via(runtime, service, port, tls: false)
  proxy = runtime.fetch('endpoints').fetch(service)
  http = Net::HTTP.new('destination', port, proxy.fetch('host'), proxy.fetch('port'))
  http.open_timeout = 5
  http.read_timeout = 5
  http.use_ssl = tls
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE if tls # Disposable origin certificate; identity is checked below.
  report = { service: service, destination_port: port, tls: tls }
  begin
    http.start do |client|
      response = client.get('/')
      report.merge!(code: response.code, headers: response.to_hash, body: response.body)
      report[:certificate_subject] = client.peer_cert.subject.to_s if tls
    end
  rescue Net::HTTPClientException, Net::HTTPFatalError => e
    # Net::HTTP raises on a refused CONNECT before attempting TLS.
    raise unless tls

    report.merge!(code: e.response.code, connect_refusal: true)
  end
  report
end

[80, 8080].each do |port|
  report = request_via(runtime, 'open', port)
  reports << report
  raise "Native GET forwarding failed: #{report.inspect}" unless report.fetch(:code) == '200' && report.fetch(:body) == expected && report.fetch(:headers).key?('via')
end

[443, 8443].each do |port|
  report = request_via(runtime, 'open', port, tls: true)
  reports << report
  raise "Native HTTPS tunnel failed: #{report.inspect}" unless report.fetch(:code) == '200' && report.fetch(:body) == expected && report.fetch(:certificate_subject) == '/CN=destination'
end

{ 'denied' => %w[403 403], 'unrelated' => %w[200 405] }.each do |service, codes|
  [false, true].zip(codes).each do |tls, code|
    report = request_via(runtime, service, tls ? 443 : 8080, tls: tls)
    reports << report
    raise "Native refusal failed: #{report.inspect}" unless report.fetch(:code) == code
    raise 'Unrelated server returned origin contents' if report[:body] == expected

    if service == 'unrelated' && !tls && report.fetch(:body) != File.binread(File.join(__dir__, '../http/htdocs/index.html'))
      raise 'Unrelated HTTP identity mismatch'
    end
  end
end

report = request_via(runtime, 'open', 8444, tls: true)
reports << report
raise "Unavailable destination was accepted: #{report.inspect}" unless report.fetch(:code) == '503' && report[:connect_refusal]
