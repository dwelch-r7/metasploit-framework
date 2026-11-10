require 'acceptance_spec_helper'
require 'openssl'
require_relative '../../../test/module_targets/sip/acceptance'

RSpec.describe 'Genuine SIP OPTIONS discovery' do
  include_context 'real SIP targets'

  cases = %w[exposed protected].product(%w[udp tcp], %w[1000 1001 1002]) + %w[1000 1001 1002].map { |account| ['exposed', 'tls', account] }
  cases.each do |service, transport, account|
    it "persists the native #{service} #{account} fingerprint twice over #{transport}" do
      expected = native_reply(service, transport, 'OPTIONS', account)
      headers = {}
      %w[User-Agent Server Allow].each do |name|
        values = expected.fetch('headers')[name.downcase]
        headers[name] = values.join(',') if values
      end
      fingerprint = { 'code' => expected.fetch('code').to_s, 'message' => expected.fetch('reason') }
      headers.each { |name, value| fingerprint['header_' + name.tr('-', '_').downcase] = value }
      summary = "SIP/2.0 #{expected.fetch('code')} #{expected.fetch('reason')}"
      summary += ": #{headers}" unless headers.empty?
      protocol = transport == 'udp' ? 'udp' : 'tcp'
      port = transport == 'tls' ? 5061 : 5060
      fullname = transport == 'udp' ? 'auxiliary/scanner/sip/options' : 'auxiliary/scanner/sip/options_tcp'
      options = { 'TO' => account }
      options['ScannerRecvWindow'] = 1 if transport == 'udp' && !(service == 'exposed' && account == '1000')
      options.merge!('SSL' => true, 'SSLVerifyMode' => 'NONE') if transport == 'tls'
      snapshots = 2.times.map do
        before = inactive(service)
        output = scan(fullname, service, options, port: port)
        expect(output).to include(summary)
        current = { services: services, notes: notes }
        expect(state_content(inactive(service))).to eq(state_content(before))
        expect(credentials).to eq([])
        current
      end
      snapshots.each do |snapshot|
        expect(snapshot.fetch(:services).map { |row| row.except('id') }).to eq([{ 'address' => endpoint(service).fetch('host'), 'port' => port, 'proto' => protocol, 'name' => 'sip', 'info' => summary }])
        expect(snapshot.fetch(:notes).map { |row| row.except('id') }).to eq([{ 'address' => endpoint(service).fetch('host'), 'port' => port, 'proto' => protocol, 'ntype' => 'sip.options.fingerprint', 'data' => fingerprint }])
      end
      expect(snapshots.last).to eq(snapshots.first)
    end
  end

  %w[udp tcp].each do |transport|
    it "does not identify the genuinely responsive DNS server as SIP over #{transport}" do
      2.times do
        fullname = transport == 'udp' ? 'auxiliary/scanner/sip/options' : 'auxiliary/scanner/sip/options_tcp'
        options = transport == 'udp' ? { 'ScannerRecvWindow' => 1 } : {}
        output = scan(fullname, 'unrelated', options, allow_errors: true)
        expect(output).not_to match(%r{SIP/2\.0 \d{3}})
        expect(services).to eq([])
        expect(notes).to eq([])
        expect(credentials).to eq([])
      end
    end
  end

  it 'records the observational PEER limitation using ordinary OpenSSL rejection and genuine Rex SIP replies' do
    certificate = File.join(target_runtime.fetch('artifacts'), 'fixture-public.crt')
    File.binwrite(certificate, target_exec('exposed', 'openssl', 'x509', '-in', '/etc/asterisk/module-target.pem'))
    raw = target_exec('framework', 'ruby', 'test/module_targets/sip/tls_contract.rb', endpoint('exposed').fetch('host'), '5061', certificate)
    File.binwrite(File.join(target_runtime.fetch('artifacts'), 'tls-verification-contract.json'), raw)
    contract = JSON.parse(raw)
    expect(contract.fetch('ordinary_rejected').fetch('accepted')).to be(false)
    expect(contract.fetch('ordinary_trusted').fetch('accepted')).to be(true)
    expect(contract.fetch('rex_peer').fetch('accepted')).to be(true)
    expect(contract.fetch('rex_peer').fetch('verify_mode')).to eq(OpenSSL::SSL::VERIFY_PEER)
    expect(contract.fetch('rex_peer').fetch('certificate_sha256')).to eq(contract.fetch('ordinary_trusted').fetch('certificate_sha256'))
    snapshots = 2.times.map do
      before = inactive('exposed')
      output = scan('auxiliary/scanner/sip/options_tcp', 'exposed', { 'TO' => '1000', 'SSL' => true, 'SSLVerifyMode' => 'PEER' }, port: 5061)
      expect(output).to include('SIP/2.0 200 OK')
      expect(services.map { |row| row.slice('address', 'port', 'proto', 'name') }).to eq([{ 'address' => endpoint('exposed').fetch('host'), 'port' => 5061, 'proto' => 'tcp', 'name' => 'sip' }])
      expect(notes.map { |row| row.slice('port', 'proto', 'ntype') }).to eq([{ 'port' => 5061, 'proto' => 'tcp', 'ntype' => 'sip.options.fingerprint' }])
      expect(notes.first.fetch('data').slice('code', 'message')).to eq('code' => '200', 'message' => 'OK')
      expect(credentials).to eq([])
      expect(state_content(inactive('exposed'))).to eq(state_content(before))
      { services: services, notes: notes }
    end
    expect(snapshots.last).to eq(snapshots.first)
  end
end
