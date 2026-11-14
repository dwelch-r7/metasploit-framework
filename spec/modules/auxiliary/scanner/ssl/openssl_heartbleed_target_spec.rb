require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/heartbleed/acceptance'

RSpec.describe 'Genuine OpenSSL Heartbleed', acceptance: true, order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::Heartbleed

  before(:all) do
    @native = hb_native('before')
    @idle = hb_state
    hb_idle
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = 'hb_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(hb_reports).to eq([])
    expect(hb_loot).to eq([])
  end

  after do
    hb_idle if @idle
  end

  after(:all) do
    if @native
      later = hb_native('after')
      expect(later.fetch('certificates')).to eq(@native.fetch('certificates'))
      expect(later.fetch('controls').fetch('native_probe.py').fetch('binary_manifest')).to eq(@native.fetch('controls').fetch('native_probe.py').fetch('binary_manifest'))
      expect(later.fetch('controls').fetch('conditioned_probe.py').fetch('conditioned-binaries.sha256')).to eq(@native.fetch('controls').fetch('conditioned_probe.py').fetch('conditioned-binaries.sha256'))
      hb_idle
      hb_resources
    end
  end

  it 'checks a genuine affected server twice and persists its vulnerability' do
    2.times do
      output, streams = hb_call({}, action: 'check')
      expect(output).to include('Target returned extra data in heartbeat response')
      expect(hb_payloads(streams, complete: false).map(&:bytesize)).to contain_exactly(be >= 16381)
      expect(hb_loot).to eq([])
      expect(hb_reports).to contain_exactly(include('port' => 10000, 'proto' => 'tcp', 'service_id' => be_a(Integer)))
    end
  end

  it('dumps the exact leaked payload without TLS or heartbeat framing twice') { hb_verify_leak({ 'HEARTBEAT_LENGTH' => 8192 }, dump: true) }
  it('scans twice with two independent leaks per invocation') { hb_verify_leak({ 'HEARTBEAT_LENGTH' => 8192, 'LEAK_COUNT' => 2 }, dump: false) }

  [10200, 10300].each do |port|
    it "rejects the fixed or heartbeat-disabled SDK on #{port} twice" do
      2.times do
        output, streams = hb_call({ 'RPORT' => port }, action: 'check')
        expect(output).to include('Target did not return extra data in heartbeat response')
        expect(hb_payloads(streams)).to eq([])
        expect(hb_loot).to eq([])
        expect(hb_reports).to eq([])
      end
    end
  end

  it 'handles a refused connection twice without loot or reports' do
    2.times do
      output, streams = hb_call({ 'RPORT' => 1 })
      expect(output).not_to include('Heartbeat response with leak,')
      expect(streams).to eq([])
      expect(hb_loot).to eq([])
      expect(hb_reports).to eq([])
    end
  end

  ['SSLv3', '1.0', '1.1', '1.2'].each do |version|
    it("dumps the exact real 1.0.1f payload twice with #{version}") { hb_verify_leak({ 'RPORT' => 10100, 'TLS_VERSION' => version, 'HEARTBEAT_LENGTH' => 8192 }, dump: true) }
  end

  it('preserves the genuine partial default-length upstream response twice') { hb_verify_leak({}, dump: true, complete: false, expected_length: 65533) }
  it('dumps all 65535 payload bytes across five records twice') { hb_verify_leak({ 'RPORT' => 11100 }, dump: true) }
  it('joins two independent dump payloads in wire order twice') { hb_verify_leak({ 'RPORT' => 11100, 'HEARTBEAT_LENGTH' => 32768, 'LEAK_COUNT' => 2 }, dump: true) }
  it('stores only the requested matching bytes twice') { hb_verify_leak({ 'RPORT' => 11100, 'HEARTBEAT_LENGTH' => 32768, 'DUMPFILTER' => 'HEARTBLEED_LAB_FACTOR' }, dump: true, expected_loot: 'HEARTBLEED_LAB_FACTOR') }
  it('stores an empty filtered artifact for a real leak with no match twice') { hb_verify_leak({ 'RPORT' => 11100, 'HEARTBEAT_LENGTH' => 32768, 'DUMPFILTER' => 'ABSENT-LAB-PATTERN' }, dump: true, expected_loot: '') }
  it('recovers a disposable RSA key and verifies a signature twice') { hb_keys(found: true) }
  it('stops at one key attempt when a one-byte leak cannot contain an RSA factor twice') { hb_keys(found: false) }

  it 'does not recover keys from the fixed SDK twice' do
    2.times do
      output, streams = hb_call({ 'ACTION' => 'KEYS', 'RPORT' => 11200, 'MAX_KEYTRIES' => 1 })
      expect(output).not_to include('Got the private key')
      expect(hb_payloads(streams)).to eq([])
      expect(hb_loot).to eq([])
      expect(hb_reports).to eq([])
    end
  end

  it 'declines unsupported ECDSA key recovery gracefully twice' do
    2.times do
      output, = hb_call({ 'ACTION' => 'KEYS', 'RPORT' => 12000, 'TLS_VERSION' => '1.2', 'MAX_KEYTRIES' => 1, 'HEARTBEAT_LENGTH' => 8192 })
      expect(output).to match(/(?:RSA|public key)/i)
      expect(output).not_to include('Got the private key')
      expect(hb_loot).to eq([])
      expect(hb_reports).to eq([])
    end
  end

  it 'rejects zero key status interval gracefully twice' do
    2.times do
      output, streams = hb_call({ 'ACTION' => 'KEYS', 'RPORT' => 11100, 'MAX_KEYTRIES' => 1, 'STATUS_EVERY' => 0 })
      expect(output).to include('STATUS_EVERY')
      expect(hb_payloads(streams)).to eq([])
      expect(hb_loot).to eq([])
      expect(hb_reports).to eq([])
    end
  end

  [
    [{ 'HEARTBEAT_LENGTH' => -1 }, 'HEARTBEAT_LENGTH'],
    [{ 'HEARTBEAT_LENGTH' => 65536 }, 'HEARTBEAT_LENGTH'],
    [{ 'RESPONSE_TIMEOUT' => -1 }, 'RESPONSE_TIMEOUT']
  ].each do |options, reason|
    it "rejects #{options.inspect} before opening a connection twice" do
      2.times do
        output, streams = hb_call(options)
        expect(output).to include(reason)
        expect(streams).to eq([])
        expect(hb_loot).to eq([])
        expect(hb_reports).to eq([])
      end
    end
  end

  it 'performs no leak when LEAK_COUNT is zero twice' do
    2.times do
      output, streams = hb_call({ 'LEAK_COUNT' => 0 })
      expect(output).not_to include('Heartbeat response with leak,')
      expect(streams).to eq([])
      expect(hb_reports).to eq([])
      expect(hb_loot).to eq([])
    end
  end

  it 'does not mistake a zero-byte payload for leaked memory twice' do
    2.times do
      output, streams = hb_call({ 'RPORT' => 11100, 'HEARTBEAT_LENGTH' => 0 })
      expect(output).not_to include('Heartbeat response with leak,')
      expect(hb_payloads(streams)).to eq([''.b])
      expect(hb_reports).to eq([])
      expect(hb_loot).to eq([])
    end
  end

  it('dumps a real leak through an ECDSA certificate twice') { hb_verify_leak({ 'RPORT' => 12000, 'TLS_VERSION' => '1.2', 'HEARTBEAT_LENGTH' => 8192 }, dump: true) }

  ['SMTP', 'IMAP', 'JABBER', 'POP3', 'FTP', 'POSTGRES'].each_with_index do |protocol, offset|
    it("dumps a real leak through #{protocol} STARTTLS twice") { hb_verify_leak({ 'RPORT' => 10400 + offset * 100, 'TLS_CALLBACK' => protocol, 'TLS_VERSION' => '1.2', 'HEARTBEAT_LENGTH' => 8192, 'RESPONSE_TIMEOUT' => 2 }, dump: true) }

    it "does not report or save fixed #{protocol} STARTTLS memory twice" do
      2.times do
        output, streams = hb_call({ 'RPORT' => 11400 + offset * 100, 'TLS_CALLBACK' => protocol, 'TLS_VERSION' => '1.2', 'HEARTBEAT_LENGTH' => 8192, 'RESPONSE_TIMEOUT' => 2, 'ACTION' => 'DUMP' })
        hb_verify_upgrade(streams, protocol)
        expect(output).not_to include('Heartbeat response with leak,')
        expect(hb_payloads(streams)).to eq([])
        expect(hb_loot).to eq([])
        expect(hb_reports).to eq([])
      end
    end
  end

  it 'handles an unrelated genuine HTTP server twice' do
    2.times do
      output, streams = hb_call({ 'RPORT' => 2525 })
      expect(output).not_to include('Heartbeat response with leak,')
      expect(streams.select { |row| row.fetch(:direction) == 'response' }.map { |row| row.fetch(:bytes) }.join).to include('<title>Error response</title>', '<p>Error code: 400</p>')
      expect(hb_reports).to eq([])
      expect(hb_loot).to eq([])
    end
  end

  it 'keeps real vulnerability reports distinct for two services on one host' do
    [10000, 10100].each do |port|
      2.times do
        output, streams = hb_call({ 'RPORT' => port, 'HEARTBEAT_LENGTH' => 8192 })
        expect(output).to include('Heartbeat response with leak,')
        expect(hb_payloads(streams).map(&:bytesize)).to eq([8192])
      end
    end
    rows = hb_reports
    expect(rows.map { |row| row.fetch('port') }).to match_array([10000, 10100])
    expect(rows.map { |row| row.fetch('service_id') }.uniq.length).to eq(2)
    expect(hb_loot).to eq([])
  end
end
