require 'spec_helper'
require 'base64'
require 'json'
require 'tmpdir'

RSpec.describe 'SIP capture native Digest records' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:modules_path) { ENV.fetch('SIP_AUTH_MODULE_ROOT', File.expand_path('../../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('sip-capture-auth-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:fixture) { JSON.parse(File.read(File.expand_path('../../../../file_fixtures/modules/auxiliary/sip/capture_auth.json', __dir__))) }
  let(:captures) { fixture.fetch('captures') }
  let(:socket) { double('captured UDP datagram socket', close: nil, sendto: nil) }
  let(:prefix) { File.join(dummy_pathname, 'capture') }
  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/sip') }

  before do
    @credentials = []
    @logins = []
    core = double('credential core')
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential) do |data|
      @credentials << data
      core
    end
    allow(mod).to receive(:create_credential_login) { |data| @logins << data }
    allow(Rex::Socket::Udp).to receive(:create).and_return(socket)
  end

  %w[sipsak-custom sipsak-default sipp-custom sipp-default].each do |name|
    it "saves the native #{name} inputs identically in the UDP credential and John file" do
      capture = captures.find { |row| row.fetch('client') == name }
      replay(capture)

      expect(@credentials.first).to include(private_data: capture.fetch('expected_hash'), private_type: :nonreplayable_hash, jtr_format: 'sip', protocol: 'udp')
      expect(File.binread(prefix + '_sip')).to eq("1001:#{capture.fetch('expected_hash')}\n")
      expect(@logins.first).to include(status: Metasploit::Model::Login::Status::UNTRIED, protocol: 'udp')
    end
  end

  it 'keeps a self-contained native hash without the optional output file' do
    capture = captures.first
    replay(capture, file: false)

    expect(@credentials.first).to include(private_data: capture.fetch('expected_hash'), private_type: :nonreplayable_hash, jtr_format: 'sip')
    expect(File.exist?(prefix + '_sip')).to be(false)
  end

  it 'accepts omitted algorithm as standard MD5 on the captured response' do
    capture = captures.first
    fields = capture.fetch('authorization').except('algorithm')
    replay(capture, fields: fields)

    expect(@credentials.first).to include(private_data: capture.fetch('expected_hash'), jtr_format: 'sip')
  end

  it 'preserves qop auth fields from the pinned John known-password vector' do
    capture = captures.first
    fields = fixture.fetch('upstream_qop').fetch('authorization')
    expected = fixture.fetch('upstream_qop').fetch('hash').split('*')
    expected[1] = capture.fetch('target')
    expected[2] = capture.fetch('source')
    replay(capture, fields: fields)

    expect(@credentials.first).to include(private_data: expected.join('*'), jtr_format: 'sip')
  end

  %w[username realm uri nonce response].each do |missing|
    it "challenges again without inventing a credential when #{missing} is absent" do
      capture = captures.first
      replay(capture, fields: capture.fetch('authorization').reject { |key, _| key == missing })

      expect(@credentials).to eq([])
      expect(File.exist?(prefix + '_sip')).to be(false)
      expect(socket).to have_received(:sendto).once
    end
  end

  {
    'an unsupported algorithm' => { 'algorithm' => 'SHA-256' },
    'unsupported auth-int qop' => { 'qop' => 'auth-int', 'cnonce' => 'captured-control', 'nc' => '00000001' },
    'qop auth without a nonce count' => { 'qop' => 'auth', 'cnonce' => 'captured-control' },
    'a malformed MD5 response' => { 'response' => 'not-an-md5-response' },
    'an unrepresentable field delimiter' => { 'realm' => 'unsupported*realm' }
  }.each do |label, changed|
    it "does not invent a credential for #{label}" do
      capture = captures.first
      replay(capture, fields: capture.fetch('authorization').merge(changed))

      expect(@credentials).to eq([])
      expect(File.exist?(prefix + '_sip')).to be(false)
      expect(socket).to have_received(:sendto).once
    end
  end

  it 'continues the challenge without a credential for a malformed authorization scheme' do
    capture = captures.first
    request = Base64.strict_decode64(capture.fetch('request_base64')).sub(/^Authorization:[^\r\n]*/, 'Authorization: Basic invalid')
    replay(capture, request: request)

    expect(@credentials).to eq([])
    expect(socket).to have_received(:sendto).once
  end

  def replay(capture, file: true, fields: nil, request: nil)
    mod.datastore['SRVHOST'] = capture.fetch('target')
    mod.datastore['JOHNPWFILE'] = prefix if file
    bytes = request || Base64.strict_decode64(capture.fetch('request_base64'))
    if fields
      authorization = fields.map { |key, value| "#{key}=\"#{value}\"" }.join(',')
      bytes = bytes.sub(/^Authorization:[^\r\n]*/, 'Authorization: Digest ' + authorization)
    end
    delivered = false
    allow(socket).to receive(:timed_recvfrom) do
      if delivered
        mod.instance_variable_set(:@run, false)
        nil
      else
        delivered = true
        [bytes.dup, ['AF_INET', capture.fetch('source_port'), capture.fetch('source'), capture.fetch('source')]]
      end
    end
    mod.run
  end
end
