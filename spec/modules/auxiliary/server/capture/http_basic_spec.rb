require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'HTTP Basic capture scheme' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/http_basic') }

  let(:client) { double('native HTTP client', peerhost: '192.0.2.42', send_response: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/http_basic.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@realm, 'Module target capture realm')
    allow(mod).to receive_messages(report_cred: nil, send_not_found: nil)
  end

  it 'challenges the actual legal Bearer token without decoding it as Basic credentials' do
    mod.on_request_uri(client, request('capture_1_11_0'))

    expect(client).to have_received(:send_response).with(have_attributes(code: 401))
    expect(mod).not_to have_received(:report_cred)
  end

  it 'preserves the actual Basic password including colon and surrounding spaces' do
    mod.on_request_uri(client, request('capture_1_6_0'))

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_user', password: ' module-target: capture "quoted" \\ tail '))
  end

  it 'accepts a derived case-insensitive Basic scheme' do
    req = request('capture_1_6_0')
    req.headers['Authorization'].sub!('Basic', 'bAsIc')
    mod.on_request_uri(client, req)

    expect(mod).to have_received(:report_cred)
  end

  it 'does not report an absent Authorization header' do
    mod.on_request_uri(client, Rex::Proto::Http::Request.new('GET', '/capture'))

    expect(mod).not_to have_received(:report_cred)
  end

  it 'does not report a derived truncated Basic header without a token' do
    req = Rex::Proto::Http::Request.new('GET', '/capture')
    req.headers['Authorization'] = 'Basic'
    mod.on_request_uri(client, req)

    expect(mod).not_to have_received(:report_cred)
  end

  def request(name)
    bytes = Base64.decode64(captures.find { |row| row.fetch('case') == name }.fetch('client_stream_base64'))
    Rex::Proto::Http::Request.new.tap { |req| req.parse(bytes) }
  end
end
