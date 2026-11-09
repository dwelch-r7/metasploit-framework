require 'spec_helper'
require 'metasploit/framework/login_scanner/mqtt'
require 'base64'
require 'json'

RSpec.describe Metasploit::Framework::LoginScanner::MQTT do
  subject(:scanner) { described_class.new(host: '192.0.2.1', client_id: 'module-target', read_timeout: 2) }

  let(:credential) { Metasploit::Framework::Credential.new(public: 'lab-mqtt-user', private: 'lab-mqtt-password') }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/proto/mqtt/connect_responses.json'))).fetch('captures') }
  let(:response) { Base64.strict_decode64(captures.find { |capture| capture.fetch('name') == 'accepted' }.fetch('response_base64')) }
  let(:socket) { double('MQTT socket', put: nil, get_once: response, shutdown: nil, close: nil) }

  before do
    allow(scanner).to receive(:connect) { scanner.sock = socket }
  end

  it 'retains successful credential classification and closes its socket' do
    result = scanner.attempt_login(credential)

    expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    expect(socket).to have_received(:close)
  end

  it 'retains refused credential classification without sending another protocol packet' do
    refused = Base64.strict_decode64(captures.find { |capture| capture.fetch('name') == 'refused' }.fetch('response_base64'))
    allow(socket).to receive(:get_once).and_return(refused)
    result = scanner.attempt_login(credential)

    expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
    expect(socket).not_to have_received(:put).with("\xe0\x00".b)
  end

  it 'classifies a missing broker response as unavailable and closes its socket' do
    allow(socket).to receive(:get_once).and_return(nil)
    result = scanner.attempt_login(credential)

    expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    expect(socket).to have_received(:close)
  end

  it 'classifies an unexpected packet as unavailable rather than an authentication result' do
    allow(socket).to receive(:get_once).and_return("\xd0\x00".b)
    result = scanner.attempt_login(credential)

    expect(result.status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    expect(socket).to have_received(:close)
  end
end
