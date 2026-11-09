require 'rspec'

RSpec.describe 'MQTT authentication response handling' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/mqtt/connect') }

  let(:client) { instance_double(Rex::Proto::MQTT::Client, connect: reply, disconnect: nil) }
  let(:reply) { ::MQTT::Packet::Connack.new(return_code: 0) }

  before do
    allow(mod).to receive(:connect)
    allow(mod).to receive(:disconnect)
    allow(mod).to receive(:sock).and_return(double('MQTT socket'))
    allow(Rex::Proto::MQTT::Client).to receive(:new).and_return(client)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:print_good).and_return(nil)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:brute)
  end

  it 'reports an accepted anonymous connection without starting a credential sweep' do
    mod.run_host('192.0.2.1')

    expect(mod).not_to have_received(:brute)
  end

  it 'closes the anonymous probe socket after a successful response' do
    expect(mod.test_login('', '')).to be(true)
    expect(mod).to have_received(:disconnect)
  end

  it 'closes the anonymous probe socket after an expected connection failure' do
    allow(client).to receive(:connect).and_raise(Rex::ConnectionError, 'No MQTT CONNECT response')

    expect { mod.test_login('', '') }.to raise_error(Rex::ConnectionError)
    expect(mod).to have_received(:disconnect)
  end

  it 'reports an expected probe error without continuing the credential sweep' do
    error = Rex::ConnectionError.new(reason: 'No MQTT CONNECT response')
    allow(client).to receive(:connect).and_raise(error)

    mod.run_host('192.0.2.1')

    expect(mod).to have_received(:elog).with('MQTT connection failed', error: error)
    expect(mod).not_to have_received(:brute)
  end

  context 'when authentication is required' do
    let(:reply) { ::MQTT::Packet::Connack.new(return_code: 5) }

    it 'starts the configured credential sweep' do
      mod.run_host('192.0.2.1')

      expect(mod).to have_received(:brute)
    end

    it 'does not send another MQTT packet after a refused CONNECT' do
      expect(mod.test_login('', '')).to be(false)
      expect(client).not_to have_received(:disconnect)
    end
  end
end
