require 'spec_helper'
require 'rex/proto/mqtt/client'
require 'base64'
require 'json'

RSpec.describe Rex::Proto::MQTT::Client do
  subject(:client) { described_class.new(socket, client_id: 'module-target', read_timeout: 2) }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/proto/mqtt/connect_responses.json'))).fetch('captures') }
  let(:response) { Base64.strict_decode64(captures.find { |capture| capture.fetch('name') == 'accepted' }.fetch('response_base64')) }
  let(:socket) { double('MQTT socket', put: nil, get_once: response) }

  it 'returns a successful CONNACK packet with its existing result shape' do
    reply = client.connect

    expect([reply.class, reply.return_code]).to eq([::MQTT::Packet::Connack, 0])
  end

  it 'preserves refused CONNACK results for credential classification' do
    allow(socket).to receive(:get_once).and_return(Base64.strict_decode64(captures.find { |capture| capture.fetch('name') == 'refused' }.fetch('response_base64')))

    expect(client.connect.return_code).to eq(5)
  end

  it 'converts a timed-out read into an expected connection error' do
    allow(socket).to receive(:get_once).and_return(nil)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end

  it 'converts an empty read into an expected connection error' do
    allow(socket).to receive(:get_once).and_return('')

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end

  it 'handles a truncated CONNACK without leaking a parser exception' do
    allow(socket).to receive(:get_once).and_return("\x20\x02\x00".b)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end

  it 'does not return an unrelated MQTT packet as the CONNECT response' do
    allow(socket).to receive(:get_once).and_return("\xd0\x00".b)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /CONNACK/)
  end

  it 'rejects a zero-length CONNACK body without leaking a parser exception' do
    allow(socket).to receive(:get_once).and_return("\x20\x00".b)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end

  it 'rejects a one-byte CONNACK body without leaking a parser exception' do
    allow(socket).to receive(:get_once).and_return("\x20\x01\x00".b)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end

  it 'rejects an unrelated HTTP response without leaking a parser exception' do
    allow(socket).to receive(:get_once).and_return("HTTP/1.1 400 Bad Request\r\n\r\n".b)

    expect { client.connect }.to raise_error(Rex::ConnectionError, /MQTT CONNECT/)
  end
end
