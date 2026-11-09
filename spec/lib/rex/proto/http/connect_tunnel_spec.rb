require 'json'
require 'base64'

RSpec.describe Rex::Proto::Http::Response do
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/proto/http/connect_tunnel/captures.json'))).fetch('captures') }
  let(:response) { described_class.new }
  let(:header) { capture('CONNECT', 443).fetch('response_header') }
  let(:tunnel_bytes) { "module-target-tunnel-data\x00" }

  describe 'CONNECT response framing' do
    [443, 8443].each do |port|
      it "completes the native successful tunnel on #{port} at its headers" do
        expect(response.parse(capture('CONNECT', port).fetch('response_header'), orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
      end
    end

    it 'leaves a successful CONNECT body empty' do
      response.parse(header + tunnel_bytes, orig_method: 'CONNECT')

      expect(response.body).to eq('')
    end

    it 'preserves coalesced tunnel bytes in the input queue' do
      response.parse(header + tunnel_bytes, orig_method: 'CONNECT')

      expect(response.bufq).to eq(tunnel_bytes)
    end

    it 'waits for the complete native header terminator' do
      expect(response.parse(header.delete_suffix("\r\n"), orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Partial)
      expect(response.parse("\r\n", orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
    end

    [201, 204, 299].each do |code|
      it "applies the protocol rule to derived successful status #{code}" do
        derived = header.sub('200 Connection Established', "#{code} Derived Success")

        expect(response.parse(derived, orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
      end
    end

    ["Content-Length: 1234\r\n", "Transfer-Encoding: chunked\r\n", "Content-Length: 1234\r\nTransfer-Encoding: chunked\r\n"].each do |fields|
      it "ignores derived forbidden framing fields #{fields.inspect} only after successful CONNECT" do
        derived = header.sub("\r\n\r\n", "\r\n#{fields}\r\n")
        response.parse(derived + tunnel_bytes, orig_method: 'CONNECT')

        expect([response.body, response.bufq]).to eq(['', tunnel_bytes])
      end
    end

    { 'denied' => 443, 'unrelated' => 443, 'open' => 8444 }.each do |service, port|
      it "retains ordinary body framing for the native #{service} refusal on #{port}" do
        reply = capture('CONNECT', port, service)
        body = remainder(reply)
        expect(response.parse(reply.fetch('response_header'), orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Partial)
        expect(response.parse(body, orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
        expect(response.body).to eq(body)
      end
    end

    it 'retains native GET response body framing' do
      reply = capture('GET', 8080)
      response.parse(reply.fetch('response_header') + remainder(reply), orig_method: 'GET')

      expect(response.body).to eq(remainder(reply))
    end

    it 'retains native HEAD semantics despite a nonzero Content-Length' do
      reply = capture('HEAD', 8080)
      expect(response.parse(reply.fetch('response_header'), orig_method: 'HEAD')).to eq(Rex::Proto::Http::Packet::ParseCode::Completed)
      expect(response.body).to eq('')
    end

    it 'does not infer a tunnel from the same headers without a CONNECT request' do
      expect(response.parse(header)).to eq(Rex::Proto::Http::Packet::ParseCode::Partial)
    end

    it 'clears the tunnel predicate when reset for another response' do
      response.parse(header, orig_method: 'CONNECT')
      response.reset

      expect(response.connect_tunnel?).to be(false)
      expect(response.auto_cl).to be(true)
    end

    it 'does not retain tunnel state when reused for a native GET response' do
      response.parse(header, orig_method: 'CONNECT')
      response.reset
      reply = capture('GET', 8080)
      response.parse(reply.fetch('response_header') + remainder(reply), orig_method: 'GET')

      expect(response.connect_tunnel?).to be(false)
    end

    it 'does not retain tunnel state after a derived malformed status line' do
      response.parse(header, orig_method: 'CONNECT')
      response.reset
      malformed = header.sub('HTTP/1.0 200 Connection Established', 'NOT-HTTP')

      expect(response.parse(malformed, orig_method: 'CONNECT')).to eq(Rex::Proto::Http::Packet::ParseCode::Error)
      expect(response.connect_tunnel?).to be(false)
    end
  end

  describe Rex::Proto::Http::Client do
    let(:client) { described_class.new('192.0.2.53') }
    let(:connection) { double('native-capture connection', put: nil, peerinfo: '192.0.2.53:80', closed?: false) }
    let(:response) { Rex::Proto::Http::Response.new }

    before do
      allow(Rex::Socket::Tcp).to receive(:create).and_return(connection)
    end

    it 'returns after the native CONNECT headers without waiting for a tunnel body' do
      expect(connection).to receive(:get_once).once.and_return(header)
      request = client.request_cgi('method' => 'CONNECT', 'uri' => 'destination:443')

      expect(client.send_recv(request, 1).code).to eq(200)
    end

    it 'keeps coalesced tunnel bytes out of the returned HTTP body' do
      expect(connection).to receive(:get_once).once.and_return(header + tunnel_bytes)
      request = client.request_cgi('method' => 'CONNECT', 'uri' => 'destination:443')
      result = client.send_recv(request, 1)

      expect([result.body, result.bufq]).to eq(['', tunnel_bytes])
    end

    it 'bypasses the HTML completion heuristic for derived tunnel metadata' do
      derived = header.sub("\r\n\r\n", "\r\nContent-Type: text/html\r\n\r\n")
      expect(connection).to receive(:get_once).once.and_return(derived + tunnel_bytes)
      request = client.request_cgi('method' => 'CONNECT', 'uri' => 'destination:443')
      result = client.send_recv(request, 1)

      expect([result.body, result.bufq]).to eq(['', tunnel_bytes])
    end

    it 'retains the complete native denied CONNECT response body' do
      reply = capture('CONNECT', 443, 'denied')
      expect(connection).to receive(:get_once).once.and_return(reply.fetch('response_header') + remainder(reply))
      request = client.request_cgi('method' => 'CONNECT', 'uri' => 'destination:443')

      expect(client.send_recv(request, 1).body).to eq(remainder(reply))
    end
  end

  def capture(method, port, service = 'open')
    captures.find { |entry| entry.fetch('method') == method && entry.fetch('port') == port && entry.fetch('service') == service }
  end

  def remainder(reply)
    Base64.strict_decode64(reply.fetch('response_remainder_base64'))
  end
end
