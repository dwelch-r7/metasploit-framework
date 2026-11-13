require 'rspec'
require 'msfenv'
require 'msf/base'
require 'digest'

RSpec.describe 'Heartbleed heartbeat payload framing' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/ssl/openssl_heartbleed.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:payload) { 'A'.b * 8192 }
  let(:chunks) { [record(heartbeat(payload))] }
  let(:socket_class) do
    Class.new do
      attr_reader :chunks, :sent

      def initialize(chunks)
        @chunks = chunks.dup
        @sent = []
      end

      def get_once(length = -1, _timeout = 3)
        chunk = @chunks.shift
        raise chunk if chunk.is_a?(Exception)
        return chunk unless chunk && length.positive? && chunk.bytesize > length

        @chunks.unshift(chunk.byteslice(length..))
        chunk.byteslice(0, length)
      end

      def put(data)
        @sent << data
        data.bytesize
      end

      def shutdown; end
      def close; end
    end
  end
  let(:socket) { socket_class.new(chunks) }

  before do
    mod.datastore['RHOST'] = '192.0.2.19'
    mod.datastore['HEARTBEAT_LENGTH'] = payload.bytesize
    mod.datastore['RESPONSE_TIMEOUT'] = 3
    allow(mod).to receive(:establish_connect) do
      mod.send(:sock=, socket)
      mod.add_socket(socket)
      true
    end
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
  end

  # Framing follows the parent's genuine OpenSSL 1.0.1f capture: TLS header
  # 1803012013, heartbeat header 022000, declared payload 8192. Memory content
  # is deliberately replaced with deterministic synthetic bytes. Native wire
  # hashes remain private campaign evidence. TCP delivery and faults are doubles;
  # bleed, get_data, heartbeat_request and TCP disconnect are real owner methods.

  def record(body, type: 0x18, version: 0x0301, length: body.bytesize)
    [type, version, length].pack('Cnn') + body
  end

  def heartbeat(data, declared: data.bytesize, type: 2, padding: 'P'.b * 16)
    [type, declared].pack('Cn') + data + padding
  end

  def expect_payload(actual, expected)
    expect([actual&.bytesize, Digest::SHA256.hexdigest(actual.to_s)]).to eq([expected.bytesize, Digest::SHA256.hexdigest(expected)])
  end

  it 'extracts all 8192 payload bytes without heartbeat header or padding' do
    expect_payload(mod.bleed, payload)
  end

  it 'uses the response payload length instead of retaining padding' do
    socket.chunks.replace([record(heartbeat('DATA!'.b))])

    expect_payload(mod.bleed, 'DATA!'.b)
  end

  it 'handles TCP fragments inside TLS and heartbeat headers' do
    wire = chunks.first
    socket.chunks.replace([wire.byteslice(0, 1), wire.byteslice(1, 5), wire.byteslice(6, 1), wire.byteslice(7..)])

    expect_payload(mod.bleed, payload)
  end

  it 'excludes TLS headers between heartbeat fragments' do
    body = heartbeat(payload)
    socket.chunks.replace([record(body.byteslice(0, 103)), record(body.byteslice(103..))])

    expect_payload(mod.bleed, payload)
  end

  it 'handles a heartbeat header spanning TLS records' do
    body = heartbeat(payload)
    socket.chunks.replace([record(body.byteslice(0, 1)), record(body.byteslice(1, 2)), record(body.byteslice(3..))])

    expect_payload(mod.bleed, payload)
  end

  context 'with the default 65535-byte request' do
    let(:payload) { 'X'.b * 65_535 }
    let(:fragments) do
      body = heartbeat(payload)
      [record(body.byteslice(0, 16_384)), record(body.byteslice(16_384, 16_384)), record(body.byteslice(32_768, 16_384)), record(body.byteslice(49_152, 16_384)), record(body.byteslice(65_536..))]
    end

    it 'extracts the complete payload across all five records' do
      socket.chunks.replace(fragments)

      expect_payload(mod.bleed, payload)
    end

    it 'retains 65533 payload bytes when s_server buffers its last fragment' do
      socket.chunks.replace(fragments.first(4) + [nil])

      expect_payload(mod.bleed, payload.byteslice(0, 65_533))
    end

    it 'identifies genuine partial evidence without counting TLS headers' do
      socket.chunks.replace(fragments.first(4) + [nil])
      mod.bleed

      expect(mod).to have_received(:vprint_status).with('Partial heartbeat payload: 65533 of 65535 bytes')
    end
  end

  [nil, EOFError.new('Peer closed')].each do |ending|
    it "retains partial payload after #{ending.inspect}" do
      socket.chunks.replace([record(heartbeat('partial'.b, declared: 20, padding: ''.b), length: 39), ending])

      expect_payload(mod.bleed, 'partial'.b)
    end
  end

  it 'excludes an incomplete next TLS header from partial evidence' do
    socket.chunks.replace([record(heartbeat('partial'.b, declared: 20, padding: ''.b)), "\x18\x03".b, nil])

    expect_payload(mod.bleed, 'partial'.b)
  end

  it 'retains partial evidence before a TLS alert' do
    socket.chunks.replace([record(heartbeat('partial'.b, declared: 20, padding: ''.b)), record("\x02\x46".b, type: 0x15)])

    expect_payload(mod.bleed, 'partial'.b)
  end

  it 'retains partial evidence before an unexpected record version' do
    socket.chunks.replace([record(heartbeat('partial'.b, declared: 20, padding: ''.b)), record('other'.b, version: 0x0303)])

    expect_payload(mod.bleed, 'partial'.b)
  end

  it 'preserves binary payload that resembles protocol headers' do
    data = "\xff\x00\x18\x03\x01\x00\x05HELLO\x02\x20\x00".b
    socket.chunks.replace([record(heartbeat(data))])

    expect_payload(mod.bleed, data)
  end

  [
    nil,
    "\x18\x03\x01".b,
    [0x18, 0x0301, 0].pack('Cnn'),
    [0x18, 0x0301, 3].pack('Cnn') + [2, 8].pack('Cn'),
    [0x18, 0x0301, 19].pack('Cnn') + [2, 0].pack('Cn') + ('P' * 16),
    [0x18, 0x0301, 26].pack('Cnn') + [1, 7].pack('Cn') + 'request' + ('P' * 16),
    [0x15, 0x0301, 2].pack('Cnn') + "\x02\x46".b,
    '220 SMTP greeting'.b
  ].each do |wire|
    it "does not treat incomplete or unrelated framing as payload: #{wire.inspect}" do
      socket.chunks.replace([wire, nil])

      expect(mod.bleed.nil?).to be(true)
    end
  end

  it 'does not classify heartbeat headers alone as a vulnerable check' do
    socket.chunks.replace([record("\x02\x00\x08".b), nil])

    expect(mod.check_host('192.0.2.19')).to eq(Msf::Exploit::CheckCode::Safe)
  end

  it 'closes and unregisters its socket after payload extraction' do
    mod.bleed

    expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
  end
end
