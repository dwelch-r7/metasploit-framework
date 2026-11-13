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

  context 'with the KEYS action' do
    let(:payload) { "\xfb".b }
    let(:rsa_key) do
      # Tiny deterministic RSA public constants keep reporting tests quick.
      # Factors 251/241 produce n=60491; this is not a production key.
      der = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(60_491), OpenSSL::ASN1::Integer.new(17)]).to_der
      OpenSSL::PKey::RSA.new(der)
    end
    let(:reports) { [] }
    let(:loot) { [] }

    before do
      mod.datastore['ACTION'] = 'KEYS'
      mod.datastore['RPORT'] = 11_100
      mod.datastore['MAX_KEYTRIES'] = 1
      mod.instance_variable_set(:@cert, instance_double(OpenSSL::X509::Certificate, public_key: rsa_key))
      allow(mod).to receive(:print_status)
      allow(mod).to receive(:print_good)
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:vprint_good)
      allow(mod).to receive(:report_vuln) { |record| reports << record }
      allow(mod).to receive(:store_loot) do |*args|
        loot << args
        '/tmp/unit-heartbleed-key'
      end
      allow(mod).to receive(:key_from_pqe).and_return(double(export: 'UNIT TEST KEY EXPORT'))
    end

    # Certificate constants and transport are explicit synthetic boundaries.
    # Actual bleed/get_data and factor search execute. Final key assembly/export
    # is a double: parent native cases independently verify real RSA 2048 recovery
    # and a challenge signature against the actual server certificate.

    it 'reports real nonempty exposure when a factor is recovered' do
      mod.get_keys

      expect(reports).to contain_exactly(include(host: '192.0.2.19', port: 11_100, name: mod.name, refs: mod.references, info: "Module #{mod.fullname} successfully leaked info"))
      expect(loot.map { |args| args[3] }).to eq(['UNIT TEST KEY EXPORT'])
    end

    it 'reports nonempty exposure when no key factor is found' do
      socket.chunks.replace([record(heartbeat("\x01".b))])
      mod.get_keys

      expect([reports.length, loot]).to eq([1, []])
    end

    it 'reports once while repeated key attempts find no factor' do
      mod.datastore['MAX_KEYTRIES'] = 2
      socket.chunks.replace([record(heartbeat("\x01".b)), record(heartbeat("\x01".b))])
      mod.get_keys

      expect(reports.length).to eq(1)
    end

    [nil, [0x18, 0x0301, 3].pack('Cnn') + [2, 8].pack('Cn')].each do |wire|
      it "does not report or store keys without payload proof: #{wire.inspect}" do
        socket.chunks.replace([wire, nil])
        mod.get_keys

        expect([reports, loot]).to eq([[], []])
      end
    end

    it 'declines EC certificates without a heartbeat probe or runtime exception' do
      mod.instance_variable_set(:@cert, instance_double(OpenSSL::X509::Certificate, public_key: OpenSSL::PKey::EC.new('prime256v1')))

      expect { mod.get_keys }.not_to raise_error
      expect([socket.sent, reports, loot]).to eq([[], [], []])
      expect(mod).to have_received(:print_error).with(/RSA/)
    end

    it 'stops cleanly when no certificate is available' do
      mod.instance_variable_set(:@cert, nil)

      expect { mod.get_keys }.not_to raise_error
      expect([socket.sent, reports, loot]).to eq([[], [], []])
    end

    it 'stops cleanly when the certificate has no public key' do
      mod.instance_variable_set(:@cert, instance_double(OpenSSL::X509::Certificate, public_key: nil))

      expect { mod.get_keys }.not_to raise_error
      expect([socket.sent, reports, loot]).to eq([[], [], []])
    end

    it 'stops cleanly when RSA public constants are missing' do
      allow(rsa_key).to receive(:params).and_return({})

      expect { mod.get_keys }.not_to raise_error
      expect([socket.sent, reports, loot]).to eq([[], [], []])
    end

    [0, -1].each do |frequency|
      it "rejects STATUS_EVERY=#{frequency} before probing memory" do
        mod.datastore['STATUS_EVERY'] = frequency

        expect { mod.get_keys }.not_to raise_error
        expect([socket.sent, reports, loot]).to eq([[], [], []])
        expect(mod).to have_received(:print_error).with(/STATUS_EVERY/)
      end
    end

    it 'preserves the registered default status frequency' do
      expect(mod.datastore['STATUS_EVERY']).to eq(5)
    end

    %w[SCAN DUMP].each do |action|
      it "preserves #{action} with an unused zero STATUS_EVERY value" do
        mod.datastore['ACTION'] = action
        mod.datastore['STATUS_EVERY'] = 0
        mod.run_host('192.0.2.19')

        expect(reports.length).to eq(1)
      end
    end

    it 'preserves DUMP exposure reporting on an EC certificate' do
      mod.datastore['ACTION'] = 'DUMP'
      mod.instance_variable_set(:@cert, instance_double(OpenSSL::X509::Certificate, public_key: OpenSSL::PKey::EC.new('prime256v1')))
      mod.run_host('192.0.2.19')

      expect([reports.length, loot.map { |args| args[3] }]).to eq([1, [payload]])
    end

    it 'preserves unexpected persistence errors after genuine payload proof' do
      allow(mod).to receive(:report_vuln).and_raise(IOError, 'Unexpected reporting error')

      expect { mod.get_keys }.to raise_error(IOError, 'Unexpected reporting error')
    end
  end
end
