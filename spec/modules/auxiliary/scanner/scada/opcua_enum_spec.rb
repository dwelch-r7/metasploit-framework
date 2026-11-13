require 'rspec'
require 'msfenv'
require 'msf/base'
require 'base64'
require 'json'
require 'digest'
require 'rex/stopwatch'

RSpec.describe 'OPC-UA complete handshake framing' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/scada/opcua_enum.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/modules/auxiliary/scanner/scada/opcua_enum/handshakes.json', __dir__)
    JSON.parse(File.read(path)).fetch('frames')
  end
  let(:ack) { Base64.strict_decode64(captures.fetch('ack_65535').fetch('response_base64')) }
  let(:error_frame) { Base64.strict_decode64(captures.fetch('err_null_reason').fetch('response_base64')) }
  let(:chunks) { [ack] }
  let(:reports) { [] }
  let(:socket_class) do
    Class.new do
      attr_reader :reads, :sent, :chunks

      def initialize(chunks)
        @chunks = chunks.dup
        @reads = []
        @sent = []
      end

      def get_once(length = -1, timeout = 5)
        @reads << [length, timeout]
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
    mod.datastore['RHOST'] = '192.0.2.17'
    allow(mod).to receive(:connect) do
      mod.send(:sock=, socket)
      mod.add_socket(socket)
    end
    allow(mod).to receive(:report_service) { |record| reports << record }
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:elog)
  end

  # Positive frames are exact independently captured open62541 responses.
  # Socket delivery segmentation, faults, malformed fields and clock durations
  # below are explicit synthetic boundaries; owner parsing/reporting/HEL and
  # the real TCP disconnect helper are not replaced.

  it 'retains the registered default OPC-UA port without setting it in the fixture' do
    expect(mod.datastore['RPORT']).to eq(4840)
  end

  it 'retains an operator-selected port in HEL, reporting and the datastore' do
    mod.datastore['RPORT'] = 18_440
    mod.run_host('192.0.2.17')

    expect([socket.sent.first.end_with?('opc.tcp://192.0.2.17:18440'), reports.first.fetch(:port), mod.datastore['RPORT']]).to eq([true, 18_440, 18_440])
  end

  it 'preserves the HEL byte layout and both advertised buffer sizes' do
    hello = mod.build_hello('opc.tcp://192.0.2.17:4840')

    expect([hello.byteslice(0, 4), hello.byteslice(4, 4).unpack1('V'), hello.byteslice(8, 20).unpack('V5')]).to eq(['HELF', hello.bytesize, [0, 65_535, 65_535, 0, 0]])
  end

  [
    ['ack_65535', 'OPC-UA server (ACK): ProtocolVersion=0 RecvBuf=65535 SendBuf=65535'],
    ['ack_16384', 'OPC-UA server (ACK): ProtocolVersion=0 RecvBuf=16384 SendBuf=16384'],
    ['err_null_reason', 'OPC-UA server (ERR): 0x80020000']
  ].each do |label, info|
    context "with the captured #{label} frame" do
      let(:frame) { Base64.strict_decode64(captures.fetch(label).fetch('response_base64')) }
      let(:chunks) { [frame] }

      it 'retains exact native frame provenance' do
        expect(Digest::SHA256.hexdigest(frame)).to eq(captures.fetch(label).fetch('response_sha256'))
      end

      it 'reports the original valid service fields' do
        mod.run_host('192.0.2.17')

        expect(reports).to eq([{ host: '192.0.2.17', port: 4840, proto: 'tcp', name: 'opc-ua', info: info }])
      end

      it 'reads the same message when TCP first delivers only one byte' do
        socket.chunks.replace([frame.byteslice(0, 1), frame.byteslice(1, 3), frame.byteslice(4, 5), frame.byteslice(9..)])
        mod.run_host('192.0.2.17')

        expect(reports.map { |record| record.fetch(:info) }).to eq([info])
      end
    end
  end

  it 'ignores the reserved header byte rather than inventing a receiver constraint' do
    ack.setbyte(3, 'Z'.ord)
    mod.run_host('192.0.2.17')

    expect(reports.length).to eq(1)
  end

  it 'consumes only the declared first message when TCP coalesces another frame' do
    socket.chunks.replace([ack + error_frame])
    mod.run_host('192.0.2.17')

    expect([reports.length, socket.chunks.join]).to eq([1, error_frame])
  end

  it 'does not persist a service for a header-only ACK declaring a longer frame' do
    socket.chunks.replace([ack.byteslice(0, 8), nil])
    mod.run_host('192.0.2.17')

    expect(reports).to eq([])
  end

  it 'does not persist a service when the ACK body is cut off' do
    socket.chunks.replace([ack.byteslice(0, 23), EOFError.new('Peer closed')])
    mod.run_host('192.0.2.17')

    expect(reports).to eq([])
  end

  [
    ['an undersized declared header', 'ACKF' + [7].pack('V')],
    ['a size above the advertised receive buffer', 'ACKF' + [65_536].pack('V')],
    ['an incomplete five-field ACK body', 'ACKF' + [20].pack('V') + [0, 65_535, 65_535].pack('V3')],
    ['an unsupported ACK protocol version', 'ACKF' + [28].pack('V') + [1, 65_535, 65_535, 0, 0].pack('V5')],
    ['an ACK receive buffer below its negotiated minimum', 'ACKF' + [28].pack('V') + [0, 8191, 65_535, 0, 0].pack('V5')],
    ['an ACK send buffer above its negotiated maximum', 'ACKF' + [28].pack('V') + [0, 65_535, 65_536, 0, 0].pack('V5')],
    ['an ERR without a UAString field', 'ERRF' + [12].pack('V') + [0x80830000].pack('V')],
    ['an ERR UAString length below null', 'ERRF' + [16].pack('V') + [0x80830000].pack('V') + [-2].pack('l<')],
    ['an ERR UAString that exceeds its complete frame', 'ERRF' + [17].pack('V') + [0x80830000, 3].pack('V2') + 'x']
  ].each do |label, bytes|
    context "with #{label}" do
      let(:chunks) { [bytes] }

      it 'does not classify or persist the malformed message' do
        mod.run_host('192.0.2.17')

        expect(reports).to eq([])
      end
    end
  end

  it 'accepts the valid minimum negotiated ACK buffers' do
    socket.chunks.replace(['ACKF' + [28].pack('V') + [0, 8192, 8192, 0, 0].pack('V5')])
    mod.run_host('192.0.2.17')

    expect(reports.first.fetch(:info)).to eq('OPC-UA server (ACK): ProtocolVersion=0 RecvBuf=8192 SendBuf=8192')
  end

  it 'accepts an empty ERR reason with the unknown status-code fallback' do
    socket.chunks.replace(['ERRF' + [16].pack('V') + [0xDEADBEEF, 0].pack('V2')])
    mod.run_host('192.0.2.17')

    expect(reports.first.fetch(:info)).to eq('OPC-UA server (ERR): 0xDEADBEEF')
  end

  it 'retains a complete ERR reason at the specified 4096-byte limit' do
    reason = 'x' * 4096
    socket.chunks.replace(['ERRF' + [16 + reason.bytesize].pack('V') + [0x80830000, reason.bytesize].pack('V2') + reason])
    mod.run_host('192.0.2.17')

    expect(reports.first.fetch(:info)).to eq("OPC-UA server (ERR): Bad_TcpEndpointUrlInvalid - #{reason}")
  end

  it 'ignores an overlong ERR reason while retaining the valid error detection' do
    reason = 'x' * 4097
    socket.chunks.replace(['ERRF' + [16 + reason.bytesize].pack('V') + [0x80830000, reason.bytesize].pack('V2') + reason])
    mod.run_host('192.0.2.17')

    expect(reports.first.fetch(:info)).to eq('OPC-UA server (ERR): Bad_TcpEndpointUrlInvalid')
  end

  it 'preserves decode_error compatibility for a status-only direct caller' do
    expect(mod.decode_error([0x80830000].pack('V'))).to eq(['Bad_TcpEndpointUrlInvalid', ''])
  end

  it 'preserves decode_error compatibility for an incomplete direct caller' do
    expect(mod.decode_error("\x00\x01")).to eq(['unknown', ''])
  end

  [nil, ''].each do |empty|
    context "with an empty transport read #{empty.inspect}" do
      let(:chunks) { [empty] }

      it 'does not report a service' do
        mod.run_host('192.0.2.17')

        expect(reports).to eq([])
      end
    end
  end

  it 'does not report a non-OPC-UA SMTP greeting' do
    socket.chunks.replace(["220 mail.example.invalid ESMTP Postfix\r\n"])
    mod.run_host('192.0.2.17')

    expect(reports).to eq([])
  end

  it 'shares one five-second receive budget across header and body fragments' do
    socket.chunks.replace([ack.byteslice(0, 1), ack.byteslice(1, 7), ack.byteslice(8..)])
    durations = [2, 2, 0.5]
    allow(Rex::Stopwatch).to receive(:elapsed_time) { |&block| [block.call, durations.shift] }
    mod.run_host('192.0.2.17')

    expect([socket.reads, reports.length]).to eq([[[8, 5], [7, 3], [20, 1]], 1])
  end

  it 'rejects a complete response that arrives after the total receive budget' do
    durations = [2, 3.1]
    allow(Rex::Stopwatch).to receive(:elapsed_time) { |&block| [block.call, durations.shift] }
    mod.run_host('192.0.2.17')

    expect(reports).to eq([])
  end

  [Rex::ConnectionRefused.new('192.0.2.17', 4840), Rex::TimeoutError.new('Read timed out'), Timeout::Error.new('Read timed out'), IOError.new('Stream closed'), Errno::ECONNRESET.new].each do |error|
    it "logs and handles the expected #{error.class} transport boundary" do
      socket.chunks.replace([error])
      expect { mod.run_host('192.0.2.17') }.not_to raise_error

      expect(mod).to have_received(:elog).with('OPC-UA HEL exchange failed', error: error)
    end
  end

  it 'closes and unregisters the socket after a truncated response' do
    socket.chunks.replace([ack.byteslice(0, 8), nil])
    mod.run_host('192.0.2.17')

    expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
  end

  %i[print_good report_service].each do |operation|
    it "preserves #{operation} programming errors while closing its socket" do
      allow(mod).to receive(operation).and_raise(IOError, 'Unexpected reporting error')

      expect { mod.run_host('192.0.2.17') }.to raise_error(IOError, 'Unexpected reporting error')
      expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
    end
  end

  it 'preserves unexpected parser errors while closing its socket' do
    socket.chunks.replace([ArgumentError.new('Unexpected read bookkeeping error')])
    expect { mod.run_host('192.0.2.17') }.to raise_error(ArgumentError, 'Unexpected read bookkeeping error')

    expect([mod.send(:sock), mod.send(:sockets)]).to eq([nil, []])
  end
end
