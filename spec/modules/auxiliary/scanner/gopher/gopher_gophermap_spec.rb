require 'rspec'
require 'json'
require 'tmpdir'
require 'rex/stopwatch'

RSpec.describe 'Gopher complete menu handling' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/gopher/gopher_gophermap') }

  let(:modules_path) { ENV.fetch('GOPHER_UNIT_MODULE_ROOT', File.expand_path('../../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('gopher-menu-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../../file_fixtures/modules/auxiliary/gopher/responses.json', __dir__))) }
  let(:selector) { '' }
  let(:body) { captures.fetch('menus').fetch(selector).fetch('body').b }
  let(:segments) { [body] }
  let(:stream) { double('Rex socket stream', put: nil, def_block_size: 16_384) }
  let(:printed) { [] }
  let(:reports) { [] }
  let(:reads) { [] }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['RPORT'] = 70
    mod.datastore['PATH'] = selector
    allow(mod).to receive(:connect)
    allow(mod).to receive(:disconnect)
    allow(mod).to receive(:sock).and_return(stream)
    allow(mod).to receive(:print_good) { |text| printed << text.b }
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:report_service) { |options| reports << options }
    pending = segments.map(&:dup)
    allow(stream).to receive(:get_once) do |length = -1, timeout = 10|
      reads << [length, timeout]
      fragment = pending.shift
      next nil unless fragment

      limit = length == -1 ? 16_384 : length
      received = fragment.byteslice(0, limit)
      pending.unshift(fragment.byteslice(limit..)) if fragment.bytesize > limit
      received
    end
  end

  ['', '/dir', '/space dir', '/custom', '/empty', '/empty-map', '/large', '/missing'].each do |path|
    context "with native #{path.empty? ? 'root' : path} menu bytes" do
      let(:selector) { path }

      it 'reports the exact complete response and correct service identity' do
        mod.run_host('192.0.2.1')
        expect(reports.map { |record| record.except(:info) }).to eq([{ host: '192.0.2.1', port: 70, name: 'gopher' }])
        expect(reports.first.fetch(:info).bytes).to eq(body.bytes)
      end
    end
  end

  context 'with the native custom information and Unicode menu' do
    let(:selector) { '/custom' }

    it 'keeps the captured descriptions and explicit location' do
      mod.run_host('192.0.2.1')
      expect(printed).to include('Native Gopher information marker'.b,
                                 '  Text file: Unicode café 日本語'.b,
                                 '    Path: 192.0.2.70:7070/dir/nested.txt'.b)
    end
  end

  context 'with two independent native responses' do
    let(:segments) { [body, body] }

    it 'resets its read buffer and preserves the selector on repeated executions' do
      2.times { mod.run_host('192.0.2.1') }
      expect(stream).to have_received(:put).with("\r\n").twice
      expect(mod).to have_received(:disconnect).twice
      expect(reports.map { |record| record.fetch(:info).bytes }).to eq([body.bytes, body.bytes])
    end
  end

  context 'with a synthetic split inside the native terminator' do
    let(:segments) { [body.byteslice(0, body.bytesize - 2), "\r".b, "\n".b] }

    it 'waits for the whole dot line before reporting' do
      mod.run_host('192.0.2.1')
      expect(reports.first&.fetch(:info)&.bytes).to eq(body.bytes)
      expect(reads.length).to eq(3)
    end
  end

  context 'with a synthetic split within a native Unicode character' do
    let(:selector) { '/custom' }
    let(:segments) { [body.byteslice(0, body.index("\xc3".b) + 1), body.byteslice(body.index("\xc3".b) + 1..)] }

    it 'retains the exact binary response across character boundaries' do
      mod.run_host('192.0.2.1')
      expect(reports.first&.fetch(:info)&.bytes).to eq(body.bytes)
    end
  end

  context 'with the native large menu' do
    let(:selector) { '/large' }

    it 'reads beyond one receive block and prints the final captured row' do
      mod.run_host('192.0.2.1')
      expect(printed).to include('  Text file: Native large menu item 0511 with a long stable description marker'.b)
      expect(reads.length).to eq(4)
    end
  end

  context 'with the native unrelated HTTP response' do
    let(:body) { captures.fetch('http').fetch('body').b }

    it 'does not persist the HTTP daemon as a Gopher service' do
      mod.run_host('192.0.2.1')
      expect(reports).to eq([])
    end
  end

  # Short optional-location forms and malformed mutations are synthetic guards.
  {
    'selector only' => ["0Short\t/text.txt\r\n.\r\n", '    Path: /text.txt'],
    'host without a port' => ["0Short\t/text.txt\texample.invalid\r\n.\r\n", '    Path: example.invalid:/text.txt'],
    'extra extension fields' => ["0Short\t/text.txt\texample.invalid\t70\textra\r\n.\r\n", '    Path: example.invalid:70/text.txt'],
    'unknown printable type' => ["zNew type\t/text.txt\texample.invalid\t70\r\n.\r\n", '  Invalid File Type (z): New type']
  }.each do |name, (wire, expected)|
    context "with synthetic #{name}" do
      let(:body) { wire.b }

      it 'preserves the compatible row output without raising' do
        mod.run_host('192.0.2.1')
        expect(printed).to include(expected.b)
      end
    end
  end

  [
    "Not a menu\r\n.\r\n", "0Missing selector\r\n.\r\n", "0Bad port\t/text.txt\texample.invalid\tnope\r\n.\r\n",
    "0Bad newline\t/text\n.txt\r\n.\r\n", "\0Bad type\t/text.txt\r\n.\r\n"
  ].each do |wire|
    context "with synthetic malformed menu #{wire.inspect}" do
      let(:body) { wire.b }

      it 'does not print success or persist an invalid menu' do
        mod.run_host('192.0.2.1')
        expect([printed, reports]).to eq([[], []])
      end
    end
  end

  context 'with a synthetically truncated native response' do
    let(:body) { captures.fetch('menus').fetch('').fetch('body').b.delete_suffix(".\r\n") }

    it 'rejects EOF before the menu terminator' do
      mod.run_host('192.0.2.1')
      expect([printed, reports]).to eq([[], []])
    end
  end

  context 'with a synthetic invalid row after a native valid row' do
    let(:body) { captures.fetch('menus').fetch('/dir').fetch('body').b.sub(".\r\n", "Invalid line\r\n.\r\n") }

    it 'validates all rows before printing partial success' do
      mod.run_host('192.0.2.1')
      expect([printed, reports]).to eq([[], []])
    end
  end

  context 'with the configured limit equal to the native response size' do
    before { mod.datastore['GopherMaxBytes'] = body.bytesize }

    it 'accepts a complete response at the limit' do
      mod.run_host('192.0.2.1')
      expect(reports.first&.fetch(:info)&.bytes).to eq(body.bytes)
    end
  end

  context 'with the configured limit one byte below the native response size' do
    before { mod.datastore['GopherMaxBytes'] = body.bytesize - 1 }

    it 'rejects the oversized response without printing partial results' do
      mod.run_host('192.0.2.1')
      expect([printed, reports]).to eq([[], []])
    end
  end

  context 'with synthetic slow fragments beyond the total read deadline' do
    let(:segments) { [body.byteslice(0, 5), body.byteslice(5..)] }

    before do
      durations = [9.0, 2.0]
      allow(Rex::Stopwatch).to receive(:elapsed_time) { |&operation| [operation.call, durations.shift || 0.0] }
    end

    it 'subtracts elapsed time between reads and rejects a late completion' do
      mod.run_host('192.0.2.1')
      expect(reports).to eq([])
      expect(reads.map(&:last)).to eq([10, 1.0])
    end
  end

  %w[GopherReadTimeout GopherMaxBytes].each do |option|
    [0, -1].each do |value|
      context "with synthetic invalid #{option}=#{value}" do
        before { mod.datastore[option] = value }

        it 'reports a bad configuration instead of disabling the bound' do
          expect { mod.run_host('192.0.2.1') }.to raise_error(Msf::Auxiliary::Failed, /must be positive/)
        end
      end
    end
  end

  context 'when the stream closes before any response' do
    before { allow(stream).to receive(:get_once).and_raise(EOFError) }

    it 'does not identify a service and still disconnects' do
      mod.run_host('192.0.2.1')
      expect(reports).to eq([])
      expect(mod).to have_received(:disconnect)
    end
  end

  context 'when an expected transport failure occurs' do
    before { allow(stream).to receive(:get_once).and_raise(Rex::ConnectionError, 'Connection reset') }

    it 'keeps output concise and always disconnects' do
      mod.run_host('192.0.2.1')
      expect(reports).to eq([])
      expect(mod).to have_received(:disconnect)
      expect(mod).not_to have_received(:print_error)
    end
  end

  context 'when an unexpected programming error occurs' do
    before { allow(stream).to receive(:get_once).and_raise(NoMethodError, 'Unexpected implementation failure') }

    it 'does not swallow the programming error in an Exception rescue' do
      expect { mod.run_host('192.0.2.1') }.to raise_error(NoMethodError)
      expect(mod).to have_received(:disconnect)
    end
  end

  it 'keeps the existing get_type result for a known character' do
    expect(mod.get_type("0\n")).to eq('Text file')
  end

  it 'returns nil for an unknown type instead of making its fallback unreachable' do
    expect(mod.get_type('z')).to be_nil
  end
end
