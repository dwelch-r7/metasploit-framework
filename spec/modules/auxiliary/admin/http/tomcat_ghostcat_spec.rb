require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'Tomcat Ghostcat response assembly and loot' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'admin/http/tomcat_ghostcat') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/tomcat_ghostcat/responses.json'))) }
  let(:stored) { [] }

  before do
    mod.datastore['RHOSTS'] = '192.0.2.53'
    allow(mod).to receive(:print)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:store_loot) do |*arguments|
      stored << arguments
      '/tmp/module-target-ghostcat.txt'
    end
  end

  { 'short' => 'short.txt', 'large' => 'large.txt', 'empty' => 'empty.txt', 'unicode' => 'unicode.txt', 'binary' => 'binary.txt', 'webxml' => 'web.xml' }.each do |name, filename|
    it "retains exact native #{name} bytes across the captured AJP body packets" do
      parsed = mod.parse_response(response("vulnerable/#{filename}"))

      expect(parsed.body).to eq(Base64.strict_decode64(captures.fetch('files').fetch(name)))
    end
  end

  it 'retains actual status and header names through the existing response shape' do
    parsed = mod.parse_response(response('vulnerable/short.txt'))

    expect(parsed.to_h).to include(status: 200, headers: include('Content-Length' => '31'))
  end

  it 'does not carry body data from a previous parse into a new empty-file response' do
    mod.parse_response(response('vulnerable/large.txt'))

    expect(mod.parse_response(response('vulnerable/empty.txt')).body).to eq('')
  end

  it 'does not mutate the supplied native response buffer' do
    original = response('vulnerable/short.txt')
    supplied = original.dup
    mod.parse_response(supplied)

    expect(supplied).to eq(original)
  end

  { 'fixed/short.txt' => 403, 'vulnerable/module-target-missing.txt' => 500 }.each do |name, status|
    it "retains the real HTTP #{status} status without treating it as a successful read" do
      parsed = mod.parse_response(response(name))

      expect(mod.read_success?(parsed)).to be(false)
    end

    it "does not print or store the real #{status} error page as file contents" do
      allow(mod).to receive(:read_remote_file).and_return(mod.parse_response(response(name)))

      mod.run

      expect(stored).to be_empty
      expect(mod).not_to have_received(:print)
      expect(mod).not_to have_received(:print_good)
    end
  end

  it 'stores the complete captured file with the established loot metadata' do
    mod.datastore['FILENAME'] = '/WEB-INF/large.txt'
    allow(mod).to receive(:read_remote_file).and_return(mod.parse_response(response('vulnerable/large.txt')))

    mod.run

    expect(stored.first.values_at(0, 1, 3, 4, 5, 6)).to eq(['/WEB-INF/large.txt', 'text/plain', Base64.strict_decode64(captures.fetch('files').fetch('large')), 'Ghostcat File Read/Inclusion', 'Read file', '/WEB-INF/large.txt'])
  end

  it 'stores a legitimate zero-byte file rather than inventing or dereferencing body data' do
    allow(mod).to receive(:read_remote_file).and_return(mod.parse_response(response('vulnerable/empty.txt')))

    mod.run

    expect(stored.first.fetch(3)).to eq('')
  end

  it 'refuses a derived truncated frame header without a Ruby nil exception' do
    expect { mod.parse_response(response('vulnerable/short.txt').byteslice(0, 3)) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'refuses a derived incomplete response without END_RESPONSE' do
    incomplete = packets('vulnerable/short.txt')[0...-1].join

    expect { mod.parse_response(incomplete) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'refuses a derived body packet shorter than its declared length' do
    incomplete = packets('vulnerable/short.txt').first + packets('vulnerable/short.txt').fetch(1).byteslice(0...-2)

    expect { mod.parse_response(incomplete) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'refuses a derived wrong-protocol signature instead of accepting the embedded status' do
    invalid = response('vulnerable/short.txt').dup
    invalid[0, 2] = 'HT'

    expect { mod.parse_response(invalid) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'refuses a derived response ending before any status headers' do
    expect { mod.parse_response(packets('vulnerable/short.txt').last) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'refuses a derived body terminator that is not the protocol zero byte' do
    invalid = packets('vulnerable/short.txt')
    invalid[1][-1] = 'X'

    expect { mod.parse_response(invalid.join) }.to raise_error(Rex::RuntimeError, /AJP|response/i)
  end

  it 'does not report an incomplete response as a successful check' do
    allow(mod).to receive(:send_recv_once).and_return(packets('vulnerable/short.txt').first)

    expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
  end

  def packets(name)
    captures.fetch('responses').fetch(name).fetch('packets_base64').map { |value| Base64.strict_decode64(value) }
  end

  def response(name)
    packets(name).join
  end
end
