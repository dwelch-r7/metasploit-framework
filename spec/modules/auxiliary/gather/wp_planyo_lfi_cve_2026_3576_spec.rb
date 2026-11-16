require 'rspec'
require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'uri'
require 'base64'

RSpec.describe 'Planyo file URL contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('PLANYO_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/wp_planyo_lfi_cve_2026_3576.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:fixture_root) { File.expand_path('../../../file_fixtures/modules/auxiliary/gather/wp_planyo_lfi_cve_2026_3576', __dir__) }
  let(:captures) { JSON.parse(File.read(File.join(fixture_root, 'responses.json'))).fetch('responses') }
  let(:provenance) { JSON.parse(File.read(File.join(fixture_root, 'provenance.json'))).fetch('responses') }
  let(:client) { Rex::Proto::Http::Client.new('192.0.2.10', 80) }
  let(:online) { true }
  let(:readme_name) { 'readme' }
  let(:file_reply) { 'text' }
  let(:requests) { [] }
  let(:loot) { [] }
  let(:output) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false)
    allow(mod).to receive(:wordpress_and_online?).and_return(online)
    allow(mod).to receive(:connect).and_return(client)
    allow(mod).to receive(:disconnect)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/unit/planyo-file.bin'
    end
    %i[print_status print_good print_error vprint_status vprint_line].each { |method| allow(mod).to receive(method) { |text| output << text } }
    # Discovery, connect/send_recv and persistence are doubles. Actual public
    # run, readme/changelog version helpers, HttpClient CGI/raw dispatch and Rex
    # request serialization execute. No socket, PHP or target filesystem runs.
    allow(client).to receive(:send_recv) { |request, *_arguments| receive_request(request) }
  end

  def response(name)
    data = captures.fetch(name)
    Rex::Proto::Http::Response.new(data.fetch('code')).tap { |result| result.body = Base64.strict_decode64(data.fetch('body_base64')) }
  end

  def bad_request
    Rex::Proto::Http::Response.new(400).tap { |result| result.body = '' }
  end

  def receive_request(request)
    line = request.to_s.b.split("\r\n", 2).first
    record = { line: line, cgi: request.opts['cgi'] }
    requests << record
    target = line[%r{\AGET ([!-~]+) HTTP/1\.1\z}, 1]
    return bad_request unless target

    parsed = URI.parse("http://192.0.2.10#{target}")
    record[:target] = parsed
    return response(readme_name) if parsed.path.end_with?('/readme.txt')
    return bad_request unless parsed.path.end_with?('/ulap.php')
    return nil if file_reply.nil?

    # Model PHP GET decoding once, then URL path percent decoding once. This
    # independent byte contract catches query/fragment splitting and a literal
    # percent being mistaken for an already encoded filename.
    parameters = URI.decode_www_form(parsed.query.to_s)
    return bad_request unless parameters.length == 1 && parameters.first.first == 'ulap_url'

    record[:url] = parameters.first.last
    file = URI.parse(record[:url])
    return bad_request unless file.scheme == 'file' && file.query.nil? && file.fragment.nil?

    record[:path_bytes] = Rex::Text.uri_decode(file.path).b
    return bad_request unless record[:path_bytes] == mod.datastore['FILEPATH'].b

    response(file_reply)
  rescue URI::InvalidURIError, ArgumentError
    bad_request
  end

  def file_requests
    requests.select { |record| record[:line].include?('/ulap.php') }
  end

  def collect(path)
    mod.datastore['FILEPATH'] = path
    mod.run
    expect(file_requests.last.fetch(:path_bytes)).to eq(path.b)
    expect(loot.last.fetch(3).b).to eq(Base64.strict_decode64(captures.fetch(file_reply).fetch('body_base64')))
  end

  it 'preserves the default file and does not add a public check' do
    expect(mod.datastore['FILEPATH']).to eq('/etc/passwd')
    expect(owner_class.instance_methods(false)).not_to include(:check)
    mod.run
    expect(file_requests.last.fetch(:path_bytes)).to eq('/etc/passwd'.b)
  end

  it 'uses the actual ascending changelog last version' do
    result = mod.check_plugin_version_from_changelog('3.0')
    expect(result).to eq(Msf::Exploit::CheckCode::Appears)
    expect(result.details[:version]).to eq('2.9')
  end

  { 'text' => 'text.txt', 'binary' => 'binary.bin', 'empty' => 'empty.bin' }.each do |kind, filename|
    context "with native #{kind} response bytes" do
      let(:file_reply) { kind }

      it('stores the exact body including empty data') { collect('/tmp/module-target-planyo/' + filename) }
    end
  end

  context 'with the native reserved and UTF-8 filename' do
    let(:file_reply) { 'special' }

    it 'matches the independently encoded native file URL' do
      collect('/tmp/module-target-planyo/space & café #.txt')
      native = provenance.find { |record| record.fetch('label') == 'special' }.fetch('path')
      expected = URI.decode_www_form(URI.parse(native).query).to_h.fetch('ulap_url')
      expect(file_requests.last.fetch(:url)).to eq(expected)
    end

    it 'preserves valid UTF-8 bytes supplied in an ASCII-8BIT datastore string' do
      collect('/tmp/module-target-planyo/space & café #.txt'.b.freeze)
      expect(file_requests.last.fetch(:line).ascii_only?).to be(true)
    end
  end

  # URI-only synthetic filenames. These do not claim additional vendor file
  # wrapper/filesystem support beyond the native captures described above.
  ['/tmp/literal%.txt', '/tmp/literal%20.txt', '/tmp/literal%2F.txt', '/tmp/plus+name.txt', '/tmp/query?name.txt', '/tmp/fragment#name.txt', '/tmp/double"quote.txt', "/tmp/single'quote.txt", '/tmp/back\\slash.txt', '/tmp//folder/../file.txt'].each do |path|
    it "preserves synthetic filename bytes #{path.inspect}" do
      collect(path.freeze)
      expect(loot.last.fetch(4)).to eq(File.basename(path))
    end
  end

  context 'with HTTP500 from a native denied or missing file' do
    %w[denied missing].each do |kind|
      context "for #{kind}" do
        let(:file_reply) { kind }

        it 'keeps the existing UnexpectedReply failure without loot' do
          expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
          expect(mod.fail_reason).to eq(Msf::Module::Failure::UnexpectedReply)
          expect(loot).to be_empty
        end
      end
    end
  end

  context 'without a file response' do
    let(:file_reply) { nil }

    it 'keeps the existing Unreachable failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
      expect(mod.fail_reason).to eq(Msf::Module::Failure::Unreachable)
      expect(loot).to be_empty
    end
  end

  context 'with the genuine fixed readme' do
    let(:readme_name) { 'fixed_readme' }

    it 'preserves version gating before the file request' do
      mod.run
      expect(file_requests).to be_empty
      expect(loot).to be_empty
      expect(output.join).to include('This version of plugin is not vulnerable')
    end
  end

  [nil, ''].each do |path|
    it "preserves refusal for unspecified FILEPATH #{path.inspect}" do
      mod.datastore['FILEPATH'] = path
      mod.run
      expect(file_requests).to be_empty
      expect(loot).to be_empty
    end
  end

  context 'when WordPress discovery fails' do
    let(:online) { false }

    it 'preserves the existing early return' do
      mod.run
      expect(requests).to be_empty
      expect(loot).to be_empty
    end
  end

  it 'preserves datastore bytes and settings across repeated prefix requests' do
    path = '/tmp/module-target-planyo/space & café #.txt'.b.freeze
    mod.datastore.merge!('TARGETURI' => '/wordpress/', 'FILEPATH' => path)
    settings = mod.datastore.to_h.dup
    2.times { mod.run }
    expect(mod.datastore.to_h).to eq(settings)
    expect(mod.datastore['FILEPATH'].encoding).to eq(Encoding::ASCII_8BIT)
    expect(file_requests.map { |record| record.fetch(:target).path }.uniq).to eq(['/wordpress/wp-content/plugins/planyo-online-reservation-system/ulap.php'])
    expect(loot.length).to eq(2)
  end
end
