require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Duplicator public check and file download contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('DUPLICATOR_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_duplicator_file_read.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    recorded = requests
    wire = transport
    boundary = Module.new do
      define_method(:send_request_cgi) do |options, *_arguments|
        recorded << { receiver: self, datastore: datastore, options: options }
        selected = if options.dig('vars_get', 'action') == 'duplicator_download'
                     wire[:download]
                   elsif options.fetch('uri').match?(%r{/plugins/duplicator/(?:readme|Readme|README)\.txt\z})
                     wire[:version]
                   else
                     Rex::Proto::Http::Response.new(404)
                   end
        raise selected if selected.is_a?(Exception)

        selected
      end
      %i[setup cleanup report_failure report_wordpress_service elog].each do |method|
        define_method(method) { |*_arguments| nil }
      end
    end
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.prepend(boundary)
    end
  end
  let(:readme_version) { '1.3.26' }
  let(:version_response) { response(200, "=== Duplicator - WordPress Migration Plugin ===\r\nStable tag: #{readme_version}\r\n") }
  let(:download_body) { "Owned Duplicator file: caf\xc3\xa9\nsecond line\x00binary\xffend\n".b }
  let(:download_headers) do
    {
      'Content-Description' => 'File Transfer',
      'Content-Disposition' => 'attachment; filename="module-target-duplicator-disclosure"',
      'Content-Length' => '52',
      'Content-Type' => 'application/octet-stream'
    }
  end
  let(:download_response) { response(200, download_body, download_headers) }
  let(:transport) { { version: version_response, download: download_response } }
  let(:requests) { [] }
  let(:loots) { [] }
  let(:messages) { [] }
  let(:listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:events) { double('FrameworkEvents', on_module_run: nil, on_module_complete: nil) }
  let(:framework) { double('Framework', events: events, datastore: Msf::DataStore.new) }

  before do
    allow(owner_class).to receive(:framework).and_return(framework)
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'FILEPATH' => '/tmp/module-target-duplicator-disclosure')
    allow(mod).to receive(:store_loot) do |type, mime, host, data, filename|
      loots << { type: type, mime: mime, host: host, data: data, filename: filename }
      '/tmp/unit-duplicator.loot'
    end
    %i[print_status print_good print_error print_line].each do |method|
      allow(mod).to receive(method) { |text| messages << [method, text] }
    end
  end

  # HTTP, lifecycle/reporting, UI, loot persistence and Framework events are
  # explicit doubles. Public capability/check_simple dispatch, real replicants,
  # WordPress readme parsing, Rex versions and HTTP response/header objects run.
  # Readmes retain the exact title/Stable tag lines and CRLF from genuine native
  # captures (receipt request2); full body SHA256 for versions1.3.24/26/28:
  # 299c8779cbc29420bd50d3e79a772ed7b862187d414fe7231e1290142255f778
  # c807e3ea69e99ddce1a09afcc6b3ad47d2a485e103541304674a2e632039f37a
  # 3b1844a0963a0a057f271caaee5e19efef1a2d2bdef39b87ad7a77dbe534812f
  # Binary request3, empty request6, missing request8 and their four stable
  # envelope headers are from native-1.3.26-20261116T004639/receipt.json.
  # Binary body SHA256:8ecb7317d7cab00eb2955b259564173defc34ce54fbc58c49bc978eb9d240736.
  # Patched refusal is native-1.3.28-20261116T004833 request3. Other variants are
  # synthetic. Captured files are owned test files, not real user data.

  def response(code, body, headers = {})
    Rex::Proto::Http::Response.new(code).tap do |result|
      result.body = body
      headers.each { |name, value| result.headers[name] = value }
    end
  end

  def public_check
    Msf::Simple::Auxiliary.check_simple(mod, 'RunAsJob' => false, 'JobListener' => listener)
  end

  def download
    mod.run_host('192.0.2.10')
  end

  def rejected(reason)
    expect { download }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, /\A#{Regexp.escape(reason)}: /)
    expect(loots).to be_empty
  end

  it('advertises scanner check support') { expect(mod.has_check?).to be(true) }

  it('preserves the direct public check API') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Appears) }

  it 'dispatches check on a distinct real replicant to the correct plugin readme' do
    mod.check
    expect(requests.first.fetch(:receiver)).not_to equal(mod)
    expect(requests.first.fetch(:datastore)).not_to equal(mod.datastore)
    expect(requests.first.fetch(:options)).to include('uri' => '/wp-content/plugins/duplicator/readme.txt')
  end

  it 'completes public scanner check for genuine 1.3.26 with a reason' do
    result = public_check
    expect(result).to have_attributes(code: 'appears', reason: a_string_matching(/Duplicator 1\.3\.26/))
    expect(listener).to have_received(:completed).with(anything, result, mod)
    expect(listener).not_to have_received(:failed)
  end

  context 'with the genuine minimum supported version' do
    let(:readme_version) { '1.3.24' }

    it('returns Appears') { expect(public_check).to eq(Msf::Exploit::CheckCode::Appears) }
  end

  context 'with genuine fixed 1.3.28' do
    let(:readme_version) { '1.3.28' }

    it('returns reason-bearing Safe') { expect(public_check).to have_attributes(code: 'safe', reason: a_string_matching(/Duplicator 1\.3\.28/)) }
  end

  context 'with no readme response' do
    let(:version_response) { nil }

    it 'preserves Unknown and all three readme variants' do
      expect(public_check).to have_attributes(code: 'unknown', reason: 'No response')
      expect(requests.map { |row| row.fetch(:options).fetch('uri') }).to eq(['/wp-content/plugins/duplicator/readme.txt', '/wp-content/plugins/duplicator/Readme.txt', '/wp-content/plugins/duplicator/README.txt'])
    end
  end

  context 'with a missing plugin readme' do
    let(:version_response) { response(404, 'Not Found') }

    it('returns Unknown') { expect(public_check.code).to eq('unknown') }
  end

  context 'with an unversioned readme document' do
    let(:version_response) { response(200, 'No version is available') }

    it('preserves the version helper Detected result') { expect(public_check).to have_attributes(code: 'detected', reason: 'Could not identify the version number') }
  end

  it 'preserves selected host, install prefix, content directory and settings' do
    mod.datastore.merge!('RHOST' => '192.0.2.11', 'TARGETURI' => '/wordpress/', 'WPCONTENTDIR' => 'custom-content')
    mod.validate
    settings = mod.datastore.to_h.dup
    expect(public_check).to eq(Msf::Exploit::CheckCode::Appears)
    expect(requests.first.fetch(:datastore)['RHOST']).to eq('192.0.2.11')
    expect(requests.first.fetch(:options)).to include('uri' => '/wordpress/custom-content/plugins/duplicator/readme.txt')
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'creates fresh replicants for repeated public checks' do
    2.times { expect(public_check).to eq(Msf::Exploit::CheckCode::Appears) }
    expect(requests.map { |row| row.fetch(:receiver).object_id }.uniq.length).to eq(2)
  end

  it 'retains exact binary bytes, filename and existing loot identity' do
    download
    expect(loots.length).to eq(1)
    expect(loots.first.slice(:type, :mime, :host, :filename)).to eq(type: 'duplicator.traversal', mime: 'text/plain', host: '192.0.2.10', filename: mod.datastore['FILEPATH'])
    expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
    expect(loots.first.fetch(:data).encoding).to eq(download_body.encoding)
  end

  context 'with the genuine empty-file envelope' do
    let(:download_body) { ''.b }
    let(:download_headers) { super().merge('Content-Disposition' => 'attachment; filename="module-target-duplicator-empty"', 'Content-Length' => '0') }

    it 'stores the zero-byte file' do
      download
      expect(loots.map { |row| row.fetch(:data).bytesize }).to eq([0])
    end
  end

  context 'with genuine missing-file refusal' do
    let(:download_response) { response(200, 'Invalid installer file name!!', 'Content-Type' => 'text/html; charset=UTF-8', 'Content-Length' => '29') }

    it('does not save refusal text') { rejected(Msf::Module::Failure::NotVulnerable) }
  end

  context 'with genuine patched refusal' do
    let(:download_response) { response(200, 'Invalid request', 'Content-Type' => 'text/html; charset=UTF-8', 'Content-Length' => '15') }

    it('does not save refusal text') { rejected(Msf::Module::Failure::NotVulnerable) }
  end

  context 'with actual file contents equal to an error message' do
    let(:download_body) { 'Invalid installer file name!!'.b }
    let(:download_headers) { super().merge('Content-Length' => '29') }

    it 'accepts the file envelope without interpreting its contents' do
      download
      expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
    end
  end

  ['Content-Disposition', 'Content-Type'].each do |header|
    context "without #{header}" do
      let(:download_headers) { super().reject { |name, _value| name == header } }

      it('rejects the incomplete vendor envelope') { rejected(Msf::Module::Failure::NotVulnerable) }
    end
  end

  ['inline; filename="owned.bin"', 'attachment; name="owned.bin"', 'attachment; filename=""', "attachment; filename=owned.bin\r\nInjected: value"].each do |value|
    context "with invalid disposition #{value.inspect}" do
      let(:download_headers) { super().merge('Content-Disposition' => value) }

      it('rejects the metadata') { rejected(Msf::Module::Failure::NotVulnerable) }
    end
  end

  ['', '-1', '52junk', '53'].each do |value|
    context "with invalid or mismatched length #{value.inspect}" do
      let(:download_headers) { super().merge('Content-Length' => value) }

      it('returns UnexpectedReply without loot') { rejected(Msf::Module::Failure::UnexpectedReply) }
    end
  end

  context 'without optional Content-Description' do
    let(:download_headers) { super().except('Content-Description') }

    it 'accepts the attachment' do
      download
      expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
    end
  end

  context 'with an already decoded chunked response' do
    let(:download_headers) { super().except('Content-Length').merge('Transfer-Encoding' => 'chunked') }

    it 'preserves binary data without requiring Content-Length' do
      download
      expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
    end
  end

  context 'with an empty close-delimited response' do
    let(:download_body) { ''.b }
    let(:download_headers) { super().except('Content-Length') }

    it 'stores the zero-byte file' do
      download
      expect(loots.map { |row| row.fetch(:data).bytesize }).to eq([0])
    end
  end

  context 'with a UTF-8 response string whose byte count differs from length' do
    let(:download_body) { 'café_☃' }
    let(:download_headers) { super().merge('Content-Length' => download_body.bytesize.to_s) }

    it 'uses byte length without changing the string' do
      download
      expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
      expect(download_body.encoding).to eq(Encoding::UTF_8)
    end
  end

  context 'with conservative HTTP header formatting variations' do
    let(:download_headers) { super().merge('Content-Type' => 'Application/Octet-Stream; charset=binary', 'Content-Description' => 'file transfer', 'Content-Disposition' => 'Attachment; creation-date="today"; FILENAME = "owned;name.bin"') }

    it 'accepts the complete envelope' do
      download
      expect(loots.first.fetch(:data).bytes).to eq(download_body.bytes)
    end
  end

  context 'with missing response body data' do
    let(:download_body) { nil }

    it('returns UnexpectedReply') { rejected(Msf::Module::Failure::UnexpectedReply) }
  end

  context 'without a download response' do
    let(:download_response) { nil }

    it('returns Unreachable') { rejected(Msf::Module::Failure::Unreachable) }
  end

  [401, 403, 404, 500].each do |code|
    context "with download HTTP #{code}" do
      let(:download_response) { response(code, 'Error') }

      it('does not create loot') { rejected([401, 403].include?(code) ? Msf::Module::Failure::NoAccess : Msf::Module::Failure::UnexpectedReply) }
    end
  end

  context 'with expected connection failure' do
    let(:download_response) { Rex::ConnectionRefused.new }
    let(:version_response) { Rex::ConnectionRefused.new }

    it('returns Unknown from public check') { expect(public_check.code).to eq('unknown') }
    it('returns Unreachable from file read') { rejected(Msf::Module::Failure::Unreachable) }
  end

  it 'preserves relative and Unicode path inputs and traversal settings' do
    mod.datastore.merge!('TARGETURI' => '/wordpress/', 'DEPTH' => 3, 'FILEPATH' => 'tmp/café space file')
    mod.validate
    settings = mod.datastore.to_h.dup
    download
    expect(requests.last.fetch(:options)).to include('uri' => '/wordpress/wp-admin/admin-ajax.php', 'vars_get' => { 'action' => 'duplicator_download', 'file' => '../../../tmp/café space file' })
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'does not reuse a prior successful envelope on repeated execution' do
    2.times { download }
    transport[:download] = response(200, 'Invalid request', 'Content-Type' => 'text/html', 'Content-Length' => '15')
    expect { download }.to raise_error(Msf::Auxiliary::Failed)
    transport[:download] = download_response
    download
    expect(loots.length).to eq(3)
    expect(loots.all? { |row| row.fetch(:data).bytes == download_body.bytes }).to be(true)
  end
end
