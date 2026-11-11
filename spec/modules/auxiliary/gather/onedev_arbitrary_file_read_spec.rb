require 'rspec'
require 'json'
require 'base64'
require 'digest'
require 'tmpdir'

RSpec.describe 'OneDev file read response contracts' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/onedev_arbitrary_file_read') }

  let(:modules_path) { ENV.fetch('ONEDEV_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('onedev-file-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/onedev_file/responses.json', __dir__))) }
  let(:requests) { [] }
  let(:root_response) { captured_response('root_private') }
  let(:file_response) { captured_response('short') }
  let(:project_response) { captured_response('project') }
  let(:wordlist) { dummy_pathname.join('projects.txt') }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['PROJECT_NAME'] = 'module-target-project'
    mod.datastore['TARGETFILE'] = '/opt/module-target-files/short.txt'
    mod.datastore['AutoCheck'] = false
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:store_loot)
    allow(mod).to receive(:send_request_cgi) do |request, *_timeouts|
      requests << request
      if request.fetch('method') == 'HEAD'
        request.fetch('uri') == '/module-target-project/~site' ? project_response : captured_response('absent_project')
      elsif request.fetch('uri') == '/'
        root_response
      else
        file_response
      end
    end
  end

  def captured_response(name)
    capture = captures.fetch('responses').fetch(name)
    body = Base64.strict_decode64(capture.fetch('body_base64'))
    raise 'Fixture body digest mismatch' unless Digest::SHA256.hexdigest(body) == capture.fetch('body_sha256')

    result = response(capture.fetch('status'), body)
    capture.fetch('headers').each { |header_name, value| result.headers[header_name] = value }
    result
  end

  def response(status, body, disposition = nil)
    result = Rex::Proto::Http::Response.new(status)
    result.body = body
    result.headers['Content-Disposition'] = disposition if disposition
    result
  end

  def run_failure(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, reason)
    expect(mod).not_to have_received(:print_good)
    expect(mod).not_to have_received(:store_loot)
  end

  context 'with genuine affected file responses replayed through doubles' do
    %w[short empty unicode space error_phrase].each do |name|
      context "with the #{name} file" do
        let(:file_response) { captured_response(name) }

        it 'prints the exact bytes even when the content resembles an error' do
          mod.run
          expect(mod).to have_received(:print_good).with("#{mod.datastore['TARGETFILE']} file retrieved with success.\n#{file_response.body}")
        end
      end
    end

    context 'with the binary file' do
      let(:file_response) { captured_response('binary') }

      it 'stores the exact bytes without text conversion' do
        mod.datastore['STORE_LOOT'] = true
        mod.run
        expect(mod).to have_received(:store_loot).with('short.txt', anything, '192.0.2.1', "\x00\xffAB\n".b, mod.datastore['TARGETFILE'], anything)
      end
    end

    context 'with the literal space-containing path from the native capture' do
      let(:file_response) { captured_response('space') }

      before { mod.datastore['TARGETFILE'] = '/opt/module-target-files/space name.txt' }

      it 'uses the native encoded file path while preserving traversal and slash separators' do
        mod.run
        expect(requests.last.fetch('uri')).to eq(captures.fetch('responses').fetch('space').fetch('path'))
      end
    end
  end

  { 'missing' => /not found|file response/i, 'directory' => /file response/i, 'fixed' => /HTTP 500/ }.each do |name, reason|
    context "with the genuine #{name} response replayed through a double" do
      let(:file_response) { captured_response(name) }

      it 'rejects the response without reporting or storing a file' do
        mod.datastore['STORE_LOOT'] = true
        run_failure(reason)
      end
    end
  end

  context 'with genuine private OneDev landing and passwd responses' do
    let(:file_response) { captured_response('passwd') }

    it 'proves vulnerability through the file response' do
      expect(mod.check).to eq(Msf::Exploit::CheckCode::Vulnerable)
    end

    it 'does not change configured options during checking' do
      before = mod.datastore.to_h
      mod.check
      expect(mod.datastore.to_h).to eq(before)
    end
  end

  context 'with the genuine fixed public landing page' do
    let(:root_response) { captured_response('root_public') }

    it 'returns Safe using the actual fixed version' do
      expect(mod.check).to eq(Msf::Exploit::CheckCode::Safe)
    end
  end

  context 'with the genuine fixed private error response' do
    let(:file_response) { captured_response('fixed') }

    it 'returns Unknown when the version is hidden and the read is not proven' do
      expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
    end
  end

  context 'with a genuine unknown-project response' do
    before { mod.datastore['PROJECT_NAME'] = 'module-target-missing' }

    it 'does not infer a fixed product from an invalid project' do
      expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown)
    end

    it 'refuses an unchecked run without false success' do
      run_failure(/project/i)
    end
  end

  context 'with a synthetic wordlist using native-proven project names' do
    let(:file_response) { captured_response('passwd') }

    before do
      mod.datastore['PROJECT_NAME'] = ''
      mod.datastore['PROJECT_NAMES_FILE'] = wordlist.to_s
      File.write(wordlist, "\nmodule-target-missing\nmodule-target-project\n")
    end

    it 'allows the documented optional project configuration' do
      expect { mod.options.validate(mod.datastore) }.not_to raise_error
    end

    it 'advertises the project name as optional' do
      expect(mod.options['PROJECT_NAME']).not_to be_required
    end

    it 'discovers a project during a versionless check' do
      expect(mod.check).to eq(Msf::Exploit::CheckCode::Vulnerable)
      expect(requests.map { |request| request['uri'] }).to include('/module-target-project/~site')
    end

    it 'skips blank candidates' do
      mod.run
      expect(requests.map { |request| request['uri'] }).not_to include('/~site')
    end

    it 'initializes and repeats discovery with AutoCheck disabled' do
      2.times { mod.run }
      expect(mod).to have_received(:print_good).twice
      expect(requests.count { |request| request['uri'] == '/module-target-project/~site' }).to eq(2)
    end

    it 'keeps the omitted project option unchanged' do
      mod.run
      expect(mod.datastore['PROJECT_NAME']).to eq('')
    end

    context 'without a matching candidate' do
      before { File.write(wordlist, "module-target-missing\n") }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('fails run without producing loot') { run_failure(/project/i) }
    end

    context 'with a missing wordlist' do
      before { File.unlink(wordlist) }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('reports the configuration failure from run') { run_failure(/wordlist/i) }
    end

    context 'with synthetically denied wordlist access' do
      before { allow(File).to receive(:open).with(wordlist.to_s, 'rb').and_raise(Errno::EACCES) }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('reports the configuration failure from run') { run_failure(/wordlist/i) }
    end

    context 'with a synthetic nil wordlist option' do
      before { mod.datastore['PROJECT_NAMES_FILE'] = nil }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('reports the configuration failure from run') { run_failure(/wordlist/i) }
    end
  end

  context 'with synthetic nullable and malformed response guards' do
    context 'when the file request does not respond' do
      let(:file_response) { nil }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('fails run without producing loot') { run_failure(/respond|timed out/i) }
    end

    [nil, '', 'inline', 'inline; filename=""', 'inline; notfilename="file.txt"', 'inline; filename="file.txt"invalid'].each do |disposition|
      context "with malformed or absent filename metadata #{disposition.inspect}" do
        let(:file_response) { response(200, 'Arbitrary server response', disposition) }

        it('does not store arbitrary HTTP 200 data') { run_failure(/file response/i) }
      end
    end

    context 'with a synthetic HTML file and genuine successful filename metadata' do
      let(:file_response) do
        result = captured_response('short')
        result.headers['Content-Type'] = 'text/html'
        result.body = '<html>Site file not found is a log message</html>'
        result
      end

      it 'preserves genuine file type independence' do
        mod.run
        expect(mod).to have_received(:print_good).with(include(file_response.body))
      end
    end

    context 'when the landing request does not respond' do
      let(:root_response) { nil }

      it('returns Unknown') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
    end

    context 'with a synthetic nil landing body' do
      let(:root_response) { response(200, nil) }

      it('returns Unknown') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
    end

    context 'with a synthetic nil file body and filename metadata' do
      let(:file_response) { response(200, nil, 'inline; filename="file.txt"') }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('fails run without producing loot') { run_failure(/file response/i) }
    end

    context 'with a synthetic HTTP error containing a vulnerable version string' do
      let(:root_response) { response(503, 'OneDev 11.0.8') }

      it('returns Unknown') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
    end

    context 'when the transport raises an expected connection exception' do
      before { allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionError) }

      it('returns Unknown from check') { expect(mod.check).to eq(Msf::Exploit::CheckCode::Unknown) }
      it('reports an operation failure from run') { run_failure(/connect|request/i) }
    end
  end
end
