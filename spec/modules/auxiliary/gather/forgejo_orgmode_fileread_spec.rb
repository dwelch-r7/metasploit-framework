require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'Forgejo org-mode file read output and reporting' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/forgejo_orgmode_fileread_cve_2026_59774') }

  let(:modules_path) { ENV.fetch('FORGEJO_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('forgejo-file-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) { JSON.parse(File.binread(File.expand_path('../../../file_fixtures/modules/auxiliary/forgejo_file/responses.json', __dir__))) }
  let(:file_kind) { 'unicode' }
  let(:file_capture) { captures.fetch('files').fetch(file_kind) }
  let(:rendered_response) { response_from(file_capture.fetch('rendered')) }
  let(:expected_text) { file_capture.fetch('text') }

  # Network, console, database reporting and loot persistence are unit doubles.
  # HTML response bytes and expected text come from the native capture.
  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['USERNAME'] = 'module-user'
    mod.datastore['PASSWORD'] = 'test-password'
    mod.datastore['REPO'] = 'module-user/private-test'
    mod.datastore['FILEPATH'] = file_capture.fetch('path')
    mod.datastore['AutoCheck'] = false
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_warning)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_line)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:store_loot).and_return('/tmp/forgejo-test-loot.txt')
    allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'POST', 'uri' => '/api/v1/markup')).and_return(rendered_response)
  end

  describe '#extract_content' do
    it 'decodes the native UTF-8 fragment without a meta charset declaration' do
      expect(mod.extract_content(rendered_response)).to eq(expected_text)
    end

    it 'retains the native rendered Unicode byte count' do
      expect(mod.extract_content(rendered_response).bytesize).to eq(30)
    end

    it 'preserves the original response body and its binary encoding' do
      original_body = rendered_response.body
      mod.extract_content(rendered_response)
      expect(rendered_response.body).to equal(original_body)
      expect(rendered_response.body.encoding).to eq(Encoding::ASCII_8BIT)
    end

    context 'with the native ASCII HTML entities' do
      let(:file_kind) { 'short' }

      it 'decodes ampersands, tags and quotes' do
        expect(mod.extract_content(rendered_response)).to eq(expected_text)
      end
    end

    context 'with the native file lacking a final newline' do
      let(:file_kind) { 'no_newline' }

      it 'preserves the rendered text without appending a newline' do
        expect(mod.extract_content(rendered_response)).to eq(expected_text)
      end
    end

    context 'with the native empty-file rendering' do
      let(:file_kind) { 'empty' }

      it('retains the unsuccessful-read sentinel') { expect(mod.extract_content(rendered_response)).to be_nil }
    end

    context 'with the native missing-file rendering' do
      let(:rendered_response) { response_from(captures.fetch('missing')) }

      it('retains the unsuccessful-read sentinel') { expect(mod.extract_content(rendered_response)).to be_nil }
    end

    context 'with a synthetic whitespace-only code element' do
      let(:rendered_response) { response(200, "<pre><code> \t\n</code></pre>") }

      it('retains the unsuccessful-read sentinel') { expect(mod.extract_content(rendered_response)).to be_nil }
    end

    context 'with a synthetic unrelated HTML document' do
      let(:rendered_response) { response(200, '<p>No file content</p>') }

      it('does not treat page text as a file') { expect(mod.extract_content(rendered_response)).to be_nil }
    end

    context 'with a frozen copy of the captured response body' do
      before { rendered_response.body.freeze }

      it('parses without mutating the body string') { expect(mod.extract_content(rendered_response)).to eq(expected_text) }
    end
  end

  describe '#run' do
    it 'prints the native Unicode text' do
      mod.run
      expect(mod).to have_received(:print_line).with(expected_text)
    end

    it 'prints the native rendered Unicode byte count' do
      mod.run
      expect(mod).to have_received(:print_good).with("Successfully read #{file_capture.fetch('path')} (30 bytes)")
    end

    it 'stores the exact rendered text with the requested file path' do
      mod.run
      expect(mod).to have_received(:store_loot).with('forgejo.file', 'text/plain', '192.0.2.1', expected_text, file_capture.fetch('path'), 'File read via CVE-2026-59774')
    end

    it 'reports the HTTP service before the confirmed vulnerability when AutoCheck is disabled' do
      expect(mod).to receive(:report_service).with(host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http').ordered
      expect(mod).to receive(:report_vuln).with(hash_including(info: "Arbitrary file read confirmed: #{file_capture.fetch('path')}")).ordered
      mod.run
    end

    it 'reads again and reports the service on a second invocation' do
      mod.run
      mod.run
      expect(mod).to have_received(:report_service).with(host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http').twice
    end

    context 'with loot disabled' do
      before { mod.datastore['STORE_LOOT'] = false }

      it 'still reports a confirmed HTTP read without storing loot' do
        mod.run
        expect(mod).to have_received(:report_service).with(host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http')
        expect(mod).not_to have_received(:store_loot)
      end
    end

    context 'with the native filename containing a space' do
      let(:file_kind) { 'space_name' }

      it 'preserves the file path and repository in the JSON request' do
        expect(mod).to receive(:send_request_cgi) do |request|
          expect(JSON.parse(request.fetch('data'))).to eq(
            'Mode' => 'file', 'Text' => "#+INCLUDE: \"#{file_capture.fetch('path')}\" src text",
            'FilePath' => 'include.org', 'Context' => 'module-user/private-test'
          )
          rendered_response
        end
        mod.run
      end
    end

    context 'with AutoCheck enabled' do
      before do
        mod.datastore['AutoCheck'] = true
        allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => '/api/v1/version')).and_return(response_from(captures.fetch('version')))
        # Synthetic accepted-authentication status; account details are unused.
        allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => '/api/v1/user')).and_return(response(200, '{}'))
      end

      it 'preserves the version service report and omits an info overwrite after reading' do
        expect(mod).to receive(:report_service).with(host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http', info: 'Forgejo 15.0.5+gitea-1.22.0').ordered
        expect(mod).to receive(:report_service).with(host: '192.0.2.1', port: 3000, proto: 'tcp', name: 'http').ordered
        mod.run
      end

      it 'retains the passive AutoCheck report alongside the confirmed file-read report' do
        mod.run
        expect(mod).to have_received(:report_vuln).with(hash_including(name: mod.fullname, check_code: Msf::Exploit::CheckCode::Appears))
        expect(mod).to have_received(:report_vuln).with(hash_including(info: "Arbitrary file read confirmed: #{file_capture.fetch('path')}"))
      end
    end

    context 'with the native missing-file response' do
      let(:rendered_response) { response_from(captures.fetch('missing')) }

      it 'does not report or store an unconfirmed read with AutoCheck disabled' do
        mod.run
        expect_no_confirmed_read
      end
    end

    context 'with the native whitespace-file response' do
      let(:file_kind) { 'whitespace' }

      it 'does not report or store an unconfirmed read with AutoCheck disabled' do
        mod.run
        expect_no_confirmed_read
      end
    end

    context 'with the native authentication refusal' do
      let(:rendered_response) { response_from(captures.fetch('denied')) }

      it 'retains the authentication failure without reporting a successful read' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Authentication failed/)
        expect_no_confirmed_read
      end
    end

    context 'with a synthetic absent HTTP response' do
      let(:rendered_response) { nil }

      it 'does not report or store an unconfirmed read' do
        mod.run
        expect_no_confirmed_read
      end
    end

    context 'with a synthetic quoted file path' do
      before { mod.datastore['FILEPATH'] = '/tmp/quote"name.txt' }

      it 'retains the option rejection without sending or reporting a read' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /FILEPATH must not contain double-quote/)
        expect(mod).not_to have_received(:send_request_cgi)
        expect_no_confirmed_read
      end
    end
  end

  def response(status, body)
    result = Rex::Proto::Http::Response.new(status)
    result.body = body.b
    result
  end

  def response_from(capture)
    result = response(capture.fetch('status'), Base64.strict_decode64(capture.fetch('body_base64')))
    capture.fetch('headers').each { |name, value| result.headers[name] = value }
    result
  end

  def expect_no_confirmed_read
    expect(mod).not_to have_received(:report_service)
    expect(mod).not_to have_received(:report_vuln)
    expect(mod).not_to have_received(:store_loot)
    expect(mod).not_to have_received(:print_good)
  end
end
