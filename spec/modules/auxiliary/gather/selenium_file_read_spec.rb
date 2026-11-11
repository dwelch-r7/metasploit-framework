require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.shared_context 'Selenium native response fixtures' do
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/selenium_file/responses.json', __dir__))) }

  def response(status, body)
    result = Rex::Proto::Http::Response.new(status)
    result.body = body
    result
  end

  def recorded_response(record)
    capture = record.fetch('request')
    response(capture.fetch('status'), Base64.strict_decode64(capture.fetch('body_base64')))
  end

  def captured_document(record)
    JSON.parse(Base64.strict_decode64(record.fetch('request').fetch('body_base64')))
  end
end

RSpec.describe 'Selenium file read lifecycle' do
  include_context 'Msf::Simple::Framework#modules loading'
  include_context 'Selenium native response fixtures'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/selenium_file_read') }

  let(:modules_path) { ENV.fetch('SELENIUM_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('selenium-file-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:profile_name) { 'firefox3' }
  let(:profile) { captures.fetch('profiles').fetch(profile_name) }
  let(:create_response) { captured_response('create') }
  let(:navigation_response) { captured_response('navigate') }
  let(:source_response) { captured_response('source') }
  let(:delete_response) { captured_response('delete') }
  let(:current_url_response) { response(200, '{"value":"about:blank"}') }
  let(:execution_response) { response(200, '{"value":null}') }
  let(:requests) { [] }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['AutoCheck'] = false
    mod.datastore['BROWSER'] = profile.fetch('browser')
    mod.datastore['FILEPATH'] = profile.fetch('path')
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_warning)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:send_request_cgi) do |request, *_timeouts|
      requests << request
      case request.fetch('method')
      when 'POST'
        if request.fetch('uri').end_with?('/url')
          navigation_response
        elsif request.fetch('uri').end_with?('/execute', '/execute/sync')
          execution_response
        else
          create_response
        end
      when 'GET'
        request.fetch('uri').end_with?('/url') ? current_url_response : source_response
      when 'DELETE'
        delete_response
      end
    end
  end

  %w[firefox3 firefox4 chrome4 edge4].each do |name|
    context "with native #{name} replies" do
      let(:profile_name) { name }

      it 'prints the actual browser-rendered file text' do
        mod.run
        expect(mod).to have_received(:print_good).with("#{profile.fetch('path')}\n#{profile.fetch('text')}")
      end

      it 'deletes only its returned browser session through a supported endpoint without check' do
        mod.run
        prefix = profile_name == 'firefox3' ? ['/wd/hub/session/'] : ['/session/', '/wd/hub/session/']
        supported = prefix.map { |path| path + profile.fetch('session_id') }
        expect(deletion_requests.length).to eq(1)
        expect(supported).to include(deletion_requests.first.fetch('uri'))
      end
    end
  end

  context 'with the native empty-file document' do
    let(:source_response) { captured_response('empty_source') }

    before { mod.datastore['FILEPATH'] = profile.fetch('empty_path') }

    it 'accepts an existing empty pre element as a successful empty read' do
      mod.run
      expect(mod).to have_received(:print_good).with("#{profile.fetch('empty_path')}\n")
    end
  end

  context 'with the native UTF-8 file document' do
    let(:source_response) { captured_response('unicode_source') }

    before { mod.datastore['FILEPATH'] = profile.fetch('unicode_path') }

    it 'preserves browser-decoded Unicode text' do
      mod.run
      expect(mod).to have_received(:print_good).with("#{profile.fetch('unicode_path')}\n#{profile.fetch('unicode_text')}")
    end
  end

  %w[missing denied].each do |name|
    context "with the native #{name} navigation error" do
      let(:navigation_response) { captured_response("#{name}_navigation") }

      it 'fails without printing a successful file read' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(mod).not_to have_received(:print_good)
      end

      it 'still deletes the known browser session' do
        begin
          mod.run
        rescue Msf::Auxiliary::Failed
          # The requested file failure must not skip browser cleanup.
        end
        expect(deletion_requests.map { |request| request.fetch('uri') }).to eq(["/wd/hub/session/#{profile.fetch('session_id')}"])
      end
    end
  end

  context 'with a native error page after a synthetically successful navigation' do
    let(:source_response) { captured_response('missing_source') }

    it 'rejects a document without a pre element rather than printing a blank success' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Failed to read file/)
      expect(mod).not_to have_received(:print_good)
    end
  end

  context 'when navigation does not respond' do
    let(:navigation_response) { nil }

    it 'releases the known session after the connection failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
      expect(deletion_requests.length).to eq(1)
    end
  end

  context 'when page-source retrieval does not respond' do
    let(:source_response) { nil }

    it 'releases the known session after the connection failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
      expect(deletion_requests.length).to eq(1)
    end
  end

  it 'uses the compatible cleanup endpoint on two unchecked executions' do
    2.times { mod.run }
    expect(deletion_requests.map { |request| request.fetch('uri') }).to eq(["/wd/hub/session/#{profile.fetch('session_id')}"] * 2)
  end

  context 'when session creation does not respond' do
    let(:create_response) { nil }

    it 'does not discover or delete an unknown session after the lost response' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
      expect(requests.map { |request| request.fetch('method') }).to eq(['POST'])
    end
  end

  context 'with a synthetic JSON Wire top-level session ID' do
    let(:create_response) { response(200, JSON.generate('sessionId' => profile.fetch('session_id'), 'status' => 0, 'value' => {})) }

    it 'preserves compatibility with the top-level ID shape' do
      mod.run
      expect(mod).to have_received(:print_good)
    end
  end

  # These malformed API replies are synthetic guards, not live target claims.
  ['null', '[]', '"not an object"', '{"value":null}', '{"value":{"sessionId":42}}'].each do |body|
    context "with synthetic unusable creation reply #{body}" do
      let(:create_response) { response(200, body) }

      it 'fails cleanly without deleting an unknown browser session' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(deletion_requests).to eq([])
      end
    end
  end

  ['{"value":{"error":"unknown error"}}', '{"status":13,"value":null}', 'not-json'].each do |body|
    context "with synthetic navigation failure #{body}" do
      let(:navigation_response) { response(200, body) }

      it 'rejects the failure and cleans up its known session' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(deletion_requests.length).to eq(1)
      end
    end
  end

  ['{"value":null}', '{"value":[]}', '{"value":42}', '{"value":{"error":"unknown error"}}', 'not-json'].each do |body|
    context "with synthetic unusable source reply #{body}" do
      let(:source_response) { response(200, body) }

      it 'fails cleanly rather than printing a file and still releases the browser' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(deletion_requests.length).to eq(1)
      end
    end
  end

  [nil, [404, '{}'], [200, '{"value":{"error":"invalid session id"}}']].each do |value|
    context "with synthetic cleanup failure #{value.inspect}" do
      let(:delete_response) { value ? response(*value) : nil }

      it 'warns without falsely claiming deletion or changing the file result' do
        mod.run
        expect(mod).to have_received(:print_warning).with(/Failed to delete/)
        expect(mod).not_to have_received(:print_status).with(/Deleted session/)
      end
    end
  end

  context 'when cleanup raises an expected transport error after a navigation error' do
    let(:navigation_response) { captured_response('missing_navigation') }
    let(:delete_response) { raise Rex::ConnectionError, 'Connection dropped' }

    it 'keeps the original file operation failure and reports cleanup separately' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Failed to navigate/)
      expect(mod).to have_received(:print_warning).with(/Failed to delete/)
    end
  end

  %w[chrome4 edge4].each do |name|
    context "with native #{name} document state" do
      let(:profile_name) { name }
      let(:states) { captures.fetch('document_states').fetch(name) }
      let(:document_name) { 'empty.txt' }
      let(:document_state) { states.fetch(document_name) }
      let(:source_response) { recorded_response(document_state.fetch('source')) }
      let(:current_url_response) { recorded_response(document_state.fetch('current_url')) }
      let(:execution_response) { recorded_response(document_state.fetch('metadata')) }

      before do
        scheme, path = document_state.fetch('requested_url').split('://', 2)
        mod.datastore['SCHEME'] = scheme
        mod.datastore['FILEPATH'] = path
      end

      %w[empty.txt empty\ space.txt redirect-empty.txt].each do |path|
        context "with the actual #{path} navigation" do
          let(:document_name) { path }

          it 'accepts the verified empty text despite its missing pre element' do
            mod.run
            expect(mod).to have_received(:print_good).with("#{mod.datastore['FILEPATH']}\n")
          end
        end
      end

      context 'with the actual blank HTML document' do
        let(:document_name) { 'blank.html' }

        it 'rejects HTML instead of treating its empty rendered text as an empty file' do
          expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
          expect(mod).not_to have_received(:print_good)
        end
      end

      # Native initial-page metadata is combined with successful navigation to
      # verify that an unrelated initial data/about page is not accepted.
      context 'with native initial-page state after synthetic navigation success' do
        let(:current_url_response) { recorded_response(states.fetch('initial').fetch('current_url')) }
        let(:execution_response) { recorded_response(states.fetch('initial').fetch('metadata')) }

        it 'rejects the initial document even when it is empty text/plain' do
          expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
          expect(mod).not_to have_received(:print_good)
        end
      end
    end
  end

  context 'with synthetic guards around the captured Chromium empty text state' do
    let(:profile_name) { 'chrome4' }
    let(:state) { captures.fetch('document_states').fetch('chrome4').fetch('empty.txt') }
    let(:source_response) { recorded_response(state.fetch('source')) }
    let(:current_url_response) { recorded_response(state.fetch('current_url')) }
    let(:execution_response) { recorded_response(state.fetch('metadata')) }

    before { mod.datastore['FILEPATH'] = state.fetch('requested_url').delete_prefix('file://') }

    context 'when driver and document URLs disagree' do
      let(:execution_response) do
        document = captured_document(state.fetch('metadata'))
        document.fetch('value')['href'] = 'file:///opt/module-target-files/another.txt'
        response(200, JSON.generate(document))
      end

      it 'rejects the unrelated document' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(mod).not_to have_received(:print_good)
      end
    end

    context 'with native nonempty plaintext state and a synthetically preless source' do
      let(:state) { captures.fetch('document_states').fetch('chrome4').fetch('short.txt') }
      let(:source_response) { recorded_response(captures.fetch('document_states').fetch('chrome4').fetch('empty.txt').fetch('source')) }

      it 'returns the verified text rather than hardcoding an empty result' do
        mod.run
        expect(mod).to have_received(:print_good).with("#{mod.datastore['FILEPATH']}\n#{state.fetch('text')}")
      end
    end

    context 'when the current URL does not respond' do
      let(:current_url_response) { nil }

      it 'fails and releases its known session' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(deletion_requests.length).to eq(1)
      end
    end

    context 'when script metadata has no text value' do
      let(:execution_response) do
        document = captured_document(state.fetch('metadata'))
        document.fetch('value')['body_text'] = nil
        response(200, JSON.generate(document))
      end

      it 'does not convert an unknown text value into empty success' do
        expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
        expect(mod).not_to have_received(:print_good)
      end
    end

    context 'with legacy JSON Wire envelopes' do
      let(:create_response) { response(200, JSON.generate('sessionId' => profile.fetch('session_id'), 'status' => 0, 'value' => {})) }
      let(:current_url_response) { response(200, JSON.generate(captured_document(state.fetch('current_url')).merge('status' => 0))) }
      let(:execution_response) { response(200, JSON.generate(captured_document(state.fetch('metadata')).merge('status' => 0))) }

      it 'uses the JSON Wire execute endpoint and preserves the empty read' do
        mod.run
        expect(requests.select { |request| request.fetch('method') == 'POST' }.map { |request| request.fetch('uri') }).to include("/wd/hub/session/#{profile.fetch('session_id')}/execute")
        expect(mod).to have_received(:print_good)
      end
    end

    context 'with a normal HTTP to HTTPS redirect' do
      let(:redirect_url) { 'https://192.0.2.1/empty.txt' }
      let(:current_url_response) { response(200, JSON.generate('value' => redirect_url)) }
      let(:execution_response) do
        document = captured_document(state.fetch('metadata'))
        document.fetch('value')['href'] = redirect_url
        response(200, JSON.generate(document))
      end

      before do
        mod.datastore['SCHEME'] = 'http'
        mod.datastore['FILEPATH'] = '192.0.2.1/redirect-empty.txt'
      end

      it 'keeps the browser effective URL instead of comparing raw request strings' do
        mod.run
        expect(mod).to have_received(:print_good).with("192.0.2.1/redirect-empty.txt\n")
      end
    end
  end

  def deletion_requests
    requests.select { |request| request.fetch('method') == 'DELETE' }
  end

  def captured_response(name)
    recorded_response(profile.fetch(name))
  end
end
