require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'Selenium file read lifecycle' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/selenium_file_read') }

  let(:modules_path) { ENV.fetch('SELENIUM_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('selenium-file-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) { JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/selenium_file/responses.json', __dir__))) }
  let(:profile_name) { 'firefox3' }
  let(:profile) { captures.fetch('profiles').fetch(profile_name) }
  let(:create_response) { captured_response('create') }
  let(:navigation_response) { captured_response('navigate') }
  let(:source_response) { captured_response('source') }
  let(:delete_response) { captured_response('delete') }
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
        request.fetch('uri').end_with?('/url') ? navigation_response : create_response
      when 'GET'
        source_response
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

  def deletion_requests
    requests.select { |request| request.fetch('method') == 'DELETE' }
  end

  def response(status, body)
    result = Rex::Proto::Http::Response.new(status)
    result.body = body
    result
  end

  def captured_response(name)
    capture = profile.fetch(name).fetch('request')
    response(capture.fetch('status'), Base64.strict_decode64(capture.fetch('body_base64')))
  end
end
