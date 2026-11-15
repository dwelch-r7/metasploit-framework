require 'rspec'
require 'msfenv'
require 'msf/base'
require 'msf/core/exploit/remote/http/wordpress'

load ENV['WORDPRESS_USERS_SOURCE'] if ENV['WORDPRESS_USERS_SOURCE']

RSpec.describe 'POST SMTP account takeover response contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('POST_SMTP_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/admin/http/wp_post_smtp_acct_takeover.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:fixture_path) { File.expand_path('../../../../file_fixtures/modules/auxiliary/admin/http/wp_post_smtp_acct_takeover/responses.json', __dir__) }
  let(:captures) { JSON.parse(File.read(fixture_path)).fetch('responses') }
  let(:replies) { successful_replies }
  let(:requests) { [] }
  let(:messages) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/', 'USERNAME' => 'module_admin', 'AutoCheck' => false)
    allow(mod).to receive(:wordpress_and_online?).and_return(true)
    allow(mod).to receive(:wordpress_user_exists?).with('module_admin').and_return(true)
    allow(mod).to receive(:report_wordpress_service)
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:print_good) { |message| messages << message }
    %i[print_status print_warning print_error vprint_status vprint_error elog].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:store_loot).and_return('/tmp/unit-reset.log')
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(10..16).and_return('unit-token', 'unit-device', 'unit-token', 'unit-device')
    # HTTP, passive product discovery, username existence, reporting and loot I/O are doubles.
    # Real Rex JSON/URI handling, version comparisons, reset helper and AutoCheck run.
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      replies.shift
    end
  end

  def captured_response(key)
    capture = captures.fetch(key)
    response(capture.fetch('status'), capture.fetch('body'), capture.fetch('headers'))
  end

  def response(code, body = '', headers = {})
    Rex::Proto::Http::Response.new(code).tap do |result|
      result.body = body
      headers.each { |key, value| result.headers[key] = value }
    end
  end

  def successful_replies
    result = %w[2.8.6-register-device-without-auth 2.8.6-password-reset 2.8.6-disclosed-logs 2.8.6-disclosed-log-content].map { |key| captured_response(key) }
    # Legacy HTTP 200 isolates log/registration guards from the separate 302 regression.
    result[1] = response(200)
    result
  end

  def rejected(reason)
    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed)
    expect(mod.fail_reason).to eq(reason)
    expect(messages.grep(/\AReset URL:/)).to be_empty
  end

  it 'prints the captured reset URL after the genuine HTTP 302 reset response' do
    replies[1] = captured_response('2.8.6-password-reset')
    mod.run
    expect(messages.map(&:strip)).to include('Reset URL: http://192.0.2.10/wp-login.php?login=module_admin&key=unit-reset-key&action=rp&wp_lang=en_US')
    expect(mod).to have_received(:store_loot).with('wordpress.post_smtp.log', 'text/plain', '192.0.2.10', captures.fetch('2.8.6-disclosed-log-content').fetch('body'), '1.log')
  end

  it 'preserves a legacy HTTP 200 reset response' do
    replies[1] = response(200)
    mod.run
    expect(messages.grep(/\AReset URL:/).size).to eq(1)
  end

  it 'uses TARGETURI for every request and preserves operator settings' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    replies[1] = response(302, '', 'Location' => '/wordpress/wp-login.php?checkemail=confirm')
    settings = mod.datastore.to_h.dup
    mod.run
    expect(requests.map { |options| options.fetch('uri') }).to eq(['/wordpress/wp-json/post-smtp/v1/connect-app', '/wordpress/wp-login.php', '/wordpress/wp-json/post-smtp/v1/get-logs', '/wordpress/wp-admin/admin.php'])
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'can run twice on the same instance without retaining request state' do
    replies.concat(successful_replies)
    2.times { mod.run }
    expect(messages.grep(/\AReset URL:/).size).to eq(2)
    expect(requests.size).to eq(8)
  end

  { '2.8.6' => Msf::Exploit::CheckCode::Appears, '2.8.7' => Msf::Exploit::CheckCode::Appears, '2.8.8' => Msf::Exploit::CheckCode::Safe }.each do |version, expected|
    it "classifies tagged version #{version}" do
      replies.replace([captured_response(version + '-readme')])
      expect(mod.check).to eq(expected)
    end
  end

  it 'permits the affected 2.8.7 path through real AutoCheck' do
    mod.datastore['AutoCheck'] = true
    replies.unshift(captured_response('2.8.7-readme'))
    mod.run
    expect(messages.grep(/\AReset URL:/).size).to eq(1)
  end

  it 'keeps the patched version blocked by AutoCheck' do
    mod.datastore['AutoCheck'] = true
    replies.replace([captured_response('2.8.8-readme')])
    rejected(Msf::Module::Failure::NotVulnerable)
    expect(requests.size).to eq(1)
  end

  it 'does not claim a known version when the readme has no version' do
    replies.replace([response(200, 'No stable tag')])
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Detected)
  end

  it 'rejects the captured HTTP 200 registration denial before sending a reset' do
    replies.replace([captured_response('2.8.8-register-device-without-auth')])
    rejected(Msf::Module::Failure::NoAccess)
    expect(requests.size).to eq(1)
    expect(messages.grep(/Successfully created token/)).to be_empty
  end

  {
    'unanswered registration' => nil,
    'malformed registration JSON' => '{',
    'null registration JSON' => 'null',
    'array registration JSON' => '[]',
    'missing registration success' => '{}',
    'missing returned token' => '{"success":true,"data":{}}',
    'mismatched returned token' => '{"success":true,"data":{"fcm_token":"foreign-token"}}'
  }.each do |label, body|
    it "handles #{label}" do
      replies.replace([body ? response(200, body) : nil])
      rejected(body ? Msf::Module::Failure::UnexpectedReply : Msf::Module::Failure::Unreachable)
      expect(requests.size).to eq(1)
    end
  end

  it 'distinguishes HTTP authentication denial during registration' do
    replies.replace([response(401)])
    rejected(Msf::Module::Failure::NoAccess)
  end

  it 'does not request logs after an unconfirmed reset' do
    replies[1] = response(302, '', 'Location' => '/unrelated')
    rejected(Msf::Module::Failure::UnexpectedReply)
    expect(requests.size).to eq(2)
  end

  {
    'malformed log JSON' => '{',
    'null log JSON' => 'null',
    'non-object log JSON' => '[]',
    'missing log data' => '{"success":true}',
    'object log data' => '{"success":true,"data":{}}',
    'non-object first log' => '{"success":true,"data":[null]}',
    'missing log ID' => '{"success":true,"data":[{}]}',
    'invalid log ID' => '{"success":true,"data":[{"id":"../other"}]}'
  }.each do |label, body|
    it "handles #{label} without dereferencing it" do
      replies[2] = response(200, body)
      rejected(Msf::Module::Failure::UnexpectedReply)
      expect(requests.size).to eq(3)
    end
  end

  it 'explains an empty log list' do
    replies[2] = response(200, '{"success":true,"data":[]}')
    rejected(Msf::Module::Failure::NotFound)
    expect(mod.fail_detail).to match(/logging/i)
  end

  it 'handles a captured API authentication error while requesting logs' do
    replies[2] = captured_response('2.8.8-logs-with-rejected-token')
    rejected(Msf::Module::Failure::NoAccess)
  end

  it 'handles a log API denial carried by HTTP 200' do
    replies[2] = response(200, '{"success":false,"data":{"error":"Denied"}}')
    rejected(Msf::Module::Failure::NoAccess)
  end

  it 'keeps a missing reset URL as an explicit failure after saving loot' do
    replies[3] = response(200, '<html>No reset URL</html>')
    rejected(Msf::Module::Failure::NotFound)
    expect(mod).to have_received(:store_loot)
  end

  it 'handles denied log content' do
    replies[3] = response(403)
    rejected(Msf::Module::Failure::NoAccess)
  end

  it 'handles unanswered log content' do
    replies[3] = nil
    rejected(Msf::Module::Failure::Unreachable)
  end

  it 'converts an escaping check TLS error into a reason-bearing Unknown' do
    allow(mod).to receive(:send_request_cgi).and_call_original
    allow(mod).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'Controlled handshake failure')
    result = mod.check
    expect(result).to eq(Msf::Exploit::CheckCode::Unknown)
    expect(result.reason).to include('TLS')
  end

  it 'handles an escaping run TLS error' do
    allow(mod).to receive(:send_request_cgi).and_call_original
    allow(mod).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'Controlled handshake failure')
    rejected(Msf::Module::Failure::Unreachable)
  end

  it 'uses the real HttpClient nil-on-connection-error behavior during registration' do
    allow(mod).to receive(:send_request_cgi).and_call_original
    allow(mod).to receive(:connect).and_raise(Rex::ConnectionRefused)
    rejected(Msf::Module::Failure::Unreachable)
  end
end
