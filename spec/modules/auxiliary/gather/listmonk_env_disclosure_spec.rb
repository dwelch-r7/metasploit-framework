require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'Listmonk environment disclosure check' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/listmonk_env_disclosure') }

  let(:modules_path) { ENV.fetch('LISTMONK_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('listmonk-check-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) do
    JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/listmonk/check_responses.json', __dir__)))
  end
  let(:login_page) { captured_response('login_page') }
  let(:login_response) { captured_response('login_accepted') }
  let(:about_response) { captured_response('5.0.1', section: 'captures') }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['USERNAME'] = 'labadmin'
    mod.datastore['PASSWORD'] = 'module-target-admin-password'
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => '/admin/login')).and_return(login_page)
    allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'POST', 'uri' => '/admin/login')).and_return(login_response)
    allow(mod).to receive(:send_request_cgi).with({ 'method' => 'GET', 'uri' => '/api/about' }).and_return(about_response)
  end

  %w[4.0.0 5.0.1 5.0.2].each do |version|
    context "with the native #{version} version response" do
      let(:about_response) { captured_response(version, section: 'captures') }

      it 'retains the affected/fixed boundary' do
        result = mod.check
        expected = version == '5.0.2' ? 'safe' : 'appears'
        expect([result.code, result.reason.include?(version)]).to eq([expected, true])
      end
    end
  end

  context 'with the native rejected password response' do
    let(:login_response) { captured_response('login_denied') }

    it 'returns a reason-bearing Unknown instead of raising the auxiliary failure' do
      expect_check('unknown', 'Authentication failed')
    end

    it 'keeps the run/login failure contract unchanged' do
      expect { mod.login }.to raise_error(Msf::Auxiliary::Failed, /Login failed with code 200/)
    end
  end

  context 'when the login page does not respond' do
    let(:login_page) { nil }

    it 'identifies the failed login connection' do
      expect_check('unknown', 'Login failed: Connection failed')
    end
  end

  context 'when the credential submission does not respond' do
    let(:login_response) { nil }

    it 'identifies the failed credential-submission connection' do
      expect_check('unknown', 'Login failed: Connection failed during login')
    end
  end

  context 'with a login page missing its nonce' do
    let(:login_page) { response(200, '<html>Unrelated login page</html>') }

    it 'identifies the unusable login page' do
      expect_check('unknown', 'Login failed: Could not extract nonce from login page')
    end
  end

  context 'when the version endpoint does not respond' do
    let(:about_response) { nil }

    it('returns Unknown') { expect_check('unknown', 'Connection failed') }
  end

  context 'when the version endpoint denies access' do
    let(:about_response) { response(403, '{"message":"permission denied"}') }

    it('returns Unknown') { expect_check('unknown', 'Could not determine if target is running Listmonk') }
  end

  # Deliberately synthetic malformed API bodies exercise nullable/parser contracts.
  ['not-json', 'null', 'false', '[]', '"5.0.1"', '42'].each do |body|
    context "with a non-object version response #{body}" do
      let(:about_response) { response(200, body) }

      it('returns Unknown without a parser or type exception') { expect_check('unknown', 'Failed to parse version information') }
    end
  end

  [nil, false, 501, [], {}, '', 'not-a-release'].each do |version|
    context "with an unusable version value #{version.inspect}" do
      let(:about_response) { response(200, JSON.generate('version' => version)) }

      it('returns Unknown without classifying the target safe') { expect_check('unknown', 'Failed to parse version information') }
    end
  end

  { '3.9.9' => 'safe', '4.0.0' => 'appears', 'v5.0.1' => 'appears', '5.0.2' => 'safe', 'v5.1.0' => 'safe' }.each do |version, code|
    context "with synthetic boundary version #{version}" do
      let(:about_response) { response(200, JSON.generate('version' => version)) }

      it 'preserves version comparison' do
        expect(mod.check.code).to eq(code)
      end
    end
  end

  def response(status, body)
    result = Rex::Proto::Http::Response.new(status)
    result.body = body
    result
  end

  def captured_response(name, section: nil)
    capture = section ? captures.fetch(section).fetch(name) : captures.fetch(name)
    request = capture.fetch('request')
    response(request.fetch('status'), Base64.strict_decode64(request.fetch('body_base64')))
  end

  def expect_check(code, reason)
    result = mod.check
    expect([result.code, result.reason]).to eq([code, reason])
  end
end
