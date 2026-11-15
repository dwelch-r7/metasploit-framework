require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'WPS Hide Login redirect validation' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('WPS_LOGIN_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_wps_hide_login_revealer.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:fixture_root) { File.expand_path('../../../../file_fixtures/modules/auxiliary/scanner/http/wp_wps_hide_login_revealer', __dir__) }
  let(:capture) { JSON.parse(File.read(File.join(fixture_root, 'provenance.json'))) }
  let(:location) { capture.fetch('root_location') }
  let(:body) { File.read(File.join(fixture_root, 'root-login-form.html')) }
  let(:probe) { response(302, '', 'Location' => location) }
  let(:validation) { response(200, body) }
  let(:replies) { [probe, validation] }
  let(:requests) { [] }
  let(:messages) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/')
    allow(mod).to receive(:wordpress_and_online?).and_return(true)
    allow(mod).to receive(:check_plugin_version_from_readme).with('wps-hide-login', '1.9.1').and_return(Msf::Exploit::CheckCode::Appears('Version 1.9'))
    allow(mod).to receive(:print_good) { |message| messages << message }
    %i[print_status print_warning print_error vprint_error elog].each { |method| allow(mod).to receive(method) }
    # HTTP responses and passive WordPress/version discovery are doubles.
    # Rex responses, HTML parsing and redirect/origin logic remain real.
    allow(mod).to receive(:send_request_cgi) do |options, *_arguments|
      requests << options.dup
      replies.shift
    end
  end

  def response(code, body = '', headers = {})
    Rex::Proto::Http::Response.new(code).tap do |reply|
      reply.body = body
      headers.each { |key, value| reply.headers[key] = value unless value.nil? }
    end
  end

  def rejected(reason)
    expect { mod.run_host('192.0.2.10') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed) { |error| expect(error.message).to start_with("#{reason}:") }
    expect(messages.grep(/\ALogin page:/)).to be_empty
  end

  it 'validates the captured root disclosure including its query' do
    mod.run_host('192.0.2.10')
    expect(messages).to include("Login page: #{location}")
    expect(requests.size).to eq(2)
  end

  it 'preserves query bytes and operator settings while verifying with GET' do
    settings = mod.datastore.to_h.dup
    mod.run_host('192.0.2.10')
    expect(requests.last).to include('method' => 'GET', 'uri' => '/module-login-alpha/', 'query' => 'redirect_to=%2Fwp-admin%2Fprobe1&reauth=1')
    expect(requests.last.fetch('headers', {})).not_to have_key('Referer')
    expect(mod.datastore.to_h).to eq(settings)
  end

  context 'with the actual prefix concealment redirect' do
    let(:location) { capture.fetch('prefix_location') }
    let(:validation) { response(404, File.read(File.join(fixture_root, 'prefix-not-found.html'))) }

    it 'refuses the non-login destination' do
      mod.datastore['TARGETURI'] = '/wordpress/'
      rejected(Msf::Module::Failure::NotVulnerable)
      expect(requests.last.fetch('uri')).to eq('/wordpress/404/')
    end
  end

  it 'accepts the captured prefix form under a synthetic disclosed prefix URL' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    address = 'http://192.0.2.10/wordpress/module-login-beta/'
    replies.replace([response(302, '', 'Location' => address), response(200, File.read(File.join(fixture_root, 'prefix-login-form.html')))])
    mod.run_host('192.0.2.10')
    expect(messages).to include("Login page: #{address}")
  end

  {
    'absolute path' => ['/module-login-alpha/?reauth=1', '/module-login-alpha/', 'reauth=1'],
    'relative parent' => ['../module-login-alpha/', '/module-login-alpha/', ''],
    'relative sibling' => ['module-login-alpha/', '/wp-admin/module-login-alpha/', ''],
    'scheme-relative same origin' => ['//192.0.2.10/module-login-alpha/', '/module-login-alpha/', ''],
    'query-only' => ['?reauth=1', '/wp-admin/options.php', 'reauth=1']
  }.each do |label, (value, path, query)|
    context "with a synthetic #{label} location" do
      let(:location) { value }

      it 'resolves against the options request' do
        mod.run_host('192.0.2.10')
        expect(requests.last).to include('uri' => path, 'query' => query)
      end
    end
  end

  {
    'foreign host' => 'http://198.51.100.20/login/',
    'foreign authority' => '//198.51.100.20/login/',
    'changed port' => 'http://192.0.2.10:8080/login/',
    'changed scheme' => 'https://192.0.2.10/login/',
    'embedded credentials' => 'http://user:password@192.0.2.10/login/',
    'non-HTTP scheme' => 'javascript:alert(1)',
    'malformed URI' => 'http://[invalid/login',
    'empty location' => '', 'missing location' => nil
  }.each do |label, value|
    context "with #{label}" do
      let(:location) { value }

      it 'refuses before any follow-up request' do
        rejected(Msf::Module::Failure::UnexpectedReply)
        expect(requests.size).to eq(1)
      end
    end
  end

  it 'handles an unanswered probe' do
    replies.replace([nil])
    rejected(Msf::Module::Failure::Unreachable)
  end
  it 'refuses a non-302 probe' do
    replies.replace([response(200, body)])
    rejected(Msf::Module::Failure::NotVulnerable)
  end
  it 'handles unanswered verification' do
    replies.replace([probe, nil])
    rejected(Msf::Module::Failure::Unreachable)
  end
  it 'distinguishes a verification server error' do
    replies.replace([probe, response(500)])
    rejected(Msf::Module::Failure::UnexpectedReply)
  end
  [401, 403].each do |code|
    it "distinguishes denied verification HTTP #{code}" do
      replies.replace([probe, response(code)])
      rejected(Msf::Module::Failure::NoAccess)
    end
  end

  it 'does not accept HTTP 200 alone' do
    replies.replace([probe, response(200, File.read(File.join(fixture_root, 'prefix-not-found.html')))])
    rejected(Msf::Module::Failure::NotVulnerable)
  end

  it 'follows one same-origin canonical slash redirect' do
    replies.replace([response(302, '', 'Location' => '/module-login-alpha'), response(301, '', 'Location' => '/module-login-alpha/'), validation])
    mod.run_host('192.0.2.10')
    expect(messages).to include('Login page: http://192.0.2.10/module-login-alpha/')
    expect(requests.size).to eq(3)
  end

  it 'does not follow a foreign verification redirect' do
    replies.replace([probe, response(302, '', 'Location' => 'http://198.51.100.20/login/')])
    rejected(Msf::Module::Failure::UnexpectedReply)
    expect(requests.size).to eq(2)
  end

  {
    'missing password' => ->(html) { html.sub('name="pwd"', 'name="other"') },
    'wrong password type' => ->(html) { html.sub('type="password"', 'type="text"') },
    'GET form' => ->(html) { html.sub('method="post"', 'method="get"') },
    'foreign form action' => ->(html) { html.sub('action="http://192.0.2.10/', 'action="http://198.51.100.20/') },
    'malformed form action' => ->(html) { html.sub(/action="[^"]*"/, 'action="http://[invalid"') }
  }.each do |label, transform|
    it "rejects a synthetic #{label} variant" do
      replies.replace([probe, response(200, transform.call(body))])
      rejected(Msf::Module::Failure::NotVulnerable)
    end
  end

  it 'does not depend on core IDs, classes or English labels' do
    html = body.gsub(/\s(?:id|class)="[^"]*"/, '').gsub('Username or Email Address', 'Utilisateur')
    replies.replace([probe, response(200, html)])
    mod.run_host('192.0.2.10')
    expect(messages).to include("Login page: #{location}")
  end

  it 'accepts a relative form action' do
    replies.replace([probe, response(200, body.sub('action="http://192.0.2.10/module-login-alpha/"', 'action="./"'))])
    mod.run_host('192.0.2.10')
    expect(messages).to include("Login page: #{location}")
  end

  it 'honors VHOST for same-origin checks' do
    mod.datastore['VHOST'] = 'blog.example.test'
    address = location.sub('192.0.2.10', 'blog.example.test')
    replies.replace([response(302, '', 'Location' => address), response(200, body.gsub('192.0.2.10', 'blog.example.test'))])
    mod.run_host('192.0.2.10')
    expect(messages).to include("Login page: #{address}")
  end

  it 'preserves the fixed-version refusal' do
    allow(mod).to receive(:check_plugin_version_from_readme).and_return(Msf::Exploit::CheckCode::Safe('Version 1.9.1'))
    rejected(Msf::Module::Failure::NotVulnerable)
    expect(requests).to eq([])
  end

  it 'preserves unrelated-product refusal' do
    allow(mod).to receive(:wordpress_and_online?).and_return(false)
    rejected(Msf::Module::Failure::NotVulnerable)
    expect(requests).to eq([])
  end

  it 'uses the actual HttpClient nil-on-connection-error contract' do
    allow(mod).to receive(:send_request_cgi).and_call_original
    allow(mod).to receive(:connect).and_raise(Rex::ConnectionRefused)
    rejected(Msf::Module::Failure::Unreachable)
  end

  it 'handles escaping TLS errors' do
    allow(mod).to receive(:send_request_cgi).and_call_original
    allow(mod).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'Controlled handshake failure')
    rejected(Msf::Module::Failure::Unreachable)
  end
end
