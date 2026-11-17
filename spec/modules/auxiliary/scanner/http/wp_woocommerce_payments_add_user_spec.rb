require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'

RSpec.describe 'WooCommerce Payments administrator creation responses' do
  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('WOO_PAYMENTS_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_woocommerce_payments_add_user.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:mod) { owner_class.new }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new, db: double('Database', active: true)) }
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_woocommerce_payments_add_user/create_user_responses.json')))
  end
  let(:document) { JSON.parse(capture.fetch('responses').fetch('plus_email').fetch('body')) }
  let(:username) { document.fetch('username') }
  let(:email) { document.fetch('email') }
  let(:password) { 'Module-target-public+2026!' }
  let(:response) { captured_response('plus_email') }
  let(:responses) { [response] }
  let(:requests) { [] }

  before do
    mod.datastore.merge!('RHOST' => '192.0.2.10', 'RPORT' => 8080, 'TARGETURI' => '/', 'USERNAME' => username, 'PASSWORD' => password, 'EMAIL' => email, 'ADMINID' => 1, 'AutoCheck' => false)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:fullname).and_return('auxiliary/scanner/http/wp_woocommerce_payments_add_user')
    allow(mod).to receive(:myworkspace_id).and_return(1)
    allow(mod).to receive(:create_credential_and_login)
    %i[print_status print_good print_error print_warning].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options.deep_dup
      responses.shift
    end
  end

  # The fixture retains complete native JSON and a verbatim homepage prefix.
  # Parser/mismatch cases explicitly derive synthetic variants from captures.
  # These examples execute the real owner/JSON parser with HTTP and DB doubles.

  it 'accepts the captured successful plus-address email response' do
    mod.run

    expect(mod).to have_received(:print_good).with('User was created successfully')
  end

  it 'records the exact credential after the captured plus-address response' do
    mod.run

    expect(mod).to have_received(:create_credential_and_login).with(hash_including(
      address: '192.0.2.10', port: 8080, protocol: 'tcp', workspace_id: 1,
      origin_type: :service, service_name: 'WordPress', username: username,
      private_type: :password, private_data: password,
      module_fullname: mod.fullname, access_level: 'administrator',
      status: Metasploit::Model::Login::Status::SUCCESSFUL
    ))
  end

  it 'keeps accepting the ordinary native administrator response' do
    data = JSON.parse(capture.fetch('responses').fetch('native_administrator').fetch('body'))
    mod.datastore.merge!('USERNAME' => data.fetch('username'), 'EMAIL' => data.fetch('email'))
    responses.replace([captured_response('native_administrator')])

    mod.run

    expect(mod).to have_received(:print_good).with('User was created successfully')
  end

  it 'accepts equivalent JSON with whitespace between keys and values' do
    responses.replace([http_response(JSON.pretty_generate(document))])

    mod.run

    expect(mod).to have_received(:create_credential_and_login)
  end

  it 'sends the exact input strings through the JSON encoder' do
    mod.run

    expect(JSON.parse(requests.fetch(0).fetch('data'))).to eq('username' => username, 'email' => email, 'password' => password, 'roles' => ['administrator'])
  end

  it 'tries the canonical plain REST route before a legacy path that returns the homepage' do
    data = JSON.parse(capture.fetch('responses').fetch('plain_native_administrator').fetch('body'))
    mod.datastore.merge!('USERNAME' => data.fetch('username'), 'EMAIL' => data.fetch('email'))
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options.deep_dup
      case options.fetch('uri')
      when '/wp-json/wp/v2/users'
        http_response('', code: 404) # Actual status; the body is unused.
      when '/'
        expect(options.fetch('vars_get')).to eq('rest_route' => '/wp/v2/users')
        captured_response('plain_native_administrator')
      when '/index.php/wp-json/wp/v2/users'
        captured_response('plain_legacy_homepage_prefix')
      else
        raise ArgumentError, 'Unexpected REST endpoint'
      end
    end

    mod.run

    expect(mod).to have_received(:print_good).with('User was created successfully')
    expect(requests.map { |options| options.fetch('uri') }).to eq(['/wp-json/wp/v2/users', '/'])
  end

  it 'preserves the installation subdirectory when falling back to the plain REST route' do
    mod.datastore['TARGETURI'] = '/shop/'
    responses.replace([http_response('', code: 404), response])

    mod.run

    expect(requests.map { |options| options.fetch('uri') }).to eq(['/shop/wp-json/wp/v2/users', '/shop/'])
    expect(requests.fetch(1).fetch('vars_get')).to eq('rest_route' => '/wp/v2/users')
  end

  it 'retains the legacy index.php path if both canonical routes return 404' do
    responses.replace([http_response('', code: 404), http_response('', code: 404), response])

    mod.run

    expect(requests.map { |options| options.fetch('uri') }).to eq(['/wp-json/wp/v2/users', '/', '/index.php/wp-json/wp/v2/users'])
  end

  it 'does not retry an HTTP201 response when its acknowledgement is malformed' do
    responses.replace([http_response('{invalid'), response])

    mod.run

    expect(requests.length).to eq(1)
    expect(mod).not_to have_received(:create_credential_and_login)
  end

  it 'rejects a different email that would match an unescaped dot' do
    mod.datastore['EMAIL'] = 'module-payments@example.test'
    responses.replace([http_response(JSON.generate(document.merge('email' => 'module-payments@exampleXtest')))])

    mod.run

    expect(mod).not_to have_received(:create_credential_and_login)
  end

  it 'rejects a different username that would match an unescaped dot' do
    mod.datastore.merge!('USERNAME' => 'module.payments', 'EMAIL' => 'module-payments@example.test')
    responses.replace([http_response(JSON.generate(document.merge('username' => 'moduleXpayments', 'email' => 'module-payments@example.test')))])

    mod.run

    expect(mod).not_to have_received(:create_credential_and_login)
  end

  it 'compares email fields rather than a nested matching JSON object' do
    mod.datastore['EMAIL'] = 'module-payments@example.test'
    responses.replace([http_response(JSON.generate('unrelated' => document.merge('email' => 'module-payments@example.test')))])

    mod.run

    expect(mod).not_to have_received(:create_credential_and_login)
  end

  {
    'an array' => [],
    'JSON null' => nil,
    'a JSON string' => 'unrelated',
    'a JSON number' => 7,
    'a JSON boolean' => false,
    'an empty object' => {},
    'a missing username' => { 'email' => 'module-payments+plus@example.test' },
    'a missing email' => { 'username' => 'module_payments_plus_email' },
    'a null username' => { 'username' => nil, 'email' => 'module-payments+plus@example.test' },
    'a null email' => { 'username' => 'module_payments_plus_email', 'email' => nil }
  }.each do |description, value|
    context "with #{description}" do
      let(:response) { http_response(JSON.generate(value)) }

      it 'does not claim success or persist credentials' do
        mod.run

        expect(mod).not_to have_received(:print_good)
        expect(mod).not_to have_received(:create_credential_and_login)
      end
    end
  end

  ['{invalid', ''].each do |body|
    context "with #{body.empty? ? 'empty' : 'malformed'} JSON" do
      let(:response) { http_response(body) }

      it 'rejects the response without a parser exception or credential' do
        mod.run

        expect(mod).not_to have_received(:create_credential_and_login)
      end
    end
  end

  context 'with a nil HTTP body' do
    let(:response) { http_response(nil) }

    it 'retains a normal unsuccessful result without a parser exception' do
      mod.run

      expect(mod).not_to have_received(:create_credential_and_login)
    end
  end

  [200, 400, 401, 403, 409, 500].each do |code|
    context "with HTTP #{code}" do
      let(:response) { captured_response('plus_email').tap { |value| value.code = code } }

      it 'requires completed creation before recording credentials' do
        mod.run

        expect(mod).not_to have_received(:create_credential_and_login)
        expect(requests.length).to eq(1)
      end
    end
  end

  context 'without a response' do
    let(:response) { nil }

    it 'retains the existing reasoned connection failure' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /unreachable: Connection failed/)
    end
  end

  it 'does not require a database to acknowledge successful creation' do
    allow(framework.db).to receive(:active).and_return(false)

    mod.run

    expect(mod).to have_received(:print_good).with('User was created successfully')
    expect(mod).not_to have_received(:create_credential_and_login)
  end

  def captured_response(name)
    data = capture.fetch('responses').fetch(name)
    http_response(data.fetch('body'), code: data.fetch('code'))
  end

  def http_response(body, code: 201)
    Rex::Proto::Http::Response.new(code).tap { |result| result.body = body }
  end
end
