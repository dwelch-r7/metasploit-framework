require 'rspec'
require 'rex/socket'

RSpec.describe 'Superset datasource credential reporting' do
  let(:recorded) { [] }
  let(:messages) { [] }
  let(:warnings) { [] }
  let(:options) { { 'USERNAME' => 'lab-user', 'PASSWORD' => 'module-target-public-password', 'ADMIN_ID' => 1 } }
  let(:parameters) do
    { 'host' => 'database.example.test', 'port' => 5432, 'username' => 'module_native', 'password' => 'module-target-public-database-password', 'database' => 'module_native' }
  end

  # Complete owner source, with explicit framework/reporting/HTTP/UI boundaries.
  # The reported datasource fields follow the genuine Superset 2.0.0 capture;
  # DNS/IP values are adapted to reserved test addresses. No Framework instance,
  # database, transport, cookie authentication or native target runs here.
  let(:mod) do
    auxiliary = Class.new do
      attr_accessor :datastore, :framework

      def print_status(_message); end
      def print_good(_message); end
      def vprint_status(_message); end
      def vprint_warning(_message); end
      def elog(_message, error:); end
      def send_request_cgi!(_options); end
      def send_request_cgi(_options); end
      def create_credential_and_login(_options); end
      def normalize_uri(*parts) = parts.join('/')
      def target_uri = Struct.new(:path).new('/')
      def peer = '192.0.2.1:80'
      def myworkspace_id = 7
      def fullname = 'auxiliary/gather/apache_superset_cookie_sig_priv_esc'
    end
    session = Module.new
    session.define_singleton_method(:decode) { |_cookie| { 'user_id' => 2 } }
    flask = Module.new
    flask.const_set(:Session, session)
    http = Module.new
    http.const_set(:FlaskUnsign, flask)
    remote = Module.new
    remote.const_set(:HttpClient, Module.new)
    remote.const_set(:AutoCheck, Module.new)
    remote.const_set(:HTTP, http)
    exploit = Module.new
    exploit.const_set(:Remote, remote)
    msf = Module.new
    msf.const_set(:Auxiliary, auxiliary)
    msf.const_set(:Exploit, exploit)
    status = Module.new
    status.const_set(:UNTRIED, 'Untried')
    login = Module.new
    login.const_set(:Status, status)
    model = Module.new
    model.const_set(:Login, login)
    metasploit = Module.new
    metasploit.const_set(:Model, model)
    scope = Module.new
    scope.const_set(:Msf, msf)
    scope.const_set(:Metasploit, metasploit)
    path = File.expand_path('../../../../modules/auxiliary/gather/apache_superset_cookie_sig_priv_esc.rb', __dir__)
    scope.module_eval(File.read(path), path)
    scope.const_get(:MetasploitModule).allocate
  end

  before do
    mod.datastore = options
    mod.framework = Struct.new(:db).new(Struct.new(:active).new(true))
    allow(mod).to receive(:print_good) { |message| messages << message }
    allow(mod).to receive(:vprint_warning) { |message| warnings << message }
    # Mirror the actual credential creation API's IP-only service guard. This
    # recorder proves the owner's arguments, not real SQL persistence.
    allow(mod).to receive(:create_credential_and_login) do |data|
      recorded << data if Rex::Socket.is_ip_addr?(data[:address])
    end
    login = double('Captured login boundary', code: 200, body: '<input name="csrf_token" type="hidden" value="module-target-csrf">', get_cookies: 'session=module-target-cookie;')
    datasource = double('Captured datasource boundary', code: 200, get_json_document: { 'result' => { 'database_name' => 'Module Native PostgreSQL', 'backend' => 'postgresql', 'parameters' => parameters } })
    missing = double('Missing datasource boundary', code: 404)
    allow(mod).to receive(:send_request_cgi!).and_return(login)
    allow(mod).to receive(:send_request_cgi).and_return(login, datasource, missing)
    allow(mod).to receive(:get_secret_key).and_return('module-target-public-key')
    allow(mod).to receive(:validate_cookie).and_return('module-target-admin-cookie')
  end

  it 'persists DNS datasource arguments using the independently resolved IP' do
    allow(Rex::Socket).to receive(:getaddress).with('database.example.test').and_return('192.0.2.2')

    mod.run

    expect(recorded).to contain_exactly(include(address: '192.0.2.2', port: 5432, username: 'module_native',
                                                private_data: 'module-target-public-database-password', workspace_id: 7,
                                                origin_type: :service, status: 'Untried'))
  end

  it 'keeps the original hostname in the displayed datasource URI' do
    allow(Rex::Socket).to receive(:getaddress).with('database.example.test').and_return('192.0.2.2')

    mod.run

    expect(messages).to include('Found Module Native PostgreSQL: postgresql://module_native:module-target-public-database-password@database.example.test:5432/module_native')
  end

  it 'preserves an IPv4 literal without a DNS lookup' do
    expect(Addrinfo).not_to receive(:getaddrinfo)

    expect(mod.database_address('192.0.2.2')).to eq('192.0.2.2')
  end

  it 'preserves an IPv6 literal without a DNS lookup' do
    expect(Addrinfo).not_to receive(:getaddrinfo)

    expect(mod.database_address('2001:db8::2')).to eq('2001:db8::2')
  end

  { 'missing' => nil, 'empty' => '', 'whitespace-only' => " \t" }.each do |description, host|
    it "does not resolve a #{description} datasource host" do
      expect(Rex::Socket).not_to receive(:getaddress)

      expect(mod.database_address(host)).to be_nil
    end
  end

  it 'logs the actual resolver failure and reports the operation at verbose level' do
    error = SocketError.new('Name or service not known')
    allow(Rex::Socket).to receive(:getaddress).and_raise(error)
    expect(mod).to receive(:elog).with('Failed to resolve database host database.example.test for credential reporting', error: error)

    expect(mod.database_address('database.example.test')).to be_nil
    expect(warnings).to include('Unable to store credentials for database host database.example.test: name could not be resolved')
  end

  [nil, 'not-an-ip'].each do |resolved|
    it "does not report an invalid resolver result #{resolved.inspect}" do
      allow(Rex::Socket).to receive(:getaddress).and_return(resolved)

      expect(mod.database_address('database.example.test')).to be_nil
      expect(warnings).to include('Unable to store credentials for database host database.example.test: no IP address was resolved')
    end
  end

  it 'continues printing discovered credentials when DNS resolution fails' do
    allow(Rex::Socket).to receive(:getaddress).and_raise(SocketError, 'Name or service not known')

    mod.run

    expect(recorded).to eq([])
    expect(messages).to include('Found Module Native PostgreSQL: postgresql://module_native:module-target-public-database-password@database.example.test:5432/module_native')
  end

  it 'does not resolve datasource hosts without an active reporting database' do
    mod.framework.db.active = false
    expect(Rex::Socket).not_to receive(:getaddress)

    mod.run

    expect(recorded).to eq([])
  end

  it 'does not create a service for a datasource without a host' do
    parameters['host'] = nil
    expect(Rex::Socket).not_to receive(:getaddress)

    mod.run

    expect(recorded).to eq([])
  end
end
