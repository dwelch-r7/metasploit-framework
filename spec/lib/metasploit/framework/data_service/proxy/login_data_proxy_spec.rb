require 'rspec'
require 'active_support/core_ext/string/inflections'
require 'metasploit/framework/data_service/proxy/login_data_proxy'
require 'metasploit/framework/data_service/proxy/credential_data_proxy'
require 'metasploit/framework/data_service/proxy/service_data_proxy'

RSpec.describe LoginDataProxy do
  subject(:proxy) { proxy_class.new(backend) }

  let(:proxy_class) do
    Class.new do
      include LoginDataProxy
      include CredentialDataProxy
      include ServiceDataProxy

      attr_reader :errors

      def initialize(backend)
        @backend = backend
        @errors = []
      end

      def data_service_operation
        yield @backend
      end

      def add_opts_workspace(options)
        options[:workspace] ||= 'module_target'
      end

      def log_error(error, context)
        @errors << [context, error.class]
        raise error
      end
    end
  end
  let(:login_class) { Struct.new(:id, :service_id, :status) }
  let(:first_login) { login_class.new(101, 11, 'Successful') }
  let(:second_login) { login_class.new(102, 12, 'Successful') }
  let(:other_port_login) { login_class.new(103, 13, 'Successful') }
  let(:other_protocol_login) { login_class.new(104, 14, 'Successful') }
  let(:other_workspace_login) { login_class.new(105, 15, 'Successful') }
  let(:other_name_login) { login_class.new(106, 16, 'Successful') }
  let(:stored_logins) { [first_login, second_login, other_port_login, other_protocol_login, other_workspace_login, other_name_login] }
  let(:logins) { stored_logins.dup }
  let(:secret) { double('cached credential private', data: 'ClueCon', type: 'Metasploit::Credential::Password') }
  let(:core) { double('cached credential core', id: 1, logins: logins, public: nil, private: secret, realm: nil) }
  let(:cores) { [core] }
  let(:service) { double('Mdm::Service result', id: 12) }
  let(:services) { [service] }
  let(:backend) { double('local or remote data service', creds: cores, services: services) }
  let(:updates) { [] }
  let(:attempt) do
    {
      workspace: 'module_target', address: '192.0.2.11', port: 8021,
      protocol: 'tcp', service_name: 'freeswitch', private_data: 'ClueCon',
      status: 'Incorrect', last_attempted_at: '2026-11-13T13:00:00Z'
    }
  end

  before do
    allow(backend).to receive(:update_login) do |attributes|
      updates << attributes.dup
      stored_logins.find { |login| login.id == attributes.fetch(:id) }.status = attributes.fetch(:status)
    end
  end

  # Credential/service lookup and update persistence are backend doubles with
  # real API option keys and cached core/login/service field names. All three
  # proxy wrappers and their dispatch/error handling remain real. These rows
  # model the native FreeSWITCH case without requiring a unit-test database.

  it 'keeps a different host successful when the attempted service has no cached login' do
    logins.delete(second_login)
    proxy.invalidate_login(attempt)

    expect(first_login.status).to eq('Successful')
  end

  it 'updates only the attempted service login' do
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'preserves same-port logins on a different host' do
    proxy.invalidate_login(attempt)

    expect(first_login.status).to eq('Successful')
  end

  it 'preserves a different port on the same host' do
    proxy.invalidate_login(attempt)

    expect(other_port_login.status).to eq('Successful')
  end

  it 'preserves a different transport protocol' do
    proxy.invalidate_login(attempt)

    expect(other_protocol_login.status).to eq('Successful')
  end

  it 'preserves a service from another workspace' do
    proxy.invalidate_login(attempt)

    expect(other_workspace_login.status).to eq('Successful')
  end

  it 'uses the ordinary service API to scope workspace, address, port and protocol' do
    expect(backend).to receive(:services).with({
      workspace: 'module_target', hosts: { address: '192.0.2.11' }, port: 8021, proto: 'tcp', name: 'freeswitch'
    }).and_return(services)

    proxy.invalidate_login(attempt)
  end

  it 'passes IPv6 addresses to the service API without manual string comparison' do
    attempt[:address] = '2001:db8::11'
    expect(backend).to receive(:services).with({
      workspace: 'module_target', hosts: { address: '2001:db8::11' }, port: 8021, proto: 'tcp', name: 'freeswitch'
    }).and_return(services)

    proxy.invalidate_login(attempt)
  end

  it 'updates a later matching core when the first has only foreign-service logins' do
    foreign = double('first cached core', id: 1, logins: [first_login], public: nil, private: secret, realm: nil)
    matching = double('later cached core', id: 2, logins: [second_login], public: nil, private: secret, realm: nil)
    allow(backend).to receive(:creds).and_return([foreign, matching])
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'keeps named-account credentials outside an explicit password-only failure' do
    attempt[:username] = nil
    allow(core).to receive(:public).and_return(double('cached public', username: 'admin'))
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'updates an explicitly matching named account' do
    attempt[:username] = 'admin'
    allow(core).to receive(:public).and_return(double('cached public', username: 'admin'))
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'keeps credentials from a different explicitly absent realm outside the failure' do
    attempt[:realm_key] = nil
    attempt[:realm_value] = nil
    allow(core).to receive(:realm).and_return(double('cached realm', key: 'Active Directory Domain', value: 'other.invalid'))
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'compares byte-equivalent Unicode private data across transport encodings' do
    allow(secret).to receive(:data).and_return('module-target-Ω spaced')
    attempt[:private_data] = 'module-target-Ω spaced'.b
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'keeps same-byte NTLM and SSH-key cores outside an explicit password failure' do
    attempt[:private_type] = :password
    first_login.service_id = second_login.service_id
    other_name_login.service_id = second_login.service_id
    hash_secret = double('cached NTLM private', data: 'ClueCon', type: 'Metasploit::Credential::NTLMHash')
    key_secret = double('cached SSH private', data: 'ClueCon', type: 'Metasploit::Credential::SSHKey')
    hash_core = double('hash core', logins: [first_login], private: hash_secret)
    key_core = double('key core', logins: [other_name_login], private: key_secret)
    allow(core).to receive(:logins).and_return([second_login])
    allow(backend).to receive(:creds).and_return([hash_core, core, key_core])
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'matches the existing STI mapping for a supplied string private type' do
    attempt[:private_type] = 'ssh_key'
    allow(secret).to receive(:type).and_return('Metasploit::Credential::SSHKey')
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'leaves an omitted private type unspecified' do
    allow(secret).to receive(:type).and_return('Metasploit::Credential::NTLMHash')
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'matches an explicitly absent private type when no private component exists' do
    attempt.delete(:private_data)
    attempt[:private_type] = nil
    allow(core).to receive(:private).and_return(nil)
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'keeps a stored private component outside an explicitly absent private type' do
    attempt[:private_type] = nil
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'recognizes a blank password stored as the Password subtype BlankPassword' do
    attempt[:private_type] = :password
    attempt[:private_data] = ''
    allow(secret).to receive_messages(data: '', type: 'Metasploit::Credential::BlankPassword')
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'does not invalidate a different private value returned by a broad candidate query' do
    allow(secret).to receive(:data).and_return('DifferentPassword')
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'does not treat an explicitly blank username as an unspecified username' do
    attempt[:username] = ''
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'matches an explicitly blank stored username exactly' do
    attempt[:username] = ''
    allow(core).to receive(:public).and_return(double('cached public', username: ''))
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'matches an explicitly blank private value exactly' do
    attempt[:private_data] = ''
    allow(secret).to receive(:data).and_return('')
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'keeps a blank private value distinct from an absent private value' do
    attempt[:private_data] = ''
    allow(core).to receive(:private).and_return(nil)
    proxy.invalidate_login(attempt)

    expect(updates).to eq([])
  end

  it 'supports a credential with no private value' do
    attempt.delete(:private_data)
    allow(core).to receive(:private).and_return(nil)
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'matches an explicitly supplied realm key and value' do
    attempt[:realm_key] = 'Active Directory Domain'
    attempt[:realm_value] = 'module.invalid'
    allow(core).to receive(:realm).and_return(double('cached realm', key: 'Active Directory Domain', value: 'module.invalid'))
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'leaves omitted public and realm identity fields unspecified' do
    allow(core).to receive(:public).and_return(double('cached public', username: 'admin'))
    allow(core).to receive(:realm).and_return(double('cached realm', key: 'Active Directory Domain', value: 'module.invalid'))
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'leaves an omitted private field unspecified' do
    attempt.delete(:private_data)
    allow(secret).to receive(:data).and_return('DifferentPassword')
    proxy.invalidate_login(attempt)

    expect(updates.map { |row| row.fetch(:id) }).to eq([102])
  end

  it 'preserves a differently named service at the same endpoint' do
    proxy.invalidate_login(attempt)

    expect(other_name_login.status).to eq('Successful')
  end

  it 'normalizes an explicitly supplied service name to the stored lowercase form' do
    attempt[:service_name] = 'FreeSWITCH'
    expect(backend).to receive(:services).with({
      workspace: 'module_target', hosts: { address: '192.0.2.11' }, port: 8021, proto: 'tcp', name: 'freeswitch'
    }).and_return(services)

    proxy.invalidate_login(attempt)
  end

  it 'does not invent a service-name filter when the name is omitted' do
    attempt.delete(:service_name)
    expect(backend).to receive(:services).with({
      workspace: 'module_target', hosts: { address: '192.0.2.11' }, port: 8021, proto: 'tcp'
    }).and_return(services)

    proxy.invalidate_login(attempt)
  end

  it 'retains the existing update attribute allow-list' do
    attempt[:access_level] = 'User'
    proxy.invalidate_login(attempt)

    expect(updates).to eq([{ id: 102, status: 'Incorrect', last_attempted_at: '2026-11-13T13:00:00Z', access_level: 'User' }])
  end

  it 'supports the Unable to Connect status without corrupting peers' do
    attempt[:status] = 'Unable to Connect'
    proxy.invalidate_login(attempt)

    expect(logins.map(&:status)).to eq(['Successful', 'Unable to Connect', 'Successful', 'Successful', 'Successful', 'Successful'])
  end

  it 'keeps the existing cached-login collection return value' do
    expect(proxy.invalidate_login(attempt)).to equal(logins)
  end

  context 'when the local credential query returns a relation' do
    let(:cores) { double('credential relation', to_a: [core]) }

    it 'updates the same scoped login as a remote array response' do
      proxy.invalidate_login(attempt)

      expect(updates.map { |row| row.fetch(:id) }).to eq([102])
    end
  end

  context 'when there are no matching services' do
    let(:services) { [] }

    it 'does not update any cached login' do
      proxy.invalidate_login(attempt)

      expect(updates).to eq([])
    end
  end

  context 'when the service API legitimately returns nil' do
    let(:services) { nil }

    it 'does not update any cached login' do
      proxy.invalidate_login(attempt)

      expect(updates).to eq([])
    end
  end

  context 'when no credential core matches' do
    let(:cores) { [] }

    it 'retains the nil return without attempting updates' do
      expect(proxy.invalidate_login(attempt)).to be_nil
    end
  end

  # DataProxy#log_error logs and re-raises; this facade preserves that contract
  # and records contexts instead of invoking the Framework's log sink.
  it 'preserves the original credential-query exception and logging contexts' do
    error = ArgumentError.new('Invalid credential query')
    allow(backend).to receive(:creds).and_raise(error)

    expect { proxy.invalidate_login(attempt) }.to raise_error(ArgumentError, error.message) { |raised| expect(raised).to equal(error) }
    expect(proxy.errors).to eq([['Problem retrieving credentials', ArgumentError], ['Problem invalidating login', ArgumentError]])
  end

  it 'preserves the original update exception and logging contexts' do
    error = ArgumentError.new('Invalid login update')
    allow(backend).to receive(:update_login).and_raise(error)

    expect { proxy.invalidate_login(attempt) }.to raise_error(ArgumentError, error.message) { |raised| expect(raised).to equal(error) }
    expect(proxy.errors).to eq([['Problem updating login', ArgumentError], ['Problem invalidating login', ArgumentError]])
  end

  it 'preserves the original service-query exception and logging contexts' do
    error = ArgumentError.new('Invalid service query')
    allow(backend).to receive(:services).and_raise(error)

    expect { proxy.invalidate_login(attempt) }.to raise_error(ArgumentError, error.message) { |raised| expect(raised).to equal(error) }
    expect(proxy.errors).to eq([['Problem retrieving services', ArgumentError], ['Problem invalidating login', ArgumentError]])
  end
end
