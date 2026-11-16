require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Brother generated credential reporting' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('BROTHER_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:credential_core) { double('Credential core') }
  let(:credential_reports) { [] }
  let(:login_reports) { [] }
  let(:timestamp) { DateTime.iso8601('2026-11-16T12:00:00Z') }
  let(:fullname) { 'auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978' }
  let(:login_status) { Metasploit::Model::Login::Status::UNTRIED }

  before do
    mod.datastore.merge!('RHOST' => '192.0.2.10', 'RPORT' => 443, 'SSL' => true)
    allow(mod).to receive(:myworkspace_id).and_return(17)
    allow(mod).to receive(:fullname).and_return(fullname)
    allow(mod).to receive(:create_credential) do |data|
      credential_reports << data
      credential_core
    end
    allow(mod).to receive(:create_credential_login) { |data| login_reports << data }
    allow(DateTime).to receive(:now).and_return(timestamp)
  end

  # Reporting is doubled to inspect the actual module arguments. The timestamp
  # contract comes from Credential::Login#consistent_last_attempted_at; genuine
  # database persistence and public console execution are verified separately.
  describe '#store_credentials' do
    it 'leaves the attempt timestamp unset for a generated but untried login' do
      mod.store_credentials('admin', '%@9jegU5', login_status)

      expect(login_reports.fetch(0).fetch(:last_attempted_at, nil)).to be_nil
    end

    it 'keeps repeated untried reports free of an attempt timestamp' do
      mod.store_credentials('admin', '%@9jegU5', login_status)
      mod.store_credentials('admin', '%@9jegU5', login_status)

      expect(login_reports.map { |data| data.values_at(:status, :last_attempted_at) }).to eq([[login_status, nil], [login_status, nil]])
    end

    [
      ['successful', Metasploit::Model::Login::Status::SUCCESSFUL],
      ['incorrect', Metasploit::Model::Login::Status::INCORRECT],
      ['unable to connect', Metasploit::Model::Login::Status::UNABLE_TO_CONNECT]
    ].each do |description, status|
      it "retains the attempt timestamp for #{description} logins" do
        mod.store_credentials('admin', '%@9jegU5', status)

        expect(login_reports.fetch(0)).to include(status: status, last_attempted_at: timestamp)
      end
    end

    it 'retains the full generated password and module service origin' do
      mod.store_credentials('admin', '%@9jegU5', login_status)

      expect(credential_reports).to contain_exactly(
        origin_type: :service, module_fullname: fullname, username: 'admin', private_data: '%@9jegU5', private_type: :password,
        address: '192.0.2.10', port: 443, service_name: 'https', protocol: 'tcp', workspace_id: 17
      )
    end

    it 'links the untried login to its credential and HTTPS service' do
      mod.store_credentials('admin', '%@9jegU5', login_status)

      expect(login_reports.fetch(0)).to include(
        core: credential_core, status: login_status,
        address: '192.0.2.10', port: 443, service_name: 'https', protocol: 'tcp', workspace_id: 17
      )
    end

    it 'preserves the configured HTTP service endpoint' do
      mod.datastore.merge!('SSL' => false, 'RPORT' => 80)
      mod.store_credentials('admin', '%@9jegU5', login_status)

      expect(login_reports.fetch(0)).to include(address: '192.0.2.10', port: 80, service_name: 'http')
    end
  end
end
