require 'rspec'

RSpec.describe 'SMB GPP credential service identity' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/smb/smb_enum_gpp') }

  let(:cores) { [] }
  let(:logins) { [] }

  before do
    allow(mod).to receive(:myworkspace_id).and_return(17)
    allow(mod).to receive(:create_credential) do |data|
      cores << data
      Object.new
    end
    allow(mod).to receive(:create_credential_login) { |data| logins << data }
  end

  it 'uses the native SMB session port when the RHOST option group is unset' do
    allow(mod).to receive(:session).and_return(instance_double(Msf::Sessions::SMB, port: 445))
    allow(mod).to receive(:rport).and_return(nil)

    mod.report_creds('192.0.2.53', 'DIRLAB\\policy_user', 'Lab-Policy-Secret:2026!')

    expect([cores.first.fetch(:port), logins.first.fetch(:port)]).to eq([445, 445])
  end

  it 'uses a derived nondefault session endpoint without changing its datastore' do
    allow(mod).to receive(:session).and_return(instance_double(Msf::Sessions::SMB, port: 139))
    allow(mod).to receive(:rport).and_return(nil)

    mod.report_creds('192.0.2.53', 'DIRLAB\\policy_user', 'Lab-Policy-Secret:2026!')

    expect(cores.first.fetch(:port)).to eq(139)
  end

  it 'keeps the selected direct-target port' do
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:rport).and_return(139)

    mod.report_creds('192.0.2.53', 'DIRLAB\\policy_user', 'Lab-Policy-Secret:2026!')

    expect(cores.first.fetch(:port)).to eq(139)
  end

  it 'keeps recovered passwords untried with the actual SMB service context' do
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:rport).and_return(445)

    mod.report_creds('192.0.2.53', 'DIRLAB\\unicode_user', 'Module-π密码-Secret!')

    expect(cores.first).to include(username: 'unicode_user', private_data: 'Module-π密码-Secret!', private_type: :password, realm_value: 'DIRLAB', protocol: 'tcp', service_name: 'smb')
    expect(logins.first.fetch(:status)).to eq(Metasploit::Model::Login::Status::UNTRIED)
  end
end
