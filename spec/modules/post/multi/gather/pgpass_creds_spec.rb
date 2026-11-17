require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'rex/socket'

RSpec.describe 'PostgreSQL password file collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/pgpass_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:session_type) { 'shell' }
  let(:session) { double('Session', platform: 'linux', type: session_type, session_host: '192.0.2.44') }
  let(:credential_core) { double('Credential core') }
  let(:target) { '/root/.pgpass' }
  let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/pgpass_creds', __dir__) }
  let(:fixture_name) { 'plain.pgpass' }
  let(:pgpass_data) { File.binread(File.join(fixtures, fixture_name)) }
  let(:catalogue) { JSON.parse(File.binread(File.join(fixtures, 'catalogue.json'))) }
  let(:native_credential) { catalogue.fetch(fixture_name) }
  let(:credentials) { [] }
  let(:logins) { [] }
  let(:backslash) { '\\' }
  let(:expected_credential) do
    {
      origin_type: :session, session_id: 3, post_reference_name: 'multi/gather/pgpass_creds',
      username: native_credential.fetch('user'), private_data: native_credential.fetch('password'),
      private_type: :password, realm_value: native_credential.fetch('database'),
      realm_key: Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE, workspace_id: 7
    }
  end
  let(:expected_login) do
    {
      address: '192.0.2.44', port: fixture_name == 'wildcard.pgpass' ? 5432 : '5432',
      protocol: 'tcp', service_name: 'postgres', core: credential_core, access_level: 'User',
      status: Metasploit::Model::Login::Status::UNTRIED, workspace_id: 7
    }
  end

  # The eight files and catalogue are exact captures consumed by PostgreSQL
  # psql 16.15 linked against libpq 18.6 on 2026-11-17. Real native login gates
  # accepted them; original-owner shell reporting supplied the contract fields.
  # Transport, framework/session metadata, hostname resolution, persistence and
  # output are doubled. Owner parsing, table construction and report arguments
  # execute without parser/result stubs. Source-derived variations below are
  # labelled separately and have no native authentication claim.
  before do
    allow(mod).to receive_messages(framework: framework, session: session, session_db_id: 3, myworkspace_id: 7, refname: 'multi/gather/pgpass_creds')
    allow(mod).to receive(:read_file).with(target).and_return(pgpass_data)
    allow(mod).to receive(:create_credential) do |data|
      credentials << data
      credential_core
    end
    allow(mod).to receive(:create_credential_login) { |data| logins << data }
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_line)
    allow(Rex::Socket).to receive(:getaddress).and_return('192.0.2.44')
  end

  shared_examples 'a native password file' do |file_name|
    let(:fixture_name) { file_name }

    it "collects the exact #{file_name} credential and login" do
      mod.parse_creds(target)

      expect([credentials, logins]).to eq([[expected_credential], [expected_login]])
    end
  end

  it_behaves_like 'a native password file', 'plain.pgpass'
  it_behaves_like 'a native password file', 'comments.pgpass'
  it_behaves_like 'a native password file', 'blanks.pgpass'
  it_behaves_like 'a native password file', 'incomplete.pgpass'
  it_behaves_like 'a native password file', 'wildcard.pgpass'
  it_behaves_like 'a native password file', 'escaped-db.pgpass'
  it_behaves_like 'a native password file', 'escaped-user.pgpass'
  it_behaves_like 'a native password file', 'escaped-password.pgpass'

  context 'with source-derived parser boundaries' do
    # pwdfMatchesString and passwordFromFile in this exact linked-libpq tag
    # substantiate these additional cases. The source receipt and content hash
    # are recorded with the validation evidence.
    # https://github.com/postgres/postgres/blob/REL_18_6/src/interfaces/libpq/fe-connect.c
    it 'decodes escaped colons in an IPv6 host before address resolution' do
      data = "#{backslash}:#{backslash}:1:5432:pgpass_lab:pgpass_user:pgpass-lab-password\n"
      allow(mod).to receive(:read_file).with(target).and_return(data)
      expect(Rex::Socket).to receive(:getaddress).with('::1').and_return('::1')

      mod.parse_creds(target)

      expect(logins).to eq([expected_login.merge(address: '::1')])
    end

    it 'decodes a pair of backslashes immediately before a database delimiter' do
      data = "localhost:5432:pgpass#{backslash * 2}:pgpass_user:pgpass-lab-password\n"
      allow(mod).to receive(:read_file).with(target).and_return(data)

      mod.parse_creds(target)

      expect(credentials).to eq([expected_credential.merge(realm_value: "pgpass#{backslash}")])
    end

    it 'decodes backslashes in a username without shifting the password' do
      data = "localhost:5432:pgpass_lab:pgpass#{backslash * 2}user:pgpass-lab-password\n"
      allow(mod).to receive(:read_file).with(target).and_return(data)

      mod.parse_creds(target)

      expect(credentials).to eq([expected_credential.merge(username: "pgpass#{backslash}user")])
    end

    it 'retains an empty final password field' do
      allow(mod).to receive(:read_file).with(target).and_return("localhost:5432:pgpass_lab:pgpass_user:\n")

      mod.parse_creds(target)

      expect(credentials).to eq([expected_credential.merge(private_data: '')])
    end

    it 'retains a trailing password backslash' do
      data = "localhost:5432:pgpass_lab:pgpass_user:password#{backslash}\n"
      allow(mod).to receive(:read_file).with(target).and_return(data)

      mod.parse_creds(target)

      expect(credentials).to eq([expected_credential.merge(private_data: "password#{backslash}")])
    end
  end

  it 'does not report credentials from an empty file' do
    allow(mod).to receive(:read_file).with(target).and_return('')

    mod.parse_creds(target)

    expect([credentials, logins]).to eq([[], []])
  end

  it 'preserves legacy unescaped password colons outside native qualification' do
    # libpq stops at an unescaped colon; this repair preserves the owner's
    # existing collection behavior without claiming native acceptance.
    allow(mod).to receive(:read_file).with(target).and_return("localhost:5432:pgpass_lab:pgpass_user:password:tail\n")

    mod.parse_creds(target)

    expect(credentials).to eq([expected_credential.merge(private_data: 'password:tail')])
  end

  it 'does not report credentials from an incomplete file' do
    allow(mod).to receive(:read_file).with(target).and_return("localhost:5432:pgpass_lab\n")

    mod.parse_creds(target)

    expect([credentials, logins]).to eq([[], []])
  end

  it 'rereads and reports the file on a second invocation' do
    expect(mod).to receive(:read_file).with(target).twice.and_return(pgpass_data)

    mod.parse_creds(target)
    mod.parse_creds(target)

    expect([credentials, logins]).to eq([[expected_credential, expected_credential], [expected_login, expected_login]])
  end

  shared_examples 'Linux collection' do
    before do
      allow(mod).to receive(:enum_user_directories).and_return(['/root', '/home/labuser'])
      allow(mod).to receive(:file?).and_return(false)
      allow(mod).to receive(:file?).with(target).and_return(true)
      allow(mod).to receive(:store_loot).and_return('/loot/root.pgpass')
    end

    it 'stores the original file bytes and reports its credential' do
      expect(mod).to receive(:store_loot).with('postgres.pgpass', 'text/plain', session, pgpass_data, target, "pgpass #{target} file").and_return('/loot/root.pgpass')

      mod.run

      expect([credentials, logins]).to eq([[expected_credential], [expected_login]])
    end
  end

  context 'with a Linux command shell' do
    it_behaves_like 'Linux collection'
  end

  context 'with Linux Meterpreter' do
    let(:session_type) { 'meterpreter' }

    it_behaves_like 'Linux collection'
  end
end
