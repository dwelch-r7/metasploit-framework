require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'

RSpec.describe 'Secure Copy WordPress table selection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('SECURE_COPY_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_secure_copy_content_protection_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:sqli) { double('SQLi engine') }
  let(:default_probe) { '13' }
  let(:custom_prefix) { 'wp_native_' }
  let(:sql_vulnerable) { true }
  let(:queries) { [] }
  let(:dumps) { [] }
  let(:messages) { [] }
  let(:credentials) { [] }
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_secure_copy_content_protection_sqli/users.json')))
  end
  let(:records) { capture.fetch('users').map { |row| row.values_at('user_login', 'user_pass') } }
  let(:fullname) { 'auxiliary/scanner/http/wp_secure_copy_content_protection_sqli' }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 8080, 'TARGETURI' => '/', 'SSL' => false, 'USER_COUNT' => 1)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:myworkspace_id).and_return(17)
    allow(mod).to receive(:fullname).and_return(fullname)
    allow(mod).to receive(:rand).with(0..19).and_return(13)
    %i[print_status print_warning print_bad print_error print_good print_line vprint_status vprint_error].each do |method|
      allow(mod).to receive(method) { |message| messages << [method, message] }
    end
    allow(mod).to receive(:create_sqli).and_return(sqli)
    allow(sqli).to receive(:test_vulnerable).and_return(sql_vulnerable)
    allow(sqli).to receive(:run_sql) do |query|
      queries << query
      query.start_with?('SELECT LEFT(table_name,') ? custom_prefix : default_probe
    end
    allow(sqli).to receive(:dump_table_fields) do |*arguments|
      dumps << arguments
      records.first(arguments.fetch(3))
    end
    allow(mod).to receive(:create_credential) { |data| credentials << data }
  end

  # The shared prefix identifier runs normally against a SQL transport double.
  # Framework access, UI and credential persistence are explicit doubles; the
  # returned user rows come from the captured native synthetic lab. These unit
  # checks do not execute SQL, emulate the vendor or prove database persistence.

  it 'keeps complete captured credentials on the default-prefix path' do
    mod.run_host('192.0.2.10')

    expect(credentials.first.values_at(:username, :private_data)).to eq(records.first)
  end

  it 'keeps the default users table and requested columns' do
    mod.run_host('192.0.2.10')

    expect(dumps).to eq([['wp_users', %w[user_login user_pass], '', 1]])
  end

  it 'keeps the existing default table heading' do
    mod.run_host('192.0.2.10')

    expect(messages.select { |method, _message| method == :print_line }.last.last).to start_with("wp_users\n")
  end

  context 'with a custom table prefix' do
    let(:default_probe) { '' }

    it 'dumps the users table selected by the shared identifier' do
      mod.run_host('192.0.2.10')

      expect(dumps).to eq([['wp_native_users', %w[user_login user_pass], '', 1]])
    end

    it 'uses that actual table name in the displayed heading' do
      mod.run_host('192.0.2.10')

      expect(messages.select { |method, _message| method == :print_line }.last.last).to start_with("wp_native_users\n")
    end

    it 'preserves USER_COUNT when dumping the selected table' do
      mod.datastore['USER_COUNT'] = 2
      mod.run_host('192.0.2.10')

      expect(dumps).to eq([['wp_native_users', %w[user_login user_pass], '', 2]])
    end

    it 'preserves complete captured credentials and service origin metadata' do
      mod.run_host('192.0.2.10')

      expect(credentials).to contain_exactly(
        include(
          workspace_id: 17, origin_type: :service, module_fullname: fullname,
          username: records.first.first, private_data: records.first.last,
          private_type: :nonreplayable_hash, service_name: 'Wordpress',
          address: '192.0.2.10', port: 8080, protocol: 'tcp',
          status: Metasploit::Model::Login::Status::UNTRIED
        )
      )
    end

    [nil, '', '   '].each do |missing_prefix|
      context "when discovery returns #{missing_prefix.inspect}" do
        let(:custom_prefix) { missing_prefix }

        it 'reports a prefix-discovery failure before attempting a dump' do
          expect { mod.run_host('192.0.2.10') }.to raise_error(Msf::Auxiliary::Failed, /Unable to identify the WordPress table prefix/)
          expect(dumps).to eq([])
        end
      end
    end
  end

  context 'when the injection probe fails' do
    let(:sql_vulnerable) { false }

    it 'does not attempt prefix discovery, dumping or reporting' do
      mod.run_host('192.0.2.10')

      expect([queries, dumps, credentials]).to eq([[], [], []])
    end
  end

  it 'rediscovers the prefix for each run instead of retaining the previous target table' do
    allow(sqli).to receive(:run_sql) do |query|
      queries << query
      ['13', '', 'wp_native_'].fetch(queries.length - 1)
    end
    mod.run_host('192.0.2.10')
    mod.datastore.merge!('RHOSTS' => '192.0.2.11', 'RHOST' => '192.0.2.11')
    mod.run_host('192.0.2.11')

    expect(dumps.map(&:first)).to eq(%w[wp_users wp_native_users])
  end
end
