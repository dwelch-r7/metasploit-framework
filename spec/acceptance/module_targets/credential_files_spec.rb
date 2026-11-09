require 'acceptance_spec_helper'
require 'base64'

profile = ENV.fetch('CREDENTIAL_FILE_PROFILE', 'config')
raise ArgumentError, "Unknown credential profile: #{profile}" unless %w[config ssh].include?(profile)

RSpec.describe 'Native Linux credential file targets' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'

  before(:all) do
    output = target_exec('linux', 'python3', '/opt/credential-fixture/native_probe.py')
    @native = JSON.parse(output)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-credentials.json'), output)
    expect(@native.fetch('requests').length).to eq(10)
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    schema = report_sql("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name, ordinal_position")
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), schema)
    expect(schema).to include('metasploit_credential_origin_sessions|post_reference_name|text', 'metasploit_credential_origin_imports|filename|text', 'sessions|local_id|integer')
  end

  before do |example|
    @workspace = "file_creds_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows).to eq([])
    @replays = 0
  end

  after do
    rows if @workspace
    target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf')
  end

  deliveries = {
    'shell' => { payload: 'linux/x64/shell_reverse_tcp', format: 'elf', file: 'shell-session.elf' },
    'meterpreter' => { payload: 'linux/x64/meterpreter_reverse_tcp', format: 'elf', file: 'meterpreter-session.elf' }
  }

  if profile == 'ssh'
    %w[root labuser].each do |user|
      deliveries.each do |kind, delivery|
        it "collects exact SSH files and usable reported keys twice as #{user} #{kind}" do
          session_id = open_native_session(kind, delivery, user: user)
          before = native_files
          2.times do
            output = collect('ssh_creds', session_id)
            expected_files(user, '/.ssh/').each do |filename, state|
              path = output[/Downloaded #{Regexp.escape(filename)} -> (.+)$/, 1]&.strip
              expect(path).not_to be_nil, output
              expect(loot_bytes(path)).to eq(Base64.strict_decode64(state.fetch('data')))
            end
            records = rows
            expected_users = user == 'root' ? %w[root labuser denieduser] : ['labuser']
            records.each do |record|
              expect(record).to include('origin_type' => 'Metasploit::Credential::Origin::Session', 'private_type' => 'Metasploit::Credential::SSHKey', 'post_reference_name' => 'multi/gather/ssh_creds')
              expect(report_sql("SELECT local_id FROM sessions WHERE id=#{Integer(record.fetch('session_id'))}").strip).to eq(session_id)
              expect(replay('ssh', record)).to be(true)
            end
            expect(records.map { |record| record.fetch('username') }.sort).to eq(expected_users.sort)
            expect(native_files).to eq(before)
          end
        end
      end
    end
    deliveries.each do |kind, delivery|
      it "handles entirely missing and empty SSH directories on #{kind}" do
        session_id = open_native_session(kind, delivery)
        paths = @native.fetch('seed').fetch('accounts').values.map { |home| "#{home}/.ssh" }
        absent_collections(paths) do |mode|
          2.times do
            output = collect('ssh_creds', session_id)
            expect(output).to include('No users found with a .ssh directory') if mode == :missing
            expect(output).not_to include('Downloaded ')
            expect(rows).to eq([])
          end
        end
      end
    end
  else
    %w[docker_creds rubygems_api_key].each do |name|
      %w[root labuser].each do |user|
        it "collects and authenticates #{name} twice as #{user} shell" do
          session_id = open_native_session('shell', deliveries.fetch('shell'), user: user)
          before = native_files
          2.times do
            output = collect(name, session_id)
            if name == 'docker_creds'
              records = rows
              expected_users = user == 'root' ? %w[root labuser denieduser] : ['labuser']
              expected = expected_users.map { |owner| @native.fetch('seed').fetch('registry').fetch(owner) }
              expect(records.map { |record| record.fetch('username') }.sort).to eq(expected.map { |record| record.fetch('username') }.sort)
              records.each do |record|
                credential = expected.find { |item| item.fetch('username') == record.fetch('username') }
                expect(replay('docker', record)).to be(true)
                expect(record).to include('private_data' => credential.fetch('password'), 'private_type' => 'Metasploit::Credential::Password', 'origin_type' => 'Metasploit::Credential::Origin::Import', 'realm_value' => '127.0.0.1:5000', 'realm_key' => '*')
                owner = expected_users.find { |entry| @native.fetch('seed').fetch('registry').fetch(entry).fetch('username') == record.fetch('username') }
                expect(record.fetch('filename')).to eq(@native.fetch('seed').fetch('accounts').fetch(owner) + '/.docker/config.json')
              end
            else
              expected_users = user == 'root' ? %w[root labuser denieduser] : ['labuser']
              expected = expected_users.map { |owner| @native.fetch('seed').fetch('gemstash').fetch(owner) }
              paths = output.scan(/RubyGems API key stored in (.+)$/).flatten.map(&:strip)
              found = paths.map { |path| loot_bytes(path) }
              found.each { |key| expect(replay('gem', { 'private_data' => key })).to be(true) }
              expect(found.sort).to eq(expected.sort)
              expect(rows).to eq([])
            end
            expect(native_files).to eq(before)
          end
        end
      end
      it "handles entirely missing and empty #{name} inputs" do
        session_id = open_native_session('shell', deliveries.fetch('shell'))
        suffix = name == 'docker_creds' ? ['/.docker'] : ['/.gem/credentials', '/.local/share/gem/credentials']
        paths = @native.fetch('seed').fetch('accounts').values.flat_map { |home| suffix.map { |ending| home + ending } }
        absent_collections(paths, file: name == 'rubygems_api_key', empty_config: name == 'docker_creds') do |mode|
          2.times do
            output = collect(name, session_id)
            expect(output).to include('No users found') if mode == :missing
            expect(output).not_to include('Saved credentials', 'RubyGems API key stored in')
            expect(rows).to eq([])
          end
        end
      end
    end
  end

  def collect(name, session_id)
    output = run_target_module("post/multi/gather/#{name}", 'linux', { 'SESSION' => session_id }, allow_errors: true, endpoint_options: {}, command_timeout: 180)
    expect(output).to include('Post module execution completed')
    expect(output).not_to match(/Post failed|Post aborted|JSON::ParserError|NoMethodError|TypeError/)
    output
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Afile_creds_[0-9_]+\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(record ORDER BY record.core_id), '[]'::json) FROM (
        SELECT core.id AS core_id, credential_public.username, secret.data AS private_data,
               secret.type AS private_type, core.origin_type, realm.key AS realm_key,
               realm.value AS realm_value, imported.filename,
               gathered.session_id, gathered.post_reference_name, workspace.name AS workspace
        FROM metasploit_credential_cores core
        JOIN workspaces workspace ON workspace.id=core.workspace_id
        LEFT JOIN metasploit_credential_publics credential_public ON credential_public.id=core.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=core.private_id
        LEFT JOIN metasploit_credential_realms realm ON realm.id=core.realm_id
        LEFT JOIN metasploit_credential_origin_imports imported ON imported.id=core.origin_id AND core.origin_type='Metasploit::Credential::Origin::Import'
        LEFT JOIN metasploit_credential_origin_sessions gathered ON gathered.id=core.origin_id AND core.origin_type='Metasploit::Credential::Origin::Session'
        WHERE workspace.name='#{@workspace}'
      ) record;
    SQL
    data = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "database-#{@workspace}.json"), JSON.pretty_generate(data))
    data
  end

  def replay(kind, record)
    @replays += 1
    path = File.join(target_runtime.fetch('artifacts'), "recovered-#{@workspace}-#{@replays}.json")
    File.write(path, JSON.generate(record), mode: 'w', perm: 0o600)
    File.write(path.sub(/\.json\z/, '.pem'), record.fetch('private_data'), mode: 'w', perm: 0o600) if kind == 'ssh'
    output = target_exec('linux', 'python3', '/opt/credential-fixture/replay.py', kind, "/opt/module-target-artifacts/#{File.basename(path)}")
    File.write(path.sub(/\.json\z/, '-authentication.json'), output)
    JSON.parse(output).fetch('success')
  end

  def native_files
    data = JSON.parse(target_exec('linux', 'python3', '/opt/credential-fixture/native_probe.py', '--inspect'))
    data.fetch('files')
  end

  def expected_files(user, fragment)
    @native.fetch('file_states').fetch(user).fetch('files').values.flat_map(&:to_a).to_h.select do |path, state|
      path.include?(fragment) && state.fetch('state') == 'readable'
    end
  end

  def loot_bytes(path)
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(path)
  end

  def absent_collections(paths, file: false, empty_config: false)
    before = native_files
    existing = paths.select { |path| target_exec('linux', 'python3', '-c', 'import os,sys;print("yes" if os.path.exists(sys.argv[1]) else "no")', path).strip == 'yes' }
    moved = []
    created = []
    empty_files = []
    begin
      existing.each do |path|
        target_exec('linux', 'mv', '--', path, "#{path}.module-target-hidden")
        moved << path
      end
      yield :missing
      existing.each do |path|
        file ? target_exec('linux', 'touch', path) : target_exec('linux', 'mkdir', path)
        created << path
        next unless empty_config

        config = "#{path}/config.json"
        target_exec('linux', 'touch', config)
        empty_files << config
        # Docker itself accepts an empty file as an unconfigured client.
        target_exec('linux', 'docker', '--config', path, 'logout', '127.0.0.1:5000')
        expect(target_exec('linux', 'stat', '-c', '%s', config).strip).to eq('0')
      end
      yield :empty
    ensure
      empty_files.each { |path| target_exec('linux', 'rm', '-f', '--', path) }
      created.each do |path|
        file ? target_exec('linux', 'rm', '-f', '--', path) : target_exec('linux', 'rmdir', '--', path)
      end
      moved.each do |path|
        target_exec('linux', 'mv', '--', "#{path}.module-target-hidden", path)
      end
    end
    expect(native_files).to eq(before)
  end
end

# Stops the family when a transport failure makes subsequent labels unreliable.
module CredentialFileConsoleBoundary
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessTimeoutError, 'Console failed; diagnostic stopped' if @console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Native Linux credential file targets' }
raise 'Credential target group is missing' unless group

group.prepend(CredentialFileConsoleBoundary)
