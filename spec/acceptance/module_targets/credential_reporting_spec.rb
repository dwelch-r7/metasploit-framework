require 'acceptance_spec_helper'
require 'csv'
require 'net/http'

RSpec.describe 'Database-backed credential reporting targets' do
  include_context 'module target'

  let_it_be(:accounts) { JSON.parse(File.read('test/module_targets/credential_reporting/accounts.json')) }

  before(:all) do
    native_preflight
    native_key_preflight
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(report_sql('SELECT count(*) FROM metasploit_credential_cores').strip).to eq('0')
    schema = report_sql("SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position")
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), schema)
    expect(rows('module_target_0')).to eq([])
  end

  before do |example|
    @workspace = "module_target_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows(@workspace)).to eq([])
  end

  %w[postgres ssh apache].each do |service|
    it "persists exact #{service} credentials and service identity twice without duplicates" do
      2.times do
        login(service)
        records = rows(@workspace)
        expect(records.size).to eq(1)
        verify_record(records.fetch(0), service)
      end
    end

    it "does not persist a rejected #{service} password as successful access" do
      login(service, password: 'module-target-wrong-password', success: false)
      expect(rows(@workspace).select { |row| row.fetch('status') == 'Successful' }).to eq([])
    end
  end

  it 'persists a usable SSH private key twice without duplicate credentials' do
    2.times do
      login_key(@native_key_path)
      records = rows(@workspace)
      expect(records.size).to eq(1)
      verify_key_record(records.fetch(0))
    end
  end

  it 'does not persist an unauthorized SSH key as successful access' do
    login_key(@wrong_key_path, success: false)
    expect(rows(@workspace).select { |row| row.fetch('status') == 'Successful' }).to eq([])
  end

  it 'keeps a password and SSH key for the same user as distinct usable credentials' do
    login('ssh')
    login_key(@native_key_path)
    records = rows(@workspace)
    expect(records.size).to eq(2)
    password_record = records.find { |row| row.fetch('private_type') == 'Metasploit::Credential::Password' }
    key_record = records.find { |row| row.fetch('private_type') == 'Metasploit::Credential::SSHKey' }
    expect(password_record).not_to be_nil
    expect(key_record).not_to be_nil
    verify_record(password_record, 'ssh')
    verify_key_record(key_record)
  end

  it 'keeps the same credential isolated between workspaces on repeated scans' do
    login('postgres')
    first = rows(@workspace)
    second_workspace = "#{@workspace}_other"
    expect(console_command("workspace -a #{second_workspace}")).not_to include('[-]')
    expect(rows(second_workspace)).to eq([])
    2.times { login('postgres') }
    second = rows(second_workspace)
    expect(first.size).to eq(1)
    expect(second.size).to eq(1)
    expect(rows(@workspace)).to eq(first)
    expect(first.fetch(0).fetch('core_id')).not_to eq(second.fetch(0).fetch('core_id'))
    expect(second.fetch(0).fetch('workspace')).to eq(second_workspace)
    verify_record(first.fetch(0), 'postgres')
    verify_record(second.fetch(0), 'postgres', workspace: second_workspace)
  end

  def native_key_preflight
    setup = <<~SH
      set -eu
      install -d -m 700 -o acceptance_tests_user -g acceptance_tests_user /home/acceptance_tests_user/.ssh
      ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f /tmp/module-target-authorized-key
      ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f /tmp/module-target-unauthorized-key
      install -m 600 -o acceptance_tests_user -g acceptance_tests_user /tmp/module-target-authorized-key.pub /home/acceptance_tests_user/.ssh/authorized_keys
    SH
    target_exec('ssh', 'sh', '-c', setup)
    @native_key_path = File.join(target_runtime.fetch('artifacts'), 'native-authorized-key.pem')
    @wrong_key_path = File.join(target_runtime.fetch('artifacts'), 'native-unauthorized-key.pem')
    { @native_key_path => '/tmp/module-target-authorized-key', @wrong_key_path => '/tmp/module-target-unauthorized-key' }.each do |artifact, path|
      File.write(artifact, target_exec('ssh', 'cat', path), mode: 'w', perm: 0o600)
    end
    expect(native_key_login('/tmp/module-target-authorized-key')).to include("acceptance_tests_user\n")
    expect(native_key_login('/tmp/module-target-unauthorized-key', expected_exit: 255)).to include('Permission denied')
  end

  def native_key_login(path, expected_exit: 0)
    target_exec('ssh', 'ssh', '-n', '-i', path, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3', '-o', 'PreferredAuthentications=publickey', '-o', 'PasswordAuthentication=no', 'acceptance_tests_user@127.0.0.1', 'id -un', expected_exit: expected_exit)
  end

  it 'exports the three real persisted credentials through the ordinary CSV command' do
    accounts.each_key { |service| login(service) }
    path = File.join(target_runtime.fetch('artifacts'), 'credential-reporting.csv')
    expect(console_command("creds -o #{path}")).to include("Wrote creds to #{path}")
    exported = CSV.read(path, headers: true)
    expect(exported.size).to eq(3)
    accounts.each do |service, account|
      row = exported.find { |entry| entry.fetch('public') == account.fetch('username') }
      expect(row).not_to be_nil
      expect(row.fetch('private')).to eq(account.fetch('password'))
      expect(row.fetch('host')).to eq(target_runtime.fetch('module_endpoints').fetch(service).fetch('host'))
    end
  end

  def native_preflight
    report = {}
    report['database_identity'] = report_sql('SELECT current_user, current_database(), version()')
    expect(report.fetch('database_identity')).to include('module_framework', 'module_targets', 'PostgreSQL 16.')
    report['database_invalid'] = target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-wrong-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user', expected_exit: 2)
    expect(report.fetch('database_invalid')).to include('password authentication failed')
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").strip).to eq('0')
    report['postgres_valid'] = target_exec('postgres', 'env', 'PGPASSWORD=password', 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-Atc', 'SELECT current_user, version()')
    expect(report.fetch('postgres_valid')).to include('postgres|PostgreSQL 16.')
    report['postgres_invalid'] = target_exec('postgres', 'env', 'PGPASSWORD=module-target-wrong-password', 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-Atc', 'SELECT current_user', expected_exit: 2)
    expect(report.fetch('postgres_invalid')).to include('password authentication failed')
    rule_query = 'SELECT json_agg(row) FROM (SELECT type, auth_method, error FROM pg_hba_file_rules ORDER BY line_number) row'
    %w[postgres reporting_db].each do |service|
      output = if service == 'reporting_db'
                 report_sql(rule_query)
               else
                 target_exec('postgres', 'env', 'PGPASSWORD=password', 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-Atc', rule_query)
               end
      rules = JSON.parse(output)
      expect(rules.map { |row| row.fetch('error') }.compact).to eq([])
      expect(rules.select { |row| row.fetch('type').start_with?('host') }.map { |row| row.fetch('auth_method') }.uniq).to eq(['scram-sha-256'])
      report["#{service}_authentication_rules"] = rules
    end
    %w[valid invalid].each do |kind|
      password = kind == 'valid' ? accounts.fetch('ssh').fetch('password') : 'module-target-wrong-password'
      report["ssh_#{kind}"] = target_exec('ssh', 'env', "MODULE_TARGET_SSH_PASSWORD=#{password}", 'SSH_ASKPASS=/opt/module-target-askpass.sh', 'SSH_ASKPASS_REQUIRE=force', 'DISPLAY=:0', 'ssh', '-n', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=3', '-o', 'NumberOfPasswordPrompts=1', '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no', 'acceptance_tests_user@127.0.0.1', 'id -un', expected_exit: kind == 'valid' ? 0 : 255)
    end
    expect(report.fetch('ssh_valid')).to include("acceptance_tests_user\n")
    expect(report.fetch('ssh_invalid')).to include('Permission denied')
    endpoint = target_endpoint('apache')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = http.read_timeout = 5
    %w[valid invalid].each do |kind|
      request = Net::HTTP::Get.new('/protected/')
      request.basic_auth(accounts.fetch('apache').fetch('username'), kind == 'valid' ? accounts.fetch('apache').fetch('password') : 'module-target-wrong-password')
      response = http.request(request)
      expect(response.code).to eq(kind == 'valid' ? '200' : '401')
      expect(response.body).to include('module-target-protected-marker') if kind == 'valid'
      report["http_#{kind}"] = { code: response.code, headers: response.to_hash, body: response.body }
    end
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-credential-preflight.json'), JSON.pretty_generate(report))
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows(workspace)
    raise ArgumentError, 'Invalid fixture workspace' unless workspace.match?(/\Amodule_target_[0-9_]+(?:_other)?\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(record ORDER BY record.core_id), '[]'::json) FROM (
        SELECT c.id AS core_id, w.name AS workspace, p.username, secret.data AS private_data,
               secret.type AS private_type, c.origin_type, o.module_full_name,
               l.status, l.last_attempted_at, host(h.address::inet) AS host,
               s.port, s.proto, s.name AS service, realm.value AS realm,
               c.workspace_id AS credential_workspace_id, h.workspace_id AS host_workspace_id,
               l.service_id AS login_service_id, o.service_id AS origin_service_id
        FROM metasploit_credential_cores c
        JOIN workspaces w ON w.id = c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id = c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id = c.private_id
        LEFT JOIN metasploit_credential_realms realm ON realm.id = c.realm_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id = c.id
        LEFT JOIN services s ON s.id = l.service_id
        LEFT JOIN hosts h ON h.id = s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id = c.origin_id AND c.origin_type = 'Metasploit::Credential::Origin::Service'
        WHERE w.name = '#{workspace}'
      ) record;
    SQL
    data = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "database-#{workspace}.json"), JSON.pretty_generate(data))
    data
  end

  def verify_context(record, service, workspace: @workspace)
    account = accounts.fetch(service)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    expect(record).to include('workspace' => workspace, 'username' => account.fetch('username'), 'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => account.fetch('module'), 'status' => 'Successful', 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'), 'proto' => 'tcp', 'service' => account.fetch('service'))
    expect(record.fetch('host_workspace_id')).to eq(record.fetch('credential_workspace_id'))
    expect(record.fetch('origin_service_id')).to eq(record.fetch('login_service_id'))
    expect(record.fetch('last_attempted_at')).not_to be_nil
    expect(record.fetch('realm')).to eq('postgres') if service == 'postgres'
  end

  def verify_record(record, service, workspace: @workspace)
    verify_context(record, service, workspace: workspace)
    expect(record).to include('private_data' => accounts.fetch(service).fetch('password'), 'private_type' => 'Metasploit::Credential::Password')
  end

  def verify_key_record(record)
    verify_context(record, 'ssh')
    expect(record.fetch('private_type')).to eq('Metasploit::Credential::SSHKey')
    expect(record.fetch('private_data')).to be_a(String)
    path = File.join(target_runtime.fetch('artifacts'), 'database-recovered-key.pem')
    File.write(path, record.fetch('private_data'), mode: 'w', perm: 0o600)
    expect(native_key_login('/opt/module-target-artifacts/database-recovered-key.pem')).to include("acceptance_tests_user\n")
  end

  def login_key(path, success: true)
    options = {
      'USERNAME' => accounts.fetch('ssh').fetch('username'), 'PASSWORD' => nil, 'KEY_PATH' => path,
      'PRIVATE_KEY' => nil, 'KEY_PASS' => nil, 'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'ANONYMOUS_LOGIN' => false,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false, 'DB_SKIP_EXISTING' => 'none',
      'CreateSession' => false, 'STOP_ON_SUCCESS' => true, 'BRUTEFORCE_SPEED' => 5, 'THREADS' => 1
    }
    output = run_target_module(accounts.fetch('ssh').fetch('module'), 'ssh', options, allow_errors: true, command_timeout: 60)
    expect(output).not_to include('No active DB', 'Exception')
    success ? expect(output).to(include('Success:')) : expect(output).not_to(include('Success:'))
    output
  end

  def login(service, password: nil, success: true)
    account = accounts.fetch(service)
    options = {
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil, 'BLANK_PASSWORDS' => false,
      'USER_AS_PASS' => false, 'ANONYMOUS_LOGIN' => false, 'STOP_ON_SUCCESS' => true,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false, 'DB_SKIP_EXISTING' => 'none',
      'BRUTEFORCE_SPEED' => 5, 'THREADS' => 1
    }
    if service == 'apache'
      options.merge!('HttpUsername' => account.fetch('username'), 'HttpPassword' => password || account.fetch('password'), 'AUTH_URI' => '/protected/', 'SSL' => false)
    else
      options.merge!('USERNAME' => account.fetch('username'), 'PASSWORD' => password || account.fetch('password'))
      options['CreateSession'] = false if service == 'ssh'
      options['DATABASE'] = 'postgres' if service == 'postgres'
    end
    output = run_target_module(account.fetch('module'), service, options, allow_errors: true, command_timeout: 60)
    expect(output).not_to include('No active DB', 'Exception')
    if success
      expect(output).to include(service == 'postgres' ? 'Login Successful:' : 'Success:')
    else
      expect(output).not_to include('Login Successful:', 'Success:')
    end
    output
  end
end
