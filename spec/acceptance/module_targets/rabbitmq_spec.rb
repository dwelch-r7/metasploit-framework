require 'acceptance_spec_helper'
require 'rbconfig'
require 'digest'

RSpec.describe 'Native RabbitMQ discovery and database-backed authentication' do
  include_context 'module target'

  broker_services = ENV.key?('RABBITMQ_PROFILE') ? [ENV.fetch('RABBITMQ_PROFILE')] : %w[old new]
  raise ArgumentError, 'Unknown RabbitMQ fixture profile' unless (broker_services - %w[old new]).empty?

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/rabbitmq/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-rabbitmq.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-rabbitmq-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout)
    release_native_client if ENV.key?('RABBITMQ_PROFILE')
    sources = %w[
      modules/auxiliary/scanner/amqp/amqp_version.rb
      modules/auxiliary/scanner/amqp/amqp_login.rb
      lib/metasploit/framework/login_scanner/amqp.rb
      lib/rex/proto/amqp/version_0_9_1/client.rb
    ]
    @source_hashes = sources.to_h { |path| [path, Digest::SHA256.file(path).hexdigest] }
    expect(target_exec('framework', 'sha256sum', *sources).lines.map(&:split).to_h).to eq(@source_hashes.invert)
    File.write(File.join(target_runtime.fetch('artifacts'), 'framework-source-hashes.json'), JSON.pretty_generate(@source_hashes))
    expect(report_sql('SELECT current_user, current_database()').strip).to eq('module_framework|module_targets')
    wrong = target_exec('reporting_db', 'env', 'PGPASSWORD=wrong-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user', expected_exit: 2)
    expect(wrong).to include('password authentication failed')
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = "module_target_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(credentials).to eq([])
  end

  broker_services.each do |service|
    [false, true].each do |tls|
      it "reports actual #{service} AMQP properties over #{tls ? 'TLS' : 'TCP'}" do
        output = invoke('amqp_version', service, tls)
        result = @native.fetch('profiles').fetch(service).fetch('amqp').fetch(tls ? 'tls' : 'plain').fetch('valid')
        native = result.fetch('properties')
        mechanisms = result.fetch('start').fetch('mechanisms').split.join(', ')
        expect(output).to include("version:RabbitMQ #{native.fetch('version')}", "cluster:#{native.fetch('cluster_name')}", "platform:#{native.fetch('platform')}", "authentication:#{mechanisms}")
        services = JSON.parse(report_sql("SELECT coalesce(json_agg(row), '[]'::json) FROM (SELECT s.name, s.info, s.port FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
        expect(services).to contain_exactly(include('name' => tls ? 'amqps' : 'amqp', 'port' => tls ? 5671 : 5672))
        expect(services.fetch(0).fetch('info')).to include("RabbitMQ #{native.fetch('version')}")
      end

      it "persists usable #{service} #{tls ? 'TLS' : 'TCP'} credentials twice without duplicates" do
        2.times do
          output = login(service, tls)
          expect(output).to include('Login Successful: lab-amqp-user:module-target-amqp-password')
          expect(credentials).to contain_exactly(credential_record(service, tls))
        end
      end

      it "does not persist an incorrect #{service} #{tls ? 'TLS' : 'TCP'} password as successful" do
        output = login(service, tls, password: 'wrong-password', allow_errors: true)
        expect(output).to include('LOGIN FAILED:', 'Incorrect', 'ACCESS_REFUSED')
        expect(output).not_to include('Login Successful:')
        expect(credentials.select { |row| row.fetch('status') == 'Successful' }).to eq([])
        expect(login(service, tls)).to include('Login Successful: lab-amqp-user:module-target-amqp-password')
        expect(credentials.select { |row| row.fetch('status') == 'Successful' }).to contain_exactly(credential_record(service, tls))
      end
    end

    it "reports #{service} valid limited credentials without claiming root vhost authorization" do
      output = login(service, false, username: 'lab-amqp-limited', password: 'module-target-limited-password')
      expect(output).to include('Login Successful: lab-amqp-limited:module-target-limited-password')
      expect(@native.fetch('profiles').fetch(service).fetch('amqp').fetch('plain').fetch('limited_root').fetch('connected')).to be(false)
      expect(credentials).to contain_exactly(credential_record(service, false, username: 'lab-amqp-limited', password: 'module-target-limited-password'))
    end

    it "rejects #{service} loopback-only guest credentials from the Framework container" do
      output = login(service, false, username: 'guest', password: 'guest', allow_errors: true)
      expect(output).to include('LOGIN FAILED:', 'Incorrect')
      expect(output).not_to include('Login Successful:')
      expect(credentials.select { |row| row.fetch('status') == 'Successful' }).to eq([])
    end
  end

  it 'keeps the same usable login isolated between workspaces' do
    service = broker_services.last
    login(service, false)
    first = credentials
    @workspace = "#{@workspace}_other"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(credentials).to eq([])
    login(service, false)
    expect(credentials).to contain_exactly(credential_record(service, false))
    expect(first.size).to eq(1)
  end

  if ENV.key?('RABBITMQ_PROFILE')
    after(:all) do
      next unless @native && @source_hashes

      service = broker_services.fetch(0)
      records = {}
      %w[list_users list_connections].each do |operation|
        records[operation] = JSON.parse(target_exec(service, 'gosu', 'rabbitmq', 'rabbitmqctl', '-q', operation, '--formatter=json'))
      end
      expect(records.fetch('list_users')).to eq(@native.fetch('profiles').fetch(service).fetch('users'))
      expect(records.fetch('list_connections')).to eq([])
      ['/', 'module-target'].each do |vhost|
        queues = JSON.parse(target_exec(service, 'gosu', 'rabbitmq', 'rabbitmqctl', '-q', 'list_queues', '-p', vhost, 'name', '--formatter=json'))
        expect(queues).to eq([])
        records["queues:#{vhost}"] = queues
      end
      permissions = JSON.parse(target_exec(service, 'gosu', 'rabbitmq', 'rabbitmqctl', '-q', 'list_permissions', '-p', '/', '--formatter=json'))
      expect(permissions).to eq(@native.fetch('profiles').fetch(service).fetch('permissions'))
      records['permissions'] = permissions
      expect(target_exec('framework', 'sha256sum', *@source_hashes.keys).lines.map(&:split).to_h).to eq(@source_hashes.invert)
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-preservation.json'), JSON.pretty_generate(records))
    end
  end

  def release_native_client
    compose = target_runtime.fetch('compose')
    output, status = Open3.capture2e(*compose, 'ps', '--all', '--quiet', 'client')
    identifier = output.strip
    expect(status.success? && identifier.match?(/\A[0-9a-f]{64}\z/)).to be(true)
    output, status = Open3.capture2e(*compose, 'rm', '--stop', '--force', '--volumes', 'client')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-client-release.json'), JSON.pretty_generate(id: identifier, exitstatus: status.exitstatus, output: output))
    expect(status.success?).to be(true), output
    output, status = Open3.capture2e(*compose, 'ps', '--all', '--quiet', 'client')
    expect(status.success? && output.strip.empty?).to be(true)
  end

  def invoke(name, service, tls, options = {}, allow_errors: false)
    run_target_module("auxiliary/scanner/amqp/#{name}", service, { 'SSL' => tls, 'RPORT' => tls ? 5671 : 5672 }.merge(options), allow_errors: allow_errors, command_timeout: 45)
  end

  def login(service, tls, username: 'lab-amqp-user', password: 'module-target-amqp-password', allow_errors: false)
    invoke('amqp_login', service, tls, {
      'USERNAME' => username, 'PASSWORD' => password,
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'ANONYMOUS_LOGIN' => false,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false, 'DB_SKIP_EXISTING' => 'none',
      'STOP_ON_SUCCESS' => true, 'BRUTEFORCE_SPEED' => 5, 'THREADS' => 1
    }, allow_errors: allow_errors)
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def credentials
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Amodule_target_[0-9_]+(?:_other)?\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(record), '[]'::json) FROM (
        SELECT p.username, secret.data AS password, secret.type AS private_type,
               c.origin_type, o.module_full_name, l.status, s.name AS service,
               host(h.address::inet) AS host, s.port, s.proto,
               (c.workspace_id=h.workspace_id) AS same_workspace,
               (o.service_id=l.service_id) AS same_service,
               (l.last_attempted_at IS NOT NULL) AS attempted
        FROM metasploit_credential_cores c
        JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id
        LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{@workspace}'
      ) record
    SQL
    rows = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "database-#{@workspace}.json"), JSON.pretty_generate(rows))
    rows
  end

  def credential_record(service, tls, username: 'lab-amqp-user', password: 'module-target-amqp-password')
    {
      'username' => username, 'password' => password, 'private_type' => 'Metasploit::Credential::Password',
      'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => 'auxiliary/scanner/amqp/amqp_login',
      'status' => 'Successful', 'service' => tls ? 'amqps' : 'amqp',
      'host' => target_runtime.fetch('module_endpoints').fetch(service).fetch('host'),
      'port' => tls ? 5671 : 5672, 'proto' => 'tcp', 'same_workspace' => true, 'same_service' => true, 'attempted' => true
    }
  end
end
