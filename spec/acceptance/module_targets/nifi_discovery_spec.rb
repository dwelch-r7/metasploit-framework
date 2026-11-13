require 'acceptance_spec_helper'
require 'json'
require 'timeout'
require 'yaml'

discovery_profile = ENV.fetch('NIFI_DISCOVERY_PROFILE', 'all')
discovery_services = %w[legacy vulnerable fixed]
raise ArgumentError, 'Unknown NiFi discovery profile' unless ['all', *discovery_services].include?(discovery_profile)

discovery_services = [discovery_profile] unless discovery_profile == 'all'

RSpec.describe 'Genuine NiFi version and login targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    @discovery_profile = discovery_profile
    @native = native_discovery('before')
    @accounts = File.readlines('test/module_targets/nifi/accounts.env', chomp: true).to_h { |line| line.split('=', 2) }
    database = YAML.safe_load_file('test/module_targets/credential_reporting/compose.yaml').fetch('services').fetch('reporting_db').fetch('environment')
    @database = database
    connected = console_command("db_connect #{database.fetch('POSTGRES_USER')}:#{database.fetch('POSTGRES_PASSWORD')}@reporting_db:5432/#{database.fetch('POSTGRES_DB')}", timeout: 120)
    expect(connected).not_to match(/\[-\]|Exception|Error/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(report_sql('SELECT count(*) FROM metasploit_credential_cores').strip).to eq('0')
  end

  after(:all) do
    if @native && @discovery_profile != 'all'
      native_after = native_discovery('after')
      services = [@discovery_profile, 'reporting_db', 'framework']
      services << 'unrelated' if @native['unrelated']
      counters = services.to_h do |service|
        observations = %w[memory.events pids.events].to_h do |counter|
          output = target_exec(service, 'cat', "/sys/fs/cgroup/#{counter}")
          values = output.each_line.to_h do |line|
            name, value = line.split
            [name, Integer(value, 10)]
          end
          [counter, values]
        end
        [service, observations]
      end
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-resource-counters.json'), JSON.pretty_generate(counters))
      expect(native_after).to eq(@native)
      counters.each do |service, observations|
        memory = observations.fetch('memory.events')
        expect(memory.keys).to include('max', 'oom', 'oom_kill')
        # memory.events:max counts boundary crossings, which can be reclaimed;
        # it is not an OOM count. Retain it without relaxing OOM/PID checks.
        # https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files
        %w[oom oom_kill oom_group_kill].each do |name|
          expect(memory.fetch(name, 0)).to eq(0), "#{service} memory.events #{name}: #{memory[name]}"
        end
        expect(observations.fetch('pids.events').fetch('max')).to eq(0), "#{service} PID limit reached"
      end
    end
  end

  before do |example|
    @workspace = "nifi_module_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows).to eq([])
  end

  discovery_services.each do |service|
    it "identifies the real #{service} release twice" do
      version = @native.fetch('profiles').fetch(service).fetch('version')
      2.times do
        output = scanner('apache_nifi_version', service)
        expect(output).to include("Apache NiFi #{version} found on ")
        expect(output).not_to include('not detected')
      end
    end

    it "does not treat the #{service} branded HTTP 200 error page as a version twice" do
      2.times do
        output = scanner('apache_nifi_version', service, { 'TARGETURI' => '/module-target-missing/' }, allow_errors: true)
        expect(output).to include('Apache NiFi not detected on ')
        expect(output).not_to include(' found on ')
      end
    end
  end

  if discovery_services.include?('legacy')
    it 'does not identify unrelated genuine Apache HTTP as NiFi twice' do
      2.times do
        output = scanner('apache_nifi_version', 'unrelated', {}, allow_errors: true)
        expect(output).to include('Apache NiFi not detected on ')
        expect(output).not_to include(' found on ')
      end
    end
  end

  (discovery_services & %w[vulnerable fixed]).each do |service|
    it "validates and persists exact #{service} credentials twice without duplicates" do
      2.times do
        output = login(service)
        expect(output).to include("Login successful as '#{@accounts.fetch('SINGLE_USER_CREDENTIALS_USERNAME')}'")
        wait_for_credential
        verify_credential(joined_rows.fetch(0), service)
      end
    end

    it "rejects a real #{service} password refusal twice without successful credentials" do
      2.times do
        output = login(service, { 'PASSWORD' => 'module-target-wrong-password' }, allow_errors: true)
        expect(output).to include('Failed to login as ')
        expect(output).not_to include('Login successful')
        expect(rows).to eq([])
      end
    end
  end

  if discovery_services.include?('legacy')
    it 'recognizes that the genuine legacy HTTP instance does not support logins twice' do
      2.times do
        output = login('legacy', {}, allow_errors: true)
        expect(output).to include('User login not supported')
        expect(output).not_to include('Login successful')
        expect(rows).to eq([])
      end
    end

    it 'rejects unrelated HTTP login content twice without credentials' do
      2.times do
        output = login('unrelated', {}, allow_errors: true)
        expect(output).to include('Unexpected response code (404)')
        expect(output).not_to include('Login successful')
        expect(rows).to eq([])
      end
    end
  end

  if discovery_services.include?('vulnerable')
    it 'rejects a branded HTTP 200 error page as a login application twice' do
      2.times do
        output = login('vulnerable', { 'TARGETURI' => '/module-target-missing/' }, allow_errors: true)
        expect(output).to include('Apache NiFi not detected on ')
        expect(output).not_to include('Login successful')
        expect(rows).to eq([])
      end
    end

    it 'keeps the same validated account isolated between two workspaces on repeat' do
      login('vulnerable')
      wait_for_credential
      first = joined_rows
      other = "#{@workspace}_other"
      expect(console_command("workspace -a #{other}")).not_to include('[-]')
      expect(rows(other)).to eq([])
      2.times { login('vulnerable') }
      wait_for_credential(other)
      second = joined_rows(other)
      expect(joined_rows).to eq(first)
      expect(second.fetch(0).fetch('core_id')).not_to eq(first.fetch(0).fetch('core_id'))
      verify_credential(first.fetch(0), 'vulnerable')
      verify_credential(second.fetch(0), 'vulnerable', workspace: other)
    end
  end

  def native_discovery(phase)
    argv = if @discovery_profile == 'all'
             ['python3', '-B', 'test/module_targets/nifi/discovery.py']
           else
             ['python3', '-B', 'test/module_targets/nifi_discovery/native_probe.py', @discovery_profile, phase]
           end
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), "native-discovery-#{phase}-status.json"), JSON.pretty_generate(argv: argv, stderr: error, exitstatus: status.exitstatus, stdout: output))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def scanner(name, service, options = {}, allow_errors: false)
    profile = @native.fetch('profiles')[service]
    defaults = { 'SSL' => profile ? profile.fetch('secure') : false, 'TARGETURI' => '/' }
    defaults['VHOST'] = service if profile
    output = run_target_module("auxiliary/scanner/http/#{name}", service, defaults.merge(options), allow_errors: allow_errors)
    expect(output).not_to include('Unknown datastore option:')
    output
  end

  def login(service, options = {}, allow_errors: false)
    defaults = {
      'USERNAME' => @accounts.fetch('SINGLE_USER_CREDENTIALS_USERNAME'),
      'PASSWORD' => @accounts.fetch('SINGLE_USER_CREDENTIALS_PASSWORD'),
      'USER_FILE' => '', 'PASS_FILE' => '', 'USERPASS_FILE' => '',
      'USER_AS_PASS' => false, 'BLANK_PASSWORDS' => false,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false,
      'BRUTEFORCE_SPEED' => 5, 'STOP_ON_SUCCESS' => true
    }
    scanner('apache_nifi_login', service, defaults.merge(options), allow_errors: allow_errors)
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', "PGPASSWORD=#{@database.fetch('POSTGRES_PASSWORD')}", 'psql', '-h', '127.0.0.1', '-U', @database.fetch('POSTGRES_USER'), '-d', @database.fetch('POSTGRES_DB'), '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows(workspace = @workspace)
    raise ArgumentError, 'Invalid fixture workspace' unless workspace.match?(/\Anifi_module_[0-9_]+(?:_other)?\z/)

    JSON.parse(report_sql(<<~SQL))
      SELECT coalesce(json_agg(record ORDER BY record.core_id), '[]'::json) FROM (
        SELECT core.id AS core_id, workspace.name AS workspace, public.username,
               secret.data AS password, secret.type AS private_type,
               origin.module_full_name, login.status, login.last_attempted_at,
               host(host.address::inet) AS address, service.port, service.proto,
               service.name AS service, login.service_id AS login_service_id,
               origin.service_id AS origin_service_id, host.workspace_id AS host_workspace_id,
               core.workspace_id AS credential_workspace_id
        FROM metasploit_credential_cores core
        JOIN workspaces workspace ON workspace.id=core.workspace_id
        LEFT JOIN metasploit_credential_publics public ON public.id=core.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=core.private_id
        LEFT JOIN metasploit_credential_origin_services origin ON origin.id=core.origin_id AND core.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN metasploit_credential_logins login ON login.core_id=core.id
        LEFT JOIN services service ON service.id=login.service_id
        LEFT JOIN hosts host ON host.id=service.host_id
        WHERE workspace.name='#{workspace}'
      ) record;
    SQL
  end

  def joined_rows(workspace = @workspace)
    records = rows(workspace)
    return [] unless records.length == 1 && records.fetch(0).values_at('login_service_id', 'origin_service_id', 'host_workspace_id').none?(&:nil?)

    records
  end

  def wait_for_credential(workspace = @workspace)
    Timeout.timeout(10) do
      wait_for_expect(100, 0.1) { expect(joined_rows(workspace).length).to eq(1) }
    end
  end

  def verify_credential(record, service, workspace: @workspace)
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    expect(record).to include(
      'workspace' => workspace, 'username' => @accounts.fetch('SINGLE_USER_CREDENTIALS_USERNAME'),
      'password' => @accounts.fetch('SINGLE_USER_CREDENTIALS_PASSWORD'),
      'private_type' => 'Metasploit::Credential::Password',
      'module_full_name' => 'auxiliary/scanner/http/apache_nifi_login',
      'status' => 'Successful', 'address' => endpoint.fetch('host'),
      'port' => endpoint.fetch('port'), 'proto' => 'tcp', 'service' => 'https'
    )
    expect(record.fetch('last_attempted_at')).not_to be_nil
    expect(record.fetch('login_service_id')).to eq(record.fetch('origin_service_id'))
    expect(record.fetch('host_workspace_id')).to eq(record.fetch('credential_workspace_id'))
  end
end
