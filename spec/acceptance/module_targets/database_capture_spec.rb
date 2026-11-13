require 'acceptance_spec_helper'
require 'base64'
require 'English'
require 'timeout'

profile = ENV.fetch('DATABASE_CAPTURE_PROFILE', 'mysql')
raise ArgumentError, 'Unknown database capture profile' unless %w[mysql mssql].include?(profile)

mysql_client = ENV.fetch('MYSQL_CAPTURE_CLIENT', 'all')
raise ArgumentError, 'Unknown MySQL capture client' unless %w[all oracle_client mariadb_client].include?(mysql_client)

# Family-local controls retain native clients, direct SQL and actual packet evidence.
module DatabaseCaptureControls
  PORTS = { 'mysql' => 13306, 'mssql' => 11433 }.freeze
  MYSQL_NUL_CHALLENGE = '00112233445566778899aabbccddeeff00112233'.freeze

  def capture_challenge(kind)
    return accounts.fetch('ntlm_challenge') if @profile == 'mssql'
    return MYSQL_NUL_CHALLENGE if kind[:nul_challenge]
    return @native.fetch('native_challenge') if kind[:native_challenge]

    accounts.fetch('challenge').downcase
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows(workspace = @workspace)
    raise ArgumentError, 'Invalid fixture workspace' unless workspace.match?(/\Adbcapture_[0-9_]+(?:_other)?\z/)

    records = JSON.parse(report_sql(<<~SQL))
      SELECT coalesce(json_agg(record ORDER BY record.core_id), '[]'::json) FROM (
        SELECT core.id AS core_id, workspace.name AS workspace, public.username,
               secret.data AS private_data, secret.type AS private_type, secret.jtr_format,
               core.origin_type, origin.module_full_name, login.status, login.last_attempted_at,
               host(host.address::inet) AS client_address, service.port, service.proto,
               service.name AS service, host.workspace_id AS host_workspace_id,
               core.workspace_id AS credential_workspace_id, login.service_id AS login_service_id,
               origin.service_id AS origin_service_id
        FROM metasploit_credential_cores core
        JOIN workspaces workspace ON workspace.id=core.workspace_id
        LEFT JOIN metasploit_credential_publics public ON public.id=core.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=core.private_id
        LEFT JOIN metasploit_credential_logins login ON login.core_id=core.id
        LEFT JOIN services service ON service.id=login.service_id
        LEFT JOIN hosts host ON host.id=service.host_id
        LEFT JOIN metasploit_credential_origin_services origin ON origin.id=core.origin_id
             AND core.origin_type='Metasploit::Credential::Origin::Service'
        WHERE workspace.name='#{workspace}'
      ) record;
    SQL
    File.write(File.join(target_runtime.fetch('artifacts'), "credentials-#{workspace}.json"), JSON.pretty_generate(records))
    records
  end

  def ready_records(expected_count, workspace: @workspace)
    probes = []
    records = nil
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    Timeout.timeout(10) do
      wait_for_expect(40, 0.1) do
        records = rows(workspace)
        probes << { elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, records: records }
        expect(records.length).to eq(expected_count)
        joined_ids = records.flat_map { |record| record.values_at('login_service_id', 'origin_service_id', 'host_workspace_id') }
        expect(joined_ids).not_to include(nil)
      end
    end
    records
  ensure
    File.open(File.join(target_runtime.fetch('artifacts'), 'sql-readiness.jsonl'), 'a') { |file| file.puts(JSON.generate(workspace: workspace, expected_count: expected_count, probes: probes)) }
  end

  def socket_rows
    script = 'rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==ARGV.fetch(0).to_i })'
    JSON.parse(target_exec('framework', 'ruby', '-rjson', '-e', script, PORTS.fetch(@profile).to_s))
  end

  def hash_files
    script = 'puts JSON.generate(Dir.glob(ARGV.fetch(0)+"_*").to_h { |path| [path.delete_prefix(ARGV.fetch(0)),File.binread(path)] })'
    JSON.parse(target_exec('framework', 'ruby', '-rjson', '-e', script, @john_prefix))
  end

  def with_listener(kind)
    @capture_job = nil
    options = { 'SRVHOST' => listener_host, 'SRVPORT' => PORTS.fetch(@profile), 'WORKSPACE' => @workspace, 'VERBOSE' => true, 'JOHNPWFILE' => @john_prefix }
    options['CHALLENGE'] = capture_challenge(kind)
    options['SRVVERSION'] = @native.fetch('server_version') if @profile == 'mysql' && kind[:native_challenge]
    options['SMB_EXTENDED_SECURITY'] = kind.fetch(:extended, false) if @profile == 'mssql'
    options['DOMAIN_NAME'] = accounts.fetch('ntlm_domain') if @profile == 'mssql'
    console_command('back')
    expect(console_command("use auxiliary/server/capture/#{@profile}")).not_to match(/Failed|Unknown command/)
    output = console_command("run -j #{format_datastore_options(options)}")
    expect(output).not_to match(/Exception|Msf::OptionValidateError|\[-\]/)
    @capture_job = output[/background job (\d+)/, 1]
    expect(@capture_job).not_to be_nil, output
    wait_for_expect(40, 0.1) { expect(socket_rows).not_to eq([]) }
    yield
  ensure
    original = $ERROR_INFO
    begin
      if @capture_job && console_command('jobs -l').match?(/^\s*#{@capture_job}\s+/)
        console_command("jobs -k #{@capture_job}")
      end
      expect(console_command('jobs -l')).to include('No active jobs')
      wait_for_expect(30, 0.1) { expect(socket_rows).to eq([]) }
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      File.open(File.join(target_runtime.fetch('artifacts'), 'cleanup-errors.jsonl'), 'a') { |file| file.puts(JSON.generate(error: e.class.name, message: e.message)) }
      RSpec.world.wants_to_quit = true
      raise unless original
    end
  end

  def client(kind, label)
    kind = { client: @mysql_client }.merge(kind) if @profile == 'mysql' && @mysql_client != 'all'
    request = { profile: @profile, kind: kind, label: label, host: listener_host, port: PORTS.fetch(@profile), client_ip: @native.fetch('client_ip'), prelogin_hex: @native['prelogin_hex'] }
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/database_capture/run_client.py', JSON.generate(request))
    expect(status.success?).to be(true), error
    response = JSON.parse(output)
    expect(response['analysis_error']).to be_nil, response.inspect
    response
  end

  def verify_record(record, response, kind, workspace: @workspace)
    decoded = response.fetch('decoded')
    username = kind.fetch(:username, accounts.fetch('username'))
    password = kind.fetch(:password, accounts.fetch('password'))
    if @profile == 'mysql'
      expect(decoded.fetch('login')).to include('username' => username, 'database' => kind[:without_database] ? nil : accounts.fetch('database'))
      challenge = capture_challenge(kind)
      expect(decoded.fetch('greeting')).to include('seed' => challenge, 'plugin' => 'mysql_native_password')
      expect([challenge].pack('H*')).to include("\x00") if kind[:nul_challenge]
      expect(decoded.fetch('greeting').fetch('version')).to eq(kind[:native_challenge] ? @native.fetch('server_version') : '5.5.16')
      expect(decoded.fetch('greeting').fetch('capabilities') & 0x800).to eq(0)
      private_data = "#{username}:$mysql$#{challenge}$#{decoded.fetch('native_response')}"
      private_type = 'Metasploit::Credential::NonreplayableHash'
      format = nil
      @expected_john['_mysqlna'] << "#{username}:$mysqlna$#{challenge}*#{decoded.fetch('native_response')}\n"
    elsif kind[:ntlm]
      expect(decoded).to include('username' => accounts.fetch('ntlm_username'), 'domain' => accounts.fetch('ntlm_domain'), 'challenge' => accounts.fetch('ntlm_challenge'))
      expect(decoded.fetch('flags') & 0x80000).to eq(kind[:extended] ? 0x80000 : 0)
      private_data = decoded.fetch('private_data')
      private_type = 'Metasploit::Credential::NonreplayableHash'
      format = kind.fetch(:ntlm) == 'yes' ? 'netntlmv2' : 'netntlm'
      expect(decoded.fetch('jtr_format')).to eq(format)
      username = accounts.fetch('ntlm_username')
      decoded.fetch('john').each { |suffix, line| @expected_john[suffix] << line + "\n" }
    else
      expect(decoded).to include('username' => username, 'password' => password, 'database' => accounts.fetch('database'), 'application' => 'TSQL')
      private_data = password
      private_type = password.empty? ? 'Metasploit::Credential::BlankPassword' : 'Metasploit::Credential::Password'
      format = nil
    end
    expect(record).to include('workspace' => workspace, 'username' => username, 'private_data' => private_data, 'private_type' => private_type, 'jtr_format' => format, 'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => "auxiliary/server/capture/#{@profile}", 'client_address' => @native.fetch('client_ip'), 'port' => PORTS.fetch(@profile), 'proto' => 'tcp', 'service' => "#{@profile}_client", 'status' => 'Untried', 'last_attempted_at' => nil)
    expect(record.fetch('origin_service_id')).to eq(record.fetch('login_service_id'))
    expect(record.fetch('credential_workspace_id')).to eq(record.fetch('host_workspace_id'))
    expect(hash_files).to eq(@expected_john)
  end
end

mysql_cases = [
  ['Oracle native password with edge fields', {}],
  ['Oracle default TLS negotiation', { default_tls: true }],
  ['MariaDB default TLS negotiation', { client: 'mariadb_client', default_tls: true }],
  ['MariaDB native password with edge fields', { client: 'mariadb_client' }],
  ['Oracle native password without a database', { without_database: true }],
  ['Rejected native password stays untried', { password: 'module-target-db-rejected' }],
  ['Oracle binary response ending NUL', { username: 'capture_tail0', password_key: 'tail_0_password' }],
  ['MariaDB binary response ending NUL', { client: 'mariadb_client', username: 'capture_tail0', password_key: 'tail_0_password' }],
  ['Oracle binary response ending space', { username: 'capture_tail32', password_key: 'tail_32_password' }],
  ['MariaDB binary response ending space', { client: 'mariadb_client', username: 'capture_tail32', password_key: 'tail_32_password' }],
  ['Oracle empty response creates no hash', { username: 'capture_empty', password: '', no_record: true }],
  ['MariaDB empty response creates no hash', { client: 'mariadb_client', username: 'capture_empty', password: '', no_record: true }],
  ['Real native seed and custom version', { native_challenge: true }],
  ['Oracle configured challenge containing literal NUL bytes', { nul_challenge: true }],
  ['MariaDB configured challenge containing literal NUL bytes', { client: 'mariadb_client', nul_challenge: true }],
  ['Required TLS sends no password to the non-TLS listener', { tls: true, no_record: true }],
  ['Greeting-only client sends no credentials', { no_auth: true }]
]
mysql_cases = mysql_cases.select { |_label, kind| kind.fetch(:client, 'oracle_client') == mysql_client } unless mysql_client == 'all'
mssql_cases = [
  ['TDS7.1 SQL authentication with edge fields', { tds: '7.1' }],
  ['TDS7.4 SQL authentication with edge fields', { tds: '7.4' }],
  ['Rejected native SQL password stays untried', { password: 'module-target-db-rejected', tds: '7.4' }],
  ['TDS7.1 empty SQL password', { username: 'capture_empty', password: '', tds: '7.1' }],
  ['TDS7.4 empty SQL password', { username: 'capture_empty', password: '', tds: '7.4' }],
  ['NTLMv2 without extended-session flag', { ntlm: 'yes' }],
  ['NTLMv2 with extended-session flag', { ntlm: 'yes', extended: true }],
  ['NTLMv1 without extended-session flag', { ntlm: 'no' }],
  ['NTLMv1 with extended-session flag', { ntlm: 'no', extended: true }],
  ['Native FreeTDS PRELOGIN-only bytes create no credential', { no_auth: true }]
]

RSpec.describe 'Genuine clients of Framework database capture servers' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include DatabaseCaptureControls

  let_it_be(:accounts) { JSON.parse(File.read('test/module_targets/database_capture/accounts.json')) }

  before(:all) do
    @profile = profile
    @mysql_client = mysql_client
    command = ['python3', '-B', "test/module_targets/capture_#{@profile}/native_probe.py"]
    command << 'before' if @profile == 'mysql'
    output, error, status = Open3.capture3(*command)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-preflight-status.json'), JSON.pretty_generate(argv: command, status: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    if @profile == 'mysql'
      clients = @native.fetch('clients').length
      servers = @native.fetch('servers').length
      expect([@native.fetch('commands').length, @native.fetch('wire_captures').length]).to eq([2 + clients + (3 * servers) + (6 * clients * servers), (6 * clients * servers) + servers])
    else
      expect([@native.fetch('commands').length, @native.fetch('wire_captures').length]).to eq([14, 9])
    end
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Exception|Error/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    schema = report_sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), schema)
    expect(schema).to include('metasploit_credential_logins|status|', 'metasploit_credential_privates|data|')
    expect(schema).not_to include('metasploit_credential_logins|proof|')
  end

  after(:all) do
    if @native && @profile == 'mysql' && @mysql_client != 'all'
      command = ['python3', '-B', 'test/module_targets/capture_mysql/native_probe.py', 'after']
      output, error, status = Open3.capture3(*command)
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-postflight-status.json'), JSON.pretty_generate(argv: command, status: status.exitstatus, stderr: error, stdout: output))
      expect(status.success?).to be(true), error
      native_after = JSON.parse(output)
      expect(native_after.fetch('state')).to eq(@native.fetch('state'))
      expect(native_after.fetch('client_ip')).to eq(@native.fetch('client_ip'))
      expect([native_after.fetch('commands').length, native_after.fetch('wire_captures').length]).to eq([11, 7])
      expect(console_command('jobs -l')).to include('No active jobs')
      expect(socket_rows).to eq([])
      services = ['client', 'framework', 'reporting_db', @mysql_client, ENV.fetch('MYSQL_CAPTURE_SERVER')]
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
      counters.each do |service, observations|
        %w[oom oom_kill oom_group_kill].each do |key|
          expect(observations.fetch('memory.events').fetch(key, 0)).to eq(0), "#{service} memory #{key}"
        end
        expect(observations.fetch('pids.events').fetch('max')).to eq(0), "#{service} PID limit reached"
      end
    end
  end

  before do |example|
    @workspace = "dbcapture_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    @john_prefix = File.join(target_runtime.fetch('artifacts'), "john-#{@workspace}")
    @expected_private_data = []
    @expected_john = Hash.new { |hash, suffix| hash[suffix] = String.new }
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows).to eq([])
    expect(hash_files).to eq({})
  end

  (profile == 'mysql' ? mysql_cases : mssql_cases).each do |label, original_kind|
    it "#{label} with exact capture and listener restart twice" do
      kind = original_kind.dup
      kind[:password] = accounts.fetch(kind.delete(:password_key)) if kind[:password_key]
      2.times do |iteration|
        with_listener(kind) do
          response = client(kind, "#{@workspace}_#{iteration}")
          expect(response.dig('result', 'status')).to eq(kind[:no_auth] ? 0 : 1)
          if kind[:no_auth] || kind[:no_record]
            records = rows
            expect(records).to eq([])
            expect(hash_files).to eq({})
          else
            if kind[:ntlm]
              @expected_private_data << response.fetch('decoded').fetch('private_data')
              records = ready_records(@expected_private_data.uniq.length)
              expect(records.map { |row| row.fetch('private_data') }).to contain_exactly(*@expected_private_data.uniq)
            else
              records = ready_records(1)
              expect(records.length).to eq(1)
            end
            record = kind[:ntlm] ? records.find { |row| row.fetch('private_data') == response.dig('decoded', 'private_data') } : records.first
            expect(record).not_to be_nil
            verify_record(record, response, kind)
          end
        end
      end
    end
  end

  it 'rejects malformed challenge input without a listener or credential twice' do
    2.times do
      console_command('back')
      console_command("use auxiliary/server/capture/#{@profile}")
      output = console_command("run -j SRVHOST=#{listener_host} SRVPORT=#{DatabaseCaptureControls::PORTS.fetch(@profile)} CHALLENGE=not-hex WORKSPACE=#{@workspace}")
      expect(output).to match(/background job \d+/)
      wait_for_expect(40, 0.1) do
        jobs = console_command('jobs -l')
        output << jobs
        expect(output).to include('CHALLENGE syntax')
        expect(jobs).to include('No active jobs')
      end
      expect(socket_rows).to eq([])
      expect(rows).to eq([])
      expect(console_command('jobs -l')).to include('No active jobs')
    end
  end

  it 'keeps captures in the listener workspace after the console workspace changes' do
    first = @workspace
    other = "#{first}_other"
    expect(console_command("workspace -a #{other}")).not_to include('[-]')
    expect(console_command("workspace #{first}")).not_to include('[-]')
    with_listener({}) do
      expect(console_command("workspace #{other}")).not_to include('[-]')
      2.times do |iteration|
        response = client({}, "#{first}_isolation_#{iteration}")
        records = ready_records(1, workspace: first)
        expect(records.length).to eq(1)
        verify_record(records.first, response, {}, workspace: first)
        expect(rows(other)).to eq([])
      end
    end
  end
end

# A broken console boundary ends diagnostics before later labels can be poisoned.
module DatabaseCaptureTransportBoundary
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessRecvError, 'Database capture console failed; diagnostic stopped' if @database_capture_console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @database_capture_console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Genuine clients of Framework database capture servers' }
raise 'Database capture target group is missing' unless group

group.prepend(DatabaseCaptureTransportBoundary)
