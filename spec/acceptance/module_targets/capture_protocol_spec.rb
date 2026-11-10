require 'acceptance_spec_helper'
require 'base64'
require 'English'

profile = ENV.fetch('CAPTURE_PROFILE', 'core')
raise ArgumentError, 'Unknown capture profile' unless %w[core mail].include?(profile)

# Family-local client, database and owned listener controls.
module CaptureProtocolControls
  PORTS = { 'ftp' => 2121, 'http_basic' => 8080, 'postgresql' => 15432, 'smtp' => 1025, 'pop3' => 1110, 'imap' => 1143 }.freeze
  SERVICES = { 'ftp' => 'ftp', 'http_basic' => 'http', 'postgresql' => 'psql_client', 'smtp' => 'smtp', 'pop3' => 'pop3', 'imap' => 'imap' }.freeze

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows(workspace = @workspace)
    raise ArgumentError, 'Invalid fixture workspace' unless workspace.match?(/\Acapture_[0-9_]+(?:_other|_guard)?\z/)

    query = <<~SQL
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
    records = JSON.parse(report_sql(query))
    File.write(File.join(target_runtime.fetch('artifacts'), "credentials-#{workspace}.json"), JSON.pretty_generate(records))
    records
  end

  def note_rows
    encoded = JSON.parse(report_sql(<<~SQL))
      SELECT coalesce(json_agg(record ORDER BY record.id), '[]'::json) FROM (
        SELECT note.id,note.ntype,note.data,host(host.address::inet) AS client_address
        FROM notes note JOIN hosts host ON host.id=note.host_id
        JOIN workspaces workspace ON workspace.id=host.workspace_id
        WHERE workspace.name='#{@workspace}'
      ) record;
    SQL
    File.write(File.join(target_runtime.fetch('artifacts'), "notes-#{@workspace}.json"), JSON.pretty_generate(encoded))
    code = "puts 'CAPTURE_NOTES:' + JSON.generate(#{encoded.inspect}.map { |row| row.merge('data' => MetasploitDataModels::Base64Serializer.new.load(row.fetch('data'))) })"
    output = console_command("irb -e #{code.inspect}")
    decoded = output[/^CAPTURE_NOTES:(\[.*\])\r?$/, 1]
    expect(decoded).not_to be_nil, output
    JSON.parse(decoded)
  end

  def native_command(service, *argv)
    request = { service: service, argv: argv }
    command = ['python3', '-B', '-c', "import json,sys;sys.dont_write_bytecode=True;sys.path.insert(0,'test/module_targets/capture_core');from native_client import NativeClients;r=json.loads(sys.argv[1]);print(json.dumps(NativeClients().command(r['service'],*r['argv'])))", JSON.generate(request)]
    output, error, status = Open3.capture3(*command)
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def client(kind, label, credential: true)
    module_name = kind.fetch(:module)
    port = PORTS.fetch(module_name)
    username = kind.fetch(:username) { module_name == 'postgresql' ? accounts.fetch('pg_username') : accounts.fetch('username') }
    password = kind.fetch(:password, accounts.fetch('edge_password'))
    uri = "http://#{listener_host}:#{port}#{kind.fetch(:uri, '/capture')}"
    role = 'curl'
    argv = ['curl', '--silent', '--show-error', '--connect-timeout', '2', '--max-time', '3', '--noproxy', '*', '--include']
    case module_name
    when 'http_basic'
      argv += ['--user', "#{username}:#{password}"] if credential
      argv << '--anyauth' if kind[:challenge]
      argv += ['--header', 'Authorization: Bearer basic-token'] if kind[:bearer]
      argv << uri
    when 'ftp'
      argv += ['--user', "#{username}:#{password}", "ftp://#{listener_host}:#{port}/"]
      if kind[:no_auth]
        role = 'client'
        argv = ['env', "CAPTURE_USERNAME=#{username}", 'python3', '/opt/module-target-client.py', 'ftp-user-only', '--host', listener_host, '--port', port.to_s]
      end
    when 'postgresql'
      role = 'client'
      argv = ['env', "PGHOST=#{listener_host}", "PGPORT=#{port}", "PGUSER=#{username}", "PGDATABASE=#{accounts.fetch('pg_database')}", "PGPASSWORD=#{password}", "PGSSLMODE=#{kind.fetch(:sslmode, 'prefer')}", 'PGGSSENCMODE=disable', 'PGCONNECT_TIMEOUT=2', 'PGPASSFILE=/dev/null', 'PGAPPNAME=module-target-capture-client', 'psql', '-w', '-Atc', 'SELECT current_user']
    when 'imap'
      if kind[:no_auth]
        role = 'client'
        argv = ['python3', '/opt/module-target-client.py', 'imap-no-auth', '--host', listener_host, '--port', port.to_s]
      else
        argv += ['--user', "#{username}:#{password}", '--login-options', 'AUTH=+LOGIN', '--write-out', "\nMODULE_TARGET_TRANSFER_SECONDS=%{time_total}\n", "imap://#{listener_host}:#{port}/"] # rubocop:disable Style/FormatStringToken -- curl write-out syntax
      end
    when 'smtp', 'pop3'
      role = 'client'
      argv = ['env', "CAPTURE_USERNAME=#{username}", "CAPTURE_PASSWORD=#{password}", 'python3', '/opt/module-target-client.py', module_name, '--host', listener_host, '--port', port.to_s, '--mode', kind.fetch(:mode, 'auth')]
    end
    request = { label: label, port: port, service: role, argv: argv }
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/capture_core/run_client.py', JSON.generate(request))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def verify_imap_completion(kind, response, outbound)
    expect(response.dig('result', 'status')).to eq(kind[:no_auth] ? 0 : 67)
    unless kind[:no_auth]
      expect(response.dig('result', 'stdout')).to match(/^MODULE_TARGET_TRANSFER_SECONDS=[0-9]+\.[0-9]+\r?$/)
    end
    inbound = response.fetch('wire').select { |stream| stream.fetch('target') == @native.fetch('client_ip') }.map { |stream| Base64.decode64(stream.fetch('base64')) }.join
    commands = outbound.scan(/^([A-Za-z0-9]+) (CAPABILITY|LOGIN|NOOP|LOGOUT)\b/)
    expect(commands).not_to be_empty
    statuses = { 'CAPABILITY' => 'OK', 'LOGIN' => 'NO', 'NOOP' => 'NO', 'LOGOUT' => 'OK' }
    commands.each do |tag, command|
      replies = inbound.lines.select { |line| line.start_with?("#{tag} ") }
      expect(replies.length).to eq(1), "#{command} tagged replies: #{replies.inspect}"
      expect(replies.first).to match(/\A#{Regexp.escape(tag)} #{statuses.fetch(command)}(?: |\r\n)/)
    end
  end

  def socket_rows(port)
    script = 'rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==ARGV.fetch(0).to_i })'
    JSON.parse(target_exec('framework', 'ruby', '-rjson', '-e', script, port.to_s))
  end

  def start_job(module_name, options = {})
    console_command('back')
    expect(console_command("use auxiliary/server/capture/#{module_name}")).not_to match(/Failed|Unknown command/)
    expect(console_command('unset RedirectURL')).not_to include('[-]') if module_name == 'http_basic'
    values = { 'SRVHOST' => listener_host, 'SRVPORT' => PORTS.fetch(module_name), 'WORKSPACE' => @workspace, 'VERBOSE' => true }.merge(options)
    output = console_command("run -j #{format_datastore_options(values)}")
    expect(output).not_to match(/Exception|Msf::OptionValidateError|\[-\]/)
    identifier = output[/background job (\d+)/, 1]
    expect(identifier).not_to be_nil, output
    wait_for_expect(40, 0.1) { expect(socket_rows(PORTS.fetch(module_name))).not_to eq([]) }
    identifier
  end

  def stop_job(identifier)
    return unless identifier

    jobs = console_command('jobs -l')
    console_command("jobs -k #{identifier}") if jobs.match?(/^\s*#{identifier}\s+/)
  end

  def http_probe(path)
    native_command('curl', 'curl', '--silent', '--show-error', '--max-time', '3', '--noproxy', '*', '--include', "http://#{listener_host}:8080#{path}")
  end

  def pool_receipt
    code = 'puts "CAPTURE_HTTP_POOL:" + JSON.generate(Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server).select { |server| server.listen_port==8080 }.map { |server| {resources:server.resources.keys,references:server.instance_variable_get(:@_references)} })'
    output = console_command("irb -e #{code.inspect}")
    value = output[/^CAPTURE_HTTP_POOL:(\[.*\])\r?$/, 1]
    expect(value).not_to be_nil, output
    pool = JSON.parse(value)
    File.open(File.join(target_runtime.fetch('artifacts'), 'http-resource-cleanup.jsonl'), 'a') { |file| file.puts(JSON.generate(workspace: @workspace, pool: pool)) }
    pool
  end

  def with_listener(kind)
    module_name = kind.fetch(:module)
    @capture_job = @guard_job = nil
    if module_name == 'http_basic'
      guard = "#{@workspace}_guard"
      expect(console_command("workspace -a #{guard}")).not_to include('[-]')
      @guard_job = start_job(module_name, 'URIPATH' => '/guard', 'REALM' => 'Capture guard realm', 'WORKSPACE' => guard)
      expect(console_command("workspace #{@workspace}")).not_to include('[-]')
    end
    options = module_name == 'http_basic' ? { 'URIPATH' => '/capture', 'REALM' => accounts.fetch('http_realm') } : {}
    options['RedirectURL'] = '/captured' if kind[:redirect]
    options['AUTHPROMPT'] = !kind[:data] && !kind[:no_auth] if module_name == 'smtp'
    @capture_job = start_job(module_name, options)
    yield
  ensure
    original = $ERROR_INFO
    begin
      stop_job(@capture_job)
      if module_name == 'http_basic' && @guard_job
        wait_for_expect(30, 0.1) { expect(http_probe('/capture').fetch('stdout')).to include('404') }
        expect(http_probe('/guard').fetch('stdout')).to include('401')
        expect(pool_receipt.flat_map { |server| server.fetch('resources') }).to eq(['/guard'])
        expect(rows("#{@workspace}_guard")).to eq([])
      end
      stop_job(@guard_job)
      expect(console_command('jobs -l')).to include('No active jobs')
      if module_name == 'http_basic'
        expect(pool_receipt.flat_map { |server| server.fetch('resources') }).to eq([])
        observed = socket_rows(PORTS.fetch(module_name))
        expect(http_probe('/capture').fetch('stdout')).to include('404') unless observed.empty?
      else
        wait_for_expect(30, 0.1) { expect(socket_rows(PORTS.fetch(module_name))).to eq([]) }
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      File.open(File.join(target_runtime.fetch('artifacts'), 'cleanup-errors.jsonl'), 'a') { |file| file.puts(JSON.generate(module: module_name, error: e.class.name, message: e.message)) }
      RSpec.world.wants_to_quit = true
      raise unless original
    end
  end

  def verify_record(record, kind, password, workspace: @workspace)
    module_name = kind.fetch(:module)
    username = kind.fetch(:username) { module_name == 'postgresql' ? accounts.fetch('pg_username') : accounts.fetch('username') }
    verify_context(record, kind, workspace: workspace)
    expect(record).to include('username' => username, 'private_data' => password, 'private_type' => password.empty? ? 'Metasploit::Credential::BlankPassword' : 'Metasploit::Credential::Password')
  end

  def verify_context(record, kind, workspace: @workspace)
    module_name = kind.fetch(:module)
    expect(record).to include('workspace' => workspace, 'origin_type' => 'Metasploit::Credential::Origin::Service', 'module_full_name' => "auxiliary/server/capture/#{module_name}", 'client_address' => @native.fetch('client_ip'), 'port' => PORTS.fetch(module_name), 'proto' => 'tcp', 'service' => SERVICES.fetch(module_name), 'status' => 'Untried', 'last_attempted_at' => nil)
    expect(record.fetch('origin_service_id')).to eq(record.fetch('login_service_id'))
    expect(record.fetch('credential_workspace_id')).to eq(record.fetch('host_workspace_id'))
  end
end

core_cases = [
  ['FTP normal', { module: 'ftp', normal: true }],
  ['FTP surrounding spaces, colon, quotes and backslash', { module: 'ftp' }],
  ['FTP password rejected by the genuine fixture remains untried', { module: 'ftp', password: 'module-target-rejected' }],
  ['FTP USER without PASS creates no credential', { module: 'ftp', no_auth: true }],
  ['HTTP Basic challenge', { module: 'http_basic', normal: true, challenge: true }],
  ['HTTP Basic preemptive edge fields', { module: 'http_basic' }],
  ['HTTP Basic empty password', { module: 'http_basic', password: '' }],
  ['HTTP Basic redirect', { module: 'http_basic', redirect: true }],
  ['HTTP request without Authorization', { module: 'http_basic', no_auth: true }],
  ['HTTP unrelated resource', { module: 'http_basic', uri: '/outside', no_record: true }],
  ['HTTP legal Bearer token containing basic', { module: 'http_basic', bearer: true, no_auth: true }],
  ['PostgreSQL SSL prefer', { module: 'postgresql', sslmode: 'prefer' }],
  ['PostgreSQL SSL disable', { module: 'postgresql', sslmode: 'disable' }],
  ['PostgreSQL SSL require sends no plaintext password', { module: 'postgresql', sslmode: 'require', no_record: true }],
  ['PostgreSQL missing password creates no credential', { module: 'postgresql', password: '', no_record: true }]
]
mail_cases = [
  ['SMTP LOGIN challenge', { module: 'smtp', mode: 'LOGIN-challenge' }],
  ['SMTP LOGIN initial response', { module: 'smtp', mode: 'LOGIN' }],
  ['SMTP PLAIN initial response', { module: 'smtp', mode: 'PLAIN' }],
  ['SMTP PLAIN challenge', { module: 'smtp', mode: 'PLAIN-challenge' }],
  ['SMTP CRAM-MD5', { module: 'smtp', mode: 'CRAM-MD5', cram: true }],
  ['SMTP DATA', { module: 'smtp', mode: 'data', data: true }],
  ['SMTP DATA containing a legal RSET line', { module: 'smtp', mode: 'data-rset', data: true }],
  ['SMTP EHLO without credentials', { module: 'smtp', mode: 'no-auth', no_auth: true }],
  ['POP3 edge fields', { module: 'pop3' }],
  ['POP3 rejected fixture password remains untried', { module: 'pop3', password: 'module-target-rejected' }],
  ['POP3 USER without PASS', { module: 'pop3', mode: 'user-only', no_auth: true }],
  ['IMAP ordinary quoted password', { module: 'imap', normal: true }],
  ['IMAP quoted space, colon, quote and backslash fields', { module: 'imap' }],
  ['IMAP commands without LOGIN', { module: 'imap', no_auth: true }],
  ['IMAP legal closing-brace user and password', { module: 'imap', account: 'closing_brace' }],
  ['IMAP legal closing-bracket user and password', { module: 'imap', account: 'closing_bracket' }]
]

RSpec.describe 'Genuine clients of Framework capture servers' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include CaptureProtocolControls

  let_it_be(:accounts) { JSON.parse(File.read('test/module_targets/capture_core/accounts.json')) }

  before(:all) do
    command = ['python3', '-B', "test/module_targets/capture_#{profile}/native_probe.py"]
    output, error, status = Open3.capture3(*command)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-preflight-status.json'), JSON.pretty_generate(argv: command, status: status.exitstatus, stderr: error))
    expect(status.success?).to be(true), error
    @native = JSON.parse(output)
    expect([@native.fetch('commands').length, @native.fetch('wire_captures').length]).to eq(profile == 'core' ? [21, 10] : [35, 13])
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Exception|Error/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    schema = report_sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), schema)
    expect(schema).to include('metasploit_credential_logins|status|', 'metasploit_credential_privates|data|')
    expect(schema).not_to include('metasploit_credential_logins|proof|')
  end

  before do |example|
    @workspace = "capture_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows).to eq([])
  end

  (profile == 'core' ? core_cases : mail_cases).each do |label, original_kind|
    it "#{label} with restart and exact reporting twice" do
      kind = original_kind.dup
      kind[:password] = accounts.fetch('normal_password') if kind.delete(:normal)
      if (imap_account = kind.delete(:account))
        kind[:username] = accounts.fetch("imap_#{imap_account}_username")
        kind[:password] = accounts.fetch("imap_#{imap_account}_password")
      end
      2.times do |iteration|
        with_listener(kind) do
          response = client(kind, "#{@workspace}_#{iteration}", credential: !kind[:no_auth])
          outbound = response.fetch('wire').select { |stream| stream.fetch('source') == @native.fetch('client_ip') }.map { |stream| Base64.decode64(stream.fetch('base64')) }.join
          expect(outbound).not_to be_empty
          if kind[:data]
            expected = outbound[/(?:\A|\r\n)DATA\r\n(.*?)\r\n\.\r\n/mi, 1]
            expect(expected).not_to be_nil
            records = note_rows
            expect(records.length).to eq(1)
            expect(records.first).to include('ntype' => 'smtp_message', 'client_address' => @native.fetch('client_ip'), 'data' => { 'message' => expected })
            expect(rows).to eq([])
          elsif kind[:no_auth] || kind[:no_record]
            expect(rows).to eq([])
            expect(response.dig('result', 'stdout')).to include(kind[:bearer] || kind[:no_auth] ? '401' : '404') if kind.fetch(:module) == 'http_basic'
          elsif kind[:cram]
            require 'openssl'
            inbound = response.fetch('wire').select { |stream| stream.fetch('target') == @native.fetch('client_ip') }.map { |stream| Base64.decode64(stream.fetch('base64')) }.join
            challenge = Base64.decode64(inbound[%r{334 ([A-Za-z0-9+/=]+)\r\n}, 1])
            digest = OpenSSL::HMAC.hexdigest('MD5', accounts.fetch('edge_password'), challenge)
            records = rows
            expect(records.length).to eq(iteration + 1)
            record = records.find { |row| row.fetch('private_data') == "#{challenge}##{digest}" }
            expect(record).not_to be_nil
            verify_context(record, kind)
            expect(record).to include('username' => accounts.fetch('username'), 'private_type' => 'Metasploit::Credential::NonreplayableHash', 'status' => 'Untried')
          else
            records = rows
            expect(records.length).to eq(1)
            verify_record(records.first, kind, kind.fetch(:password, accounts.fetch('edge_password')))
            expect(response.dig('result', 'stdout')).to include(kind[:redirect] ? '302' : '404') if kind.fetch(:module) == 'http_basic'
          end
          verify_imap_completion(kind, response, outbound) if kind.fetch(:module) == 'imap'
        end
      end
    end
  end

  if profile == 'core'
    it 'keeps captured credentials isolated when the console workspace changes' do
      first = @workspace
      other = "#{@workspace}_other"
      expect(console_command("workspace -a #{other}")).not_to include('[-]')
      expect(rows(other)).to eq([])
      expect(console_command("workspace #{first}")).not_to include('[-]')
      kind = { module: 'http_basic' }
      with_listener(kind) do
        expect(console_command("workspace #{other}")).not_to include('[-]')
        2.times { |iteration| client(kind, "#{first}_isolation_#{iteration}") }
        records = rows(first)
        expect(records.length).to eq(1)
        verify_record(records.first, kind, accounts.fetch('edge_password'), workspace: first)
        expect(rows(other)).to eq([])
      end
    end
  end
end

# Stop after a transport boundary failure rather than mislabeling later examples.
module CaptureProtocolTransportBoundary
  def console_command(command, timeout: 40)
    raise Acceptance::ChildProcessRecvError, 'Capture console failed; diagnostic stopped' if @capture_console_broken

    super
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError, EOFError, Errno::EPIPE
    @capture_console_broken = true
    RSpec.world.wants_to_quit = true
    raise
  end
end

group = RSpec.world.example_groups.find { |item| item.description == 'Genuine clients of Framework capture servers' }
raise 'Capture target group is missing' unless group

group.prepend(CaptureProtocolTransportBoundary)
