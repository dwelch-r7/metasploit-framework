# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native Drupal PostgreSQL target' do
  include_context 'module target'

  before(:all) do
    @drpg_profile = DrupalPgsqlProfiles.fetch
    @drpg_native = { requests: [], commands: [], calls: [], reports: [], controls: [] }
    begin
      drpg_counters('before')
      @drpg_baseline = drpg_identity unless @drpg_profile.fetch('mode') == 'unrelated'
      drpg_native_controls('before')
      expect(drpg_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      endpoint = target_endpoint('db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      output = console_command('irb -e \'puts "DRPG_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/drupal_pgsql_entityquery_sqli.rb").hexdigest, has_check: framework.modules.create("auxiliary/scanner/http/drupal_pgsql_entityquery_sqli").has_check?}.to_json\'')
      @drpg_native[:provenance] = JSON.parse(output.match(/^DRPG_PROVENANCE=(.+)$/)[1])
      expect(@drpg_native[:provenance].values_at('config', 'owner_sha256', 'has_check')).to eq([ENV.fetch('MSF_CFGROOT_CONFIG'), Digest::SHA256.file("modules/#{DrupalPgsqlProfiles::OWNER}.rb").hexdigest, true])
      @drpg_native[:preflight] = 'passed'
    ensure
      drpg_save
    end
  end

  before do |example|
    @drpg_workspace = 'drpg_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@drpg_workspace}")).not_to include('[-]')
    expect(drpg_reports.values).to all(eq([]))
  end

  after(:all) do
    drpg_native_controls('after') if @drpg_native&.key?(:preflight)
    expect(console_command('irb -e \'puts "DRPG_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('DRPG_STATE={"sessions":[],"jobs":[]}') if @drpg_native&.key?(:provenance)
  ensure
    drpg_counters('after') if @drpg_profile
    drpg_save
  end

  def drpg_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-drupal-pgsql.json'), JSON.pretty_generate(@drpg_native)) if @drpg_native
  end

  def drpg_command(role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @drpg_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    drpg_save
    raise "Native Drupal command failed: #{role}: #{error}" unless status.success?

    output
  end

  def drpg_identity
    JSON.parse(drpg_command('app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def drpg_request(label, path, query = nil)
    path += '?' + URI.encode_www_form(query) if query
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    http.max_retries = 0
    request = Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    @drpg_native.fetch(:requests) << { label: label, path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: elapsed }
    drpg_save
    [response, elapsed]
  ensure
    http&.finish if http&.started?
  end

  def drpg_filter(field, values)
    { 'filter[native][condition][path]' => field, 'filter[native][condition][operator]' => 'IN' }.merge(values.transform_keys { |key| "filter[native][condition][value][#{key}]" })
  end

  def drpg_native_controls(phase)
    mode = @drpg_profile.fetch('mode')
    if mode == 'unrelated'
      expect(drpg_request(phase + '-unrelated', '/').first.body).to include('module-target-http-marker')
    else
      actual = drpg_identity
      driver = @drpg_profile.fetch('database')
      expect(actual.values_at('drupal', 'php', 'uid', 'driver', 'prefix', 'mode')).to eq([@drpg_profile.fetch('release'), '8.4.8', 33, driver, @drpg_profile.fetch('prefix'), mode])
      if driver == 'pgsql'
        expect(actual.values_at('database_role', 'database_role_superuser', 'database_grants')).to eq(['module_target', false, nil])
      else
        expect(actual.values_at('database_role', 'database_role_superuser')).to eq(['module_target@%', nil])
        expect(actual.fetch('server')).to start_with('11.2.2-MariaDB')
        grants = actual.fetch('database_grants')
        expect(grants.length).to eq(2)
        expect(grants).to include(start_with('GRANT USAGE ON *.* TO "module_target"@"%"'), 'GRANT ALL PRIVILEGES ON "drupal_root".* TO "module_target"@"%"')
      end
      expect(actual.fetch('connection_class')).to eq("Drupal\\#{driver}\\Driver\\Database\\#{driver}\\Connection")
      expect(actual.fetch('installed_modules')).to include(driver)
      release = DrupalPgsqlProfiles::RELEASES.fetch(@drpg_profile.fetch('release'))
      expect(actual.values_at('archive_sha256', 'critical_sha256')).to eq(release.values_at('sha256', 'critical_sha256'))
      expect(actual.fetch('fields').fetch('field_module_marker').fetch('case_sensitive')).to be(false)
      expect(actual.fetch('fields').fetch('field_case_marker').fetch('case_sensitive')).to be(true)
      expect(actual.fetch('anonymous_access_content')).to eq(mode != 'private')
      expect(actual.fetch('installed_modules').include?('jsonapi')).to eq(mode != 'disabled')
      expect(actual.fetch('nodes').length).to eq(mode == 'empty' ? 0 : 1)
      prefix = @drpg_profile.fetch('prefix')
      login = drpg_request(phase + '-login', "#{prefix}/user/login").first
      expect(login.code).to eq('200')
      expect(login.body).to include('user-login-form', 'name="name"', 'name="pass"')
      path = "#{prefix}/jsonapi/node/article"
      response = drpg_request(phase + '-jsonapi', path).first
      @drpg_native[:baseline_http_status] = response.code
      if mode == 'disabled'
        expect(response.code).to eq('404')
      elsif mode == 'private'
        expect(response.code).to eq('200')
        document = JSON.parse(response.body)
        expect(document.fetch('data')).to eq([])
        omitted = document.fetch('meta').fetch('omitted')
        expect(omitted.fetch('detail')).to eq('Some resources have been omitted because of insufficient authorization.')
        items = omitted.fetch('links').values.select { |item| item.dig('meta', 'rel') == 'item' }
        expect(items.length).to eq(1)
        expect(items.first.fetch('href')).to end_with('/' + actual.fetch('nodes').first.fetch('uuid'))
        expect(items.first.dig('meta', 'detail')).to include("The 'access content' permission is required.")
      else
        expect(response.code).to eq('200')
        data = JSON.parse(response.body).fetch('data')
        expect(data.length).to eq(mode == 'empty' ? 0 : 1)
        unless mode == 'empty'
          expect(data.first.values_at('id', 'type')).to eq([actual.fetch('nodes').first.fetch('uuid'), 'node--article'])
          expect(data.first.fetch('attributes').fetch('title')).to eq('Module native café article')
          [
            ['empty', 'title', 'native-no-match', 0],
            ['title', 'title', 'MODULE NATIVE CAFÉ ARTICLE', 1],
            ['custom', 'field_module_marker', 'MODULE NATIVE MARKER', 1],
            ['case-sensitive', 'field_case_marker', 'MODULE CASE MARKER', 0]
          ].each do |label, field, value, count|
            ordinary = drpg_request(phase + '-normal-' + label, path, drpg_filter(field, '0' => value, '1' => 'native-no-match-B')).first
            expect(ordinary.code).to eq('200')
            expect(JSON.parse(ordinary.body).fetch('data').length).to eq(count)
          end
          timings = %w[false true].to_h do |truth|
            condition = truth == 'true' ? '1=1' : '1=2'
            payload = "1=(case when #{condition} then (select 1 from pg_sleep(0.8)) else 1 end)"
            key = "1))/**/OR/**/(#{payload})::text=((chr(49)"
            # Core caches identical anonymous GETs. Distinct values keep each
            # timing control a fresh database query, as the owner module does.
            values = { '0' => "native-#{phase}-#{truth}-A", '1' => "native-#{phase}-#{truth}-B", key => "native-#{phase}-#{truth}-C" }
            reply, seconds = drpg_request(phase + '-injection-' + truth, path, drpg_filter('title', values))
            expect(reply.code).to eq('200')
            [truth, seconds]
          end
          if mode == 'affected'
            expect(timings.fetch('true')).to be >= 0.7
            expect(timings.fetch('true') - timings.fetch('false')).to be >= 0.55
          else
            expect(timings.values.max).to be < 0.65
          end
        end
      end
      drpg_unchanged
    end
    @drpg_native.fetch(:controls) << { phase: phase, status: 'passed' }
    drpg_save
  end

  def drpg_unchanged
    expect(drpg_identity).to eq(@drpg_baseline) if @drpg_baseline
  end

  def drpg_sql(query)
    drpg_command('db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def drpg_reports
    raise ArgumentError, 'Invalid Drupal workspace' unless @drpg_workspace.match?(/\Adrpg_[0-9_]+\z/)

    services = JSON.parse(drpg_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.name,s.state FROM services s
        JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@drpg_workspace}'
      ) row
    SQL
    vulns = JSON.parse(drpg_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
          (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
        FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@drpg_workspace}'
      ) row
    SQL
    result = { 'services' => services, 'vulns' => vulns }
    @drpg_native.fetch(:reports) << { workspace: @drpg_workspace, rows: result }
    drpg_save
    result
  end

  def drpg_run(options = {}, expected:, service_report:)
    %w[run check].each { |action| drpg_owner(options, expected: expected, service_report: service_report, action: action) }
  end

  def drpg_owner(options = {}, expected:, service_report:, action: 'run')
    @drpg_native.fetch(:calls) << { action: action, workspace: @drpg_workspace, options: options, state: 'started' }
    drpg_save
    output = run_target_module(DrupalPgsqlProfiles::OWNER, 'app', { 'SSL' => false, 'TARGETURI' => @drpg_profile.fetch('prefix') + '/', 'SqliDelay' => 0.8, 'HttpClientTimeout' => 5 }.merge(options), allow_errors: true, command_timeout: 65, action: action)
    @drpg_native.fetch(:calls).last.merge!(state: 'returned', output_base64: Base64.strict_encode64(output.b))
    drpg_save
    expect(output).not_to match(/Auxiliary (?:failed|aborted)|Exception|undefined method|Unknown command|LocalJumpError|Unknown datastore option/)
    expect(output).to include(expected)
    reports = drpg_reports
    endpoint = target_endpoint('app')
    if service_report
      expect(reports.fetch('services').length).to eq(1)
      expect(reports.fetch('services').first.values_at('host', 'port', 'proto', 'name', 'state')).to eq([endpoint.fetch('host'), endpoint.fetch('port'), 'tcp', 'http', 'open'])
    else
      expect(reports.fetch('services')).to eq([])
    end
    if expected == 'Time-based blind SQL injection via JSON:API filter array key'
      expect(reports.fetch('vulns').length).to eq(1)
      vuln = reports.fetch('vulns').first
      expect(vuln.values_at('host', 'service_id', 'name')).to eq([endpoint.fetch('host'), reports.fetch('services').first.fetch('id'), 'Drupal Core PostgreSQL EntityQuery SQL Injection'])
      expect(vuln.fetch('info')).to include(expected).or eq("Vulnerability confirmed by check of #{DrupalPgsqlProfiles::OWNER}.")
      expect(vuln.fetch('refs')).to include('CVE-2026-9082')
    else
      expect(reports.fetch('vulns')).to eq([])
    end
    expect(Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '**', '*')].select { |path| File.file?(path) }).to eq([])
    drpg_unchanged
    output
  end

  def drpg_counters(phase)
    roles = %w[app db]
    roles << 'mysql' if @drpg_profile['database'] == 'mysql'
    values = roles.to_h do |role|
      counters = %w[memory.events pids.events].to_h do |name|
        numbers = target_exec(role, 'cat', "/sys/fs/cgroup/#{name}").lines.to_h do |line|
          key, value = line.split
          [key, Integer(value, 10)]
        end
        [name, numbers]
      end
      [role, counters]
    end
    File.write(File.join(target_runtime.fetch('artifacts'), "drupal-pgsql-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
