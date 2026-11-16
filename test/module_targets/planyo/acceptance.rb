# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native Planyo target' do
  include_context 'module target'

  before(:all) do
    @planyo_profile = PlanyoProfiles.fetch
    @planyo_native = { requests: [], commands: [], calls: [], controls: [], loots: [] }
    begin
      planyo_counters('before')
      @planyo_baseline = planyo_identity unless @planyo_profile.fetch('mode') == 'unrelated'
      planyo_native_controls('before')
      output = console_command('irb -e \'puts "PLANYO_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/gather/wp_planyo_lfi_cve_2026_3576.rb").hexdigest}.to_json\'')
      @planyo_native[:provenance] = JSON.parse(output.match(/^PLANYO_PROVENANCE=(.+)$/)[1])
      expect(@planyo_native[:provenance].fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(@planyo_native[:provenance].fetch('owner_sha256')).to eq(Digest::SHA256.file("modules/#{PlanyoProfiles::OWNER}.rb").hexdigest)
      @planyo_native[:preflight] = 'passed'
    ensure
      planyo_save
    end
  end

  after(:all) do
    planyo_native_controls('after') if @planyo_native&.key?(:preflight)
    expect(console_command('irb -e \'puts "PLANYO_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('PLANYO_STATE={"sessions":[],"jobs":[]}') if @planyo_native&.key?(:provenance)
  ensure
    planyo_counters('after') if @planyo_profile
    planyo_save
  end

  def planyo_prefix
    @planyo_profile.fetch('prefix')
  end

  def planyo_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-planyo.json'), JSON.pretty_generate(@planyo_native)) if @planyo_native
  end

  def planyo_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '20', 'php', '/opt/module-target/control.php']
    output, error, status = Open3.capture3(*argv)
    @planyo_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    planyo_save
    raise "Native Planyo inspection failed: #{error}" unless status.success?

    JSON.parse(output)
  end

  def planyo_request(path)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path))
    @planyo_native.fetch(:requests) << { path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    planyo_save
    response
  ensure
    http&.finish if http&.started?
  end

  def planyo_file_request(path)
    # Independent native client: encode each file-path segment, then the HTTP
    # query parameter. Literal %, query syntax and UTF-8 bytes stay file data.
    file_path = path.split('/', -1).map { |part| URI.encode_www_form_component(part).gsub('+', '%20') }.join('/')
    query = URI.encode_www_form('ulap_url' => 'file://localhost' + file_path)
    planyo_request("#{planyo_prefix}/wp-content/plugins/planyo-online-reservation-system/ulap.php?#{query}")
  end

  def planyo_native_controls(phase)
    mode = @planyo_profile.fetch('mode')
    if mode == 'unrelated'
      response = planyo_request('/')
      expect(response.code).to eq('200')
      expect(response.body).to include('module-target-http-marker')
    else
      actual = planyo_identity
      expect(actual.values_at('core', 'php', 'uid', 'prefix')).to eq(['6.8.3', '8.3.28', 33, planyo_prefix])
      expect(actual.fetch('db_error')).to eq('')
      expect(planyo_request("#{planyo_prefix}/wp-login.php").body).to include('name="log"', 'name="pwd"')
      expect(planyo_request("#{planyo_prefix}/").code).to eq('200')
      installed = mode != 'absent'
      active = installed && mode != 'inactive'
      expect(actual.values_at('installed', 'active', 'plugin_version')).to eq([installed, active, installed ? @planyo_profile.fetch('release') : nil])
      expect(actual.fetch('active_plugins')).to eq(active ? ['planyo-online-reservation-system/planyo.php'] : [])
      release = PlanyoProfiles::RELEASES.fetch(@planyo_profile.fetch('release'))
      expect(actual.fetch('archive_sha256')).to eq(release.fetch('sha256'))
      expect(actual.fetch('installed_sha256')).to eq(installed ? release.fetch('installed_sha256') : {})
      readme = planyo_request("#{planyo_prefix}/wp-content/plugins/planyo-online-reservation-system/readme.txt")
      expect(readme.code).to eq(installed ? '200' : '404')
      PlanyoProfiles::FILES.each do |name, fixture|
        file = actual.fetch('files').fetch(name)
        expect(file.values_at('path', 'exists', 'readable')).to eq(fixture.values_at('path', 'exists', 'readable'))
        expect(file.fetch('mode')).to eq(fixture.fetch('mode').delete_prefix('0')) if fixture.key?('mode')
        expect(file.fetch('owner_uid')).to eq(0) if fixture.fetch('create', true)
        if fixture.fetch('create', true) && fixture.fetch('readable')
          expected = fixture.key?('hex') ? [fixture.fetch('hex')].pack('H*') : fixture.fetch('text').b
          expect(Base64.strict_decode64(file.fetch('base64'))).to eq(expected)
        end
        response = planyo_file_request(fixture.fetch('path'))
        if mode == 'fixed'
          expect(response.code).to eq('200')
          expect(response.body).to eq('Error: Only HTTP(S) URLs are allowed')
        elsif mode == 'absent'
          expect(response.code).to eq('404')
        elsif fixture.fetch('readable')
          expect(response.code).to eq('200')
          expect(response.body.to_s.b).to eq(Base64.strict_decode64(file.fetch('base64')))
        else
          expect(response.code).to eq('500')
        end
      end
      if installed
        query = URI.encode_www_form('ulap_url' => 'https://module-target-disallowed.example.test/')
        response = planyo_request("#{planyo_prefix}/wp-content/plugins/planyo-online-reservation-system/ulap.php?#{query}")
        expect(response.code).to eq('200')
        expect(response.body).to start_with('Error: Call to ')
      end
      expect(planyo_request("#{planyo_prefix}/wp-login.php").code).to eq('200')
      planyo_unchanged
    end
    @planyo_native.fetch(:controls) << { phase: phase, mode: mode, status: 'passed' }
    planyo_save
  end

  def planyo_unchanged
    expect(planyo_identity).to eq(@planyo_baseline) if @planyo_baseline
  end

  def planyo_loot_paths
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def planyo_owner(options = {})
    @planyo_native.fetch(:calls) << { action: 'run', options: options, state: 'started' }
    planyo_save
    output = run_target_module(PlanyoProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{planyo_prefix}/", 'VERBOSE' => true, 'HttpClientTimeout' => 5
    }.merge(options), allow_errors: true)
    @planyo_native.fetch(:calls).last.merge!(state: 'returned', output_base64: Base64.strict_encode64(output.b))
    planyo_save
    expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|LocalJumpError|Unknown datastore option/)
    output
  end

  def planyo_download(name)
    before = planyo_loot_paths
    options = name == 'default' ? {} : { 'FILEPATH' => PlanyoProfiles::FILES.fetch(name).fetch('path') }
    output = planyo_owner(options)
    expect(output).not_to match(/Auxiliary (?:failed|aborted)/)
    loots = planyo_loot_paths - before
    expect(loots.length).to eq(1), output.dup.force_encoding(Encoding::UTF_8).scrub
    expected = @planyo_baseline.fetch('files').fetch(name)
    bytes = File.binread(loots.first)
    expect(bytes).to eq(Base64.strict_decode64(expected.fetch('base64')))
    expect([bytes.bytesize, Digest::SHA256.hexdigest(bytes)]).to eq(expected.values_at('size', 'sha256'))
    expect(File.expand_path(loots.first)).to start_with(File.expand_path(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/')
    expect(output).to include('File saved to:')
    expect(output.b).to include(loots.first.b)
    @planyo_native.fetch(:loots) << { input: name, path: loots.first, size: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes) }
    planyo_unchanged
    planyo_save
  end

  def planyo_refuse(options = {})
    before = planyo_loot_paths
    output = planyo_owner(options)
    expect(planyo_loot_paths).to eq(before)
    expect(output).not_to include('File saved to:')
    planyo_unchanged
    output
  end

  def planyo_counters(phase)
    roles = @planyo_profile.fetch('mode') == 'unrelated' ? ['app'] : %w[app db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "planyo-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
