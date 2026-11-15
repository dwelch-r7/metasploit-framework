# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'uri'
require_relative 'profiles'

RSpec.shared_context 'native WPS Hide Login target' do
  include_context 'module target'

  before(:all) do
    @wps_profile = WpsHideLoginProfiles.fetch
    @wps_native = { requests: [], commands: [] }
    begin
      wps_counters('before')
      if @wps_profile[:unrelated]
        response = wps_request('/')
        expect(response.code).to eq('200')
        expect(response.body).to include('module-target-http-marker')
      else
        @wps_identity = wps_identity
        expect(@wps_identity.values_at('core', 'php', 'sapi', 'uid', 'prefix')).to eq(['6.8.3', '8.3.28', 'cli', 33, @wps_profile.fetch(:prefix)])
        release = @wps_profile.fetch(:release)
        expect(@wps_identity.fetch('active')).to eq(!release.nil?)
        expect(@wps_identity.fetch('configured_slug')).to eq(@wps_profile.fetch(:slug))
        expect(@wps_identity.fetch('plugin_version')).to eq(release && WpsHideLoginProfiles::RELEASES.fetch(release).fetch('version'))
        expect(@wps_identity.fetch('verified_release')).to eq(release ? WpsHideLoginProfiles::RELEASES.fetch(release) : nil)
        expect(@wps_identity.fetch('active_plugins')).to eq(release ? ['wps-hide-login/wps-hide-login.php'] : [])
        prefix = @wps_profile.fetch(:prefix)
        expect(wps_request("#{prefix}/").code).to eq('200')
        expect(wps_request("#{prefix}/wp-login.php").code).to eq(release ? '404' : '200')
        if release
          expect(wps_login_form?(wps_request("#{prefix}/#{@wps_profile.fetch(:slug)}/"))).to be(true)
          readme = wps_request("#{prefix}/wp-content/plugins/wps-hide-login/readme.txt")
          expect(readme.code).to eq('200')
          expect(Digest::SHA256.hexdigest(readme.body)).to eq(@wps_identity.fetch('readme_sha256'))
          without = wps_request("#{prefix}/wp-admin/options.php")
          with = wps_request("#{prefix}/wp-admin/options.php", 'Referer' => 'probe1')
          expect([without.code, with.code]).to eq(%w[302 302])
          @wps_expected_path = @wps_profile.fetch(:disclosure) ? "#{prefix}/#{@wps_profile.fetch(:slug)}/" : "#{prefix}/404/"
          expect(URI(with.fetch('location')).path).to eq(@wps_expected_path)
          expect(URI(without.fetch('location')).path).not_to eq("#{prefix}/#{@wps_profile.fetch(:slug)}/")
          expect(wps_login_form?(wps_request(@wps_expected_path))).to eq(@wps_profile.fetch(:disclosure))
        else
          expect(wps_request('/wp-content/plugins/wps-hide-login/readme.txt').code).to eq('404')
        end
        expect(wps_identity).to eq(@wps_identity)
      end
      @wps_native[:preflight] = 'passed'
    ensure
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-wps-hide-login.json'), JSON.pretty_generate(@wps_native))
    end
  end

  after(:all) do
    expect(wps_identity).to eq(@wps_identity) if @wps_identity
    expect(console_command('irb -e \'puts "WPS_STATE=" + {sessions: framework.sessions.keys, jobs: framework.jobs.keys}.to_json\'')).to include('WPS_STATE={"sessions":[],"jobs":[]}')
  ensure
    wps_counters('after')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-wps-hide-login.json'), JSON.pretty_generate(@wps_native)) if @wps_native
  end

  def wps_identity
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', 'www-data', 'app', 'timeout', '15', 'php', '/opt/module-target/wps-inspect.php']
    stdout, stderr, status = Open3.capture3(*argv)
    @wps_native.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(stdout), stderr: stderr, exitstatus: status.exitstatus }
    raise "Native plugin inspection failed: #{stderr}" unless status.success?

    JSON.parse(stdout)
  end

  def wps_request(path, headers = {})
    endpoint = target_endpoint('app')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    response = http.request(Net::HTTP::Get.new(path, headers))
    @wps_native.fetch(:requests) << { path: path, headers_sent: headers, code: response.code, headers_received: response.to_hash, body_base64: Base64.strict_encode64(response.body.to_s) }
    response
  end

  def wps_login_form?(response)
    return false unless response.code == '200'

    document = Nokogiri::HTML(response.body)
    !document.at_css('form#loginform input[name="log"]').nil? && !document.at_css('form#loginform input[name="pwd"]').nil?
  end

  def wps_owner(options = {})
    output = run_target_module(WpsHideLoginProfiles::OWNER, 'app', {
      'SSL' => false, 'TARGETURI' => "#{@wps_profile.fetch(:prefix)}/", 'THREADS' => 1, 'HttpClientTimeout' => 5
    }.merge(options), allow_errors: true)
    File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
      file.puts(JSON.generate(options: options, output: output))
    end
    output
  end

  def wps_counters(phase)
    roles = WpsHideLoginProfiles.fetch[:unrelated] ? %w[app framework] : %w[db app framework]
    results = {}
    roles.each do |role|
      results[role] = {}
      %w[memory.events pids.events].each do |name|
        text = target_exec(role, 'cat', "/sys/fs/cgroup/#{name}")
        values = text.lines.to_h do |line|
          key, value = line.split
          [key, Integer(value, 10)]
        end
        results[role][name] = values
      end
    end
    File.write(File.join(target_runtime.fetch('artifacts'), "wps-resource-#{phase}.json"), JSON.pretty_generate(results))
    results.each_value do |counters|
      expect(counters.fetch('memory.events').values_at('oom', 'oom_kill')).to eq([0, 0])
      expect(counters.fetch('pids.events').fetch('max')).to eq(0)
    end
  end
end
