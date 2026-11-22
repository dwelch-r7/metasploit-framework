require 'acceptance_spec_helper'
require 'rbconfig'
require_relative '../../../test/module_targets/erlang_cookie/acceptance'

RSpec.describe 'Native RabbitMQ Erlang distribution execution' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::ErlangCookie

  brokers = ENV.key?('RABBITMQ_PROFILE') ? [ENV.fetch('RABBITMQ_PROFILE')] : %w[old new]
  raise ArgumentError, 'Invalid broker profile' unless (brokers - %w[old new]).empty?

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
    ec_boot(brokers)
  end

  brokers.each do |service|
    lengths = ENV.key?('RABBITMQ_PROFILE') ? [13, 255, 256, 65_535] : [13, 255, 256]
    lengths.each do |length|
      it "executes a #{length}-byte command twice on #{service} with the broker identity" do
        path = '/tmp/e'
        command = 'touch /tmp/e '.ljust(length)
        expect(command.bytesize).to eq(length)
        ec_rpc(service, command)
        expect(file_owner(service, path)).to eq('rabbitmq')
        target_exec(service, 'rm', path)
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

    if ENV.key?('RABBITMQ_PROFILE')
      it "preserves exact rich command bytes twice on #{service}" do
        path = '/tmp/module-target-erlang-rich'
        value = "Quote ' \" ; UTF-8 é λ 💥\r\nsecond line\n"
        command = "printf %s #{Shellwords.escape(value)} > #{path}"
        begin
          ec_rpc(service, command)
          expect(target_exec(service, 'cat', path)).to eq(value)
          target_exec(service, 'rm', path)
          2.times do
            invoke(service, { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 })
            wait_for_expect(100, 0.1) { expect(file_owner(service, path)).to eq('rabbitmq') }
            expect(target_exec(service, 'cat', path)).to eq(value)
            target_exec(service, 'rm', path)
          end
        ensure
          target_exec(service, 'rm', '-f', path)
        end
      end

      it "refuses a 65536-byte command on #{service} without executing it" do
        path = '/tmp/module-target-erlang-limit'
        command = "touch #{path} ".ljust(65_536)
        ec_rpc(service, command)
        expect(file_owner(service, path)).to eq('rabbitmq')
        target_exec(service, 'rm', path)
        output = invoke(service, { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, allow_errors: true)
        expect(output).to include('65535-byte Erlang STRING_EXT limit')
        expect(target_exec(service, 'test', '!', '-e', path)).to eq('')
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
        ec_sessions(service, payload, target)
      end
    end
  end

  after(:all) do
    ec_finish if @ec
  end

  def invoke(service, options, action: 'run', timeout: 40, allow_errors: false)
    reuse = false
    if options['CMD'].to_s.match?(/[\r\n]/)
      # Literal newlines cannot be sent as one inline console command. Set the
      # real datastore through its public API and verify the exact input bytes.
      console_command('back')
      console_command('use ' + Acceptance::ErlangCookie::OWNER)
      console_command("set TARGET #{options.fetch('TARGET', 0)}")
      console_command("set PAYLOAD #{options.fetch('PAYLOAD')}")
      encoded = Base64.strict_encode64(options.fetch('CMD'))
      recorded = ec_json("begin;active_module.datastore['CMD']=Base64.strict_decode64(#{encoded.inspect}).force_encoding(Encoding::UTF_8);{command:Base64.strict_encode64(active_module.datastore['CMD']),source:active_module.method(:exploit).source_location};end")
      expect(recorded.fetch('command')).to eq(encoded)
      (@ec[:command_inputs] ||= []) << recorded
      ec_save
      options = options.except('CMD', 'TARGET', 'PAYLOAD')
      reuse = true
    end
    run_target_module('exploit/multi/misc/erlang_cookie_rce', service, {
      'COOKIE' => 'MODULE_TARGET_ERLANG_COOKIE', 'VERBOSE' => true
    }.merge(reuse ? {} : { 'TARGET' => 0 }).merge(options), action: action, allow_errors: allow_errors, reuse_module: reuse, endpoint_options: {
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
