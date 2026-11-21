require 'spec_helper'
require 'tmpdir'
require 'rbconfig'
require_relative '../../support/acceptance/child_process'

# The same cases reproduce the original transport behavior when the new opt-in
# helper is absent. The Ruby subprocess tests recovery, not a target service.
recovery = File.expand_path('../../../test/module_targets/projectsend_sessions/console_recovery.rb', __dir__)
require recovery if File.file?(recovery)

RSpec.describe 'ProjectSend console transport recovery' do
  let(:program) do
    <<~'RUBY_CHILD'
      STDOUT.sync = true
      puts 'msf > '
      STDIN.each_line do |line|
        case line.strip
        when 'hang'
          puts 'Work started'
          sleep 60
        when 'quit'
          exit 0
        else
          puts "Reply: #{line.strip}"
          puts 'msf > '
        end
      end
    RUBY_CHILD
  end
  let(:driver) { Acceptance::ConsoleDriver.new(console_command: [RbConfig.ruby, '-e', program]) }
  let(:console) { driver.open_console }
  let(:runtime) { { 'artifacts' => @directory } }
  let(:harness) do
    transport = Class.new do
      attr_reader :driver, :console, :target_runtime

      def initialize(driver, console, runtime)
        @driver = driver
        @console = console
        @target_runtime = runtime
      end

      # Keep the standard send/read contract; all timeout and EOF behavior is
      # produced by the real Acceptance::Console and operating-system process.
      def console_command(command, timeout: 1)
        raise 'Unrelated host failure' if command == 'host-error'

        console.sendline(command)
        result = console.recvuntil(Acceptance::Console.prompt, timeout: timeout)
        raise "Console exited during #{command.inspect}" unless result

        result
      end

      def cleanup_session
        console_command('sessions -K')
        console_command('jobs -K')
      end
    end
    transport.prepend(ProjectsendConsoleRecovery) if defined?(ProjectsendConsoleRecovery)
    transport.new(driver, console, runtime)
  end

  around do |example|
    Dir.mktmpdir('projectsend-console-recovery-') do |path|
      @directory = path
      example.run
    end
  end

  before do
    # This is a process-level unit fixture, not a Framework metadata bootstrap.
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('MODULE_TARGET_RUNTIME').and_return(nil)
    console.instance_variable_set(:@default_timeout, 0.1)
  end

  after do
    driver.close
    console.wait_thread.join(2)
    ObjectSpace.undefine_finalizer(driver)
  end

  def lose_prompt
    expect { harness.console_command('hang', timeout: 0.1) }
      .to raise_error(Acceptance::ChildProcessRecvError, /Failed recvuntil/)
  end

  it 'keeps successful commands and normal reset behavior' do
    expect(harness.console_command('healthy')).to include('Reply: healthy')
    console.reset
    expect(harness.console_command('again')).to include('Reply: again')
  end

  it 'terminates and reaps the exact unresponsive child while preserving the receive error' do
    lose_prompt
    expect(console.wait_thread.join(1)).not_to be_nil
    expect(console.wait_thread.value.success?).not_to be(true)
  end

  it 'retains the failure and partial output before resetting the closed transport' do
    lose_prompt
    path = File.join(@directory, 'console-failure.json')
    expect(File.file?(path)).to be(true)
    row = JSON.parse(File.read(path))
    expect(row).to include('terminated' => true, 'pid' => console.wait_thread.pid)
    expect(Base64.strict_decode64(row.fetch('output_base64'))).to include('Work started')
  end

  it 'does not send reset commands after the original transport failure' do
    lose_prompt
    expect(console).not_to receive(:sendline)
    console.reset
  end

  it 'does not repeat process termination when the driver closes again' do
    lose_prompt
    # Reap first so a repeated kill would target an already absent process.
    console.wait_thread.join(1) || console.close
    console.wait_thread.join(1)
    expect { driver.close }.not_to output(/error .*pid/).to_stderr
  end

  it 'rejects later commands and cleanup without writing to the closed transport' do
    lose_prompt
    before = console.all_data.dup
    expect { harness.console_command('must-not-run') }.to raise_error(Acceptance::ChildProcessRecvError)
    expect(harness.cleanup_session).to be_nil
    expect(console.all_data).to eq(before)
  end

  it 'preserves a genuine child-exit failure without adding another reset error' do
    expect { harness.console_command('quit') }.to raise_error do |error|
      expect([EOFError, RuntimeError]).to include(error.class)
    end
    expect(console).not_to receive(:sendline)
    console.reset
  end

  it 'does not abandon a live console for an unrelated host error' do
    expect { harness.console_command('host-error') }.to raise_error(RuntimeError, 'Unrelated host failure')
    expect(console.alive?).to be(true)
    expect(harness.console_command('still-healthy')).to include('Reply: still-healthy')
  end
end
