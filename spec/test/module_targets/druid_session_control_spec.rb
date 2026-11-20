require 'rspec'
require 'msfenv'
require 'msf/base'
require 'rex/socket'
require 'rex/post/meterpreter'
require_relative '../../../test/module_targets/druid_sessions/session_control'

RSpec.describe DruidSessionControl do
  let(:path) { '/tmp/module-target-druid-session-98813_1-1' }
  let(:child) { double('Remote touch process', pid: 812) }
  let(:process_api) { double('Meterpreter process API', getpid: 799, execute: child, get_processes: []) }
  let(:files) { double('Meterpreter file API') }
  let(:stat) { double('Remote zero-byte regular file', file?: true, size: 0) }
  let(:session) do
    double(
      'Ready Meterpreter session',
      type: 'meterpreter',
      sys: double(process: process_api, config: double(getuid: 'www-data')),
      fs: double(file: files)
    )
  end
  let(:framework) { double('Framework', sessions: { 1 => session }) }
  let(:events) { [] }
  let(:missing) { Rex::Post::Meterpreter::RequestError.new(0, 'No such file', 2) }

  before do
    allow(files).to receive(:stat).with(path) do
      events << :touch_completed
      stat
    end
    # Mettle 1.0.48 sys_process_close actively sends SIGINT. This contract was
    # independently checked against its release source and installed machine
    # code; closing an accepted process is not evidence that touch executed.
    # https://github.com/rapid7/mettle/blob/46ebde9db0c25d0c8cf287469f091266c4e9c3d5/mettle/src/stdapi/sys/process.c#L172-L184
    allow(child).to receive(:close) { events << :sigint }
    allow(described_class).to receive(:sleep)
  end

  it 'preserves the exact command, arguments and launch flags' do
    expect(process_api).to receive(:execute).with('/bin/touch', path, 'Hidden' => true, 'Channelized' => false).and_return(child)
    described_class.proof(framework, 1, path)
  end

  it 'preserves the public session identity and proof fields' do
    expect(described_class.proof(framework, 1, path)).to include(
      id: 1, type: 'meterpreter', pid: 799, identity: 'www-data',
      command: "/bin/touch #{path}", expected: ''
    )
  end

  it 'establishes the same touch proof before the active close' do
    described_class.proof(framework, 1, path)
    expect(events).to eq(%i[touch_completed sigint])
  end

  it 'records the spawned child separately from the Meterpreter PID' do
    expect(described_class.proof(framework, 1, path).fetch(:proof_process)).to include(
      pid: 812, file_observed: true, close_requested: true, cleanup: 'child_absent'
    )
  end

  it 'allows the accepted child to complete after an initial absent-file response' do
    allow(files).to receive(:stat).with(path).and_raise(missing)
    expect(files).to receive(:stat).with(path).ordered.and_raise(missing)
    expect(files).to receive(:stat).with(path).ordered do
      events << :touch_completed
      stat
    end
    described_class.proof(framework, 1, path)
    expect(events).to eq(%i[touch_completed sigint])
  end

  it 'actively cleans up a child when the session cannot observe the proof' do
    stub_const('DruidSessionControl::PROOF_TIMEOUT', 0)
    allow(files).to receive(:stat).with(path).and_raise(missing)
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, /Remote touch proof.*812.*file_observed.*false.*close_requested/m)
    expect(events).to eq([:sigint])
  end

  it 'does not accept a directory as successful command execution' do
    stub_const('DruidSessionControl::PROOF_TIMEOUT', 0)
    allow(stat).to receive(:file?).and_return(false)
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, /Remote touch proof/)
  end

  it 'does not accept unexpected proof bytes' do
    stub_const('DruidSessionControl::PROOF_TIMEOUT', 0)
    allow(stat).to receive(:size).and_return(9)
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, /Remote touch proof/)
  end

  it 'preserves stat failure diagnostics after bounded cleanup' do
    stub_const('DruidSessionControl::PROOF_TIMEOUT', 0)
    denied = Rex::Post::Meterpreter::RequestError.new(0, 'Permission denied', 13)
    allow(files).to receive(:stat).with(path).and_raise(denied)
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, /Permission denied/)
    expect(events).to eq([:sigint])
  end

  it 'waits for child disappearance after requesting active cleanup' do
    expect(process_api).to receive(:get_processes).ordered.and_return([{ 'pid' => 812 }])
    expect(process_api).to receive(:get_processes).ordered.and_return([{ 'pid' => 799 }])
    expect(described_class.proof(framework, 1, path).fetch(:proof_process)).to include(cleanup: 'child_absent')
  end

  it 'does not claim cleanup merely because close returned' do
    stub_const('DruidSessionControl::PROOF_TIMEOUT', 0)
    allow(process_api).to receive(:get_processes).and_return([{ 'pid' => 812 }])
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, /Unable to clean up proof child 812/)
  end

  it 'attempts active cleanup if an unexpected observation failure occurs' do
    allow(files).to receive(:stat).with(path).and_raise(IOError, 'Transport closed')
    expect { described_class.proof(framework, 1, path) }.to raise_error(IOError, 'Transport closed')
    expect(events).to eq([:sigint])
  end

  it 'preserves the shell proof command and result' do
    shell = double('Ready command shell', type: 'shell')
    allow(framework).to receive(:sessions).and_return(1 => shell)
    expect(shell).to receive(:shell_command_token).with("printf %s druid-session > #{path}; id; echo $$").and_return("uid=33(www-data)\n675\n")
    expect(described_class.proof(framework, 1, path)).to include(pid: 675, expected: 'druid-session')
  end

  it 'rejects an unowned path before executing a command' do
    expect(process_api).not_to receive(:execute)
    expect { described_class.proof(framework, 1, '/tmp/unowned') }.to raise_error(ArgumentError, 'Unexpected proof path')
  end
end
