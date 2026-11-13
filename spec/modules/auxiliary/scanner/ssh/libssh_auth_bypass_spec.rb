require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'libssh bypass command completion and cleanup' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/ssh/libssh_auth_bypass.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.framework = framework
    end
  end
  let(:framework) { double(features: double(enabled?: false), datastore: Msf::DataStore.new) }
  let(:version) { 'SSH-2.0-libssh_0.8.3' }
  let(:transport) { instance_double(Net::SSH::Transport::Session, server_version: double(version: version)) }
  let(:ssh) { instance_double(Net::SSH::Connection::Session, transport: transport) }
  let(:channel) { instance_double(Net::SSH::Connection::Channel) }
  let(:closed) { { value: false } }
  let(:handlers) { {} }
  let(:output_chunks) { ['libssh-1-', '5-0', "\n"] }
  let(:messages) { [] }
  let(:stream_error) { nil }
  let(:legacy_stream) { instance_double(Net::SSH::CommandStream, error: stream_error, channel: { data: '' }, lsock: double) }

  before do
    mod.datastore['RHOST'] = '192.0.2.18'
    mod.datastore['RPORT'] = 2222
    mod.datastore['ACTION'] = 'Execute'
    mod.datastore['CMD'] = 'sleep 0.4;printf %s libssh-1-5-0'
    mod.datastore['SSH_TIMEOUT'] = 3
    mod.datastore['CreateSession'] = false
    allow(Net::SSH).to receive(:start).and_return(ssh)
    allow(ssh).to receive(:open_channel).and_yield(channel).and_return(channel)
    allow(channel).to receive(:request_pty)
    allow(channel).to receive(:exec).and_yield(channel, true)
    allow(channel).to receive(:on_data) { |&handler| handlers[:stdout] = handler }
    allow(channel).to receive(:wait) { output_chunks.each { |data| handlers.fetch(:stdout).call(channel, data) } }
    allow(ssh).to receive(:closed?) { closed.fetch(:value) }
    allow(ssh).to receive(:close) { closed[:value] = true }
    allow(ssh).to receive(:shutdown!) { closed[:value] = true }
    allow(Net::SSH::CommandStream).to receive(:new).and_return(legacy_stream)
    allow(mod).to receive(:sleep)
    allow(mod).to receive(:report_vuln)
    allow(mod).to receive(:print_status) { |message| messages << message }
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:vprint_good)
    allow(mod).to receive(:elog)
  end

  # Net::SSH channel callbacks, connection failures and CommandStream are explicit
  # synthetic boundaries. The owner action/options, banner gate, output handling
  # and cleanup execute unchanged. The delayed marker is from the parent's sealed
  # genuine libssh 0.8.3 baseline; no remote execution occurs in these examples.

  it 'collects all stdout delivered while waiting for command completion' do
    mod.run_host('192.0.2.18')

    expect(messages.last).to eq("192.0.2.18:2222 - Executed: sleep 0.4;printf %s libssh-1-5-0\nlibssh-1-5-0")
  end

  it 'closes the SSH connection after command completion' do
    mod.run_host('192.0.2.18')

    expect(ssh).to have_received(:close).once
  end

  it 'preserves the PTY option for Execute' do
    mod.datastore['SPAWN_PTY'] = true
    mod.run_host('192.0.2.18')

    expect(channel).to have_received(:request_pty).once
  end

  it 'does not request a PTY by default' do
    mod.run_host('192.0.2.18')

    expect(channel).not_to have_received(:request_pty)
  end

  it 'uses the configured timeout for command completion and SSH cleanup' do
    allow(Timeout).to receive(:timeout).and_call_original
    mod.run_host('192.0.2.18')

    expect(Timeout).to have_received(:timeout).with(3).exactly(3).times
  end

  context 'when the command completes with whitespace only' do
    let(:output_chunks) { [" \n"] }

    it 'retains the empty-output diagnostic' do
      mod.run_host('192.0.2.18')

      expect(mod).to have_received(:print_error).with('192.0.2.18:2222 - Empty or blank command output')
    end
  end

  context 'with a genuine fixed-version banner' do
    let(:version) { 'SSH-2.0-libssh_0.8.4' }

    it 'closes the established connection when the banner gate refuses it' do
      mod.run_host('192.0.2.18')

      expect(ssh).to have_received(:close).once
    end

    it 'does not report or open a command channel after refusing the banner' do
      mod.run_host('192.0.2.18')

      expect([messages.grep(/Executed:/), handlers]).to eq([[], {}])
    end
  end

  it 'handles and logs a command deadline without reporting incomplete output' do
    error = Timeout::Error.new('Command deadline expired')
    allow(channel).to receive(:wait).and_raise(error)
    mod.run_host('192.0.2.18')

    expect(mod).to have_received(:elog).with('SSH command execution failed', error: error)
    expect(messages.grep(/Executed:/)).to eq([])
  end

  it 'handles a rejected exec request as an expected SSH failure' do
    allow(channel).to receive(:exec).and_yield(channel, false)
    mod.run_host('192.0.2.18')

    expect(mod).to have_received(:elog).with('SSH command execution failed', error: an_instance_of(Net::SSH::ChannelRequestFailed))
    expect(ssh).to have_received(:close).once
  end

  it 'handles a rejected channel open without leaking its SSH connection' do
    error = Net::SSH::ChannelOpenFailed.new(1, 'Session channel open failed')
    allow(ssh).to receive(:open_channel).and_raise(error)
    mod.run_host('192.0.2.18')

    expect(mod).to have_received(:elog).with('SSH command execution failed', error: error)
    expect(ssh).to have_received(:close).once
  end

  it 'forces shutdown when graceful cleanup times out' do
    error = Timeout::Error.new('Close deadline expired')
    allow(ssh).to receive(:close).and_raise(error)
    mod.run_host('192.0.2.18')

    expect(ssh).to have_received(:shutdown!).once
    expect(mod).to have_received(:elog).with('SSH connection cleanup failed', error: error)
  end

  it 'retains command output when expected cleanup fails' do
    allow(ssh).to receive(:close).and_raise(IOError, 'Close failed')
    mod.run_host('192.0.2.18')

    expect(messages.last).to end_with("\nlibssh-1-5-0")
  end

  it 'logs expected final shutdown failures' do
    error = IOError.new('Shutdown failed')
    allow(ssh).to receive(:close).and_raise(IOError, 'Close failed')
    allow(ssh).to receive(:shutdown!).and_raise(error)
    mod.run_host('192.0.2.18')

    expect(mod).to have_received(:elog).with('SSH connection shutdown failed', error: error)
  end

  it 'preserves unexpected command errors while closing SSH' do
    allow(ssh).to receive(:open_channel).and_raise(ArgumentError, 'Unexpected command bookkeeping error')

    expect { mod.run_host('192.0.2.18') }.to raise_error(ArgumentError, 'Unexpected command bookkeeping error')
    expect(ssh).to have_received(:close).once
  end

  it 'preserves reporting IOErrors while closing SSH' do
    allow(mod).to receive(:report_vuln).and_raise(IOError, 'Unexpected report error')

    expect { mod.run_host('192.0.2.18') }.to raise_error(IOError, 'Unexpected report error')
    expect(ssh).to have_received(:close).once
  end

  context 'with the existing Shell action' do
    before do
      mod.datastore['ACTION'] = 'Shell'
      mod.datastore.delete('CMD')
      mod.datastore['CreateSession'] = true
    end

    it 'transfers SSH ownership to a successfully created session' do
      allow(mod).to receive(:start_session).and_return(double)
      mod.run_host('192.0.2.18')

      expect(ssh).not_to have_received(:close)
    end

    it 'closes SSH when session creation returns no session' do
      allow(mod).to receive(:start_session).and_return(nil)
      mod.run_host('192.0.2.18')

      expect(ssh).to have_received(:close).once
    end

    it 'closes SSH when session creation is disabled' do
      mod.datastore['CreateSession'] = false
      mod.run_host('192.0.2.18')

      expect(ssh).to have_received(:close).once
    end

    it 'preserves a Shell request failure and closes SSH' do
      allow(legacy_stream).to receive(:error).and_return(Net::SSH::ChannelRequestFailed.new('Shell request failed'))
      mod.run_host('192.0.2.18')

      expect(ssh).to have_received(:close).once
    end
  end
end
