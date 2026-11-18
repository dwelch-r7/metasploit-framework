require 'msfenv'
require 'msf/base'
require 'rex'
require 'rex/socket'
require 'rex/post/meterpreter/extensions/stdapi/sys/process'
require 'csv'
require 'shellwords'

RSpec.describe 'Operating system environment collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/env.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:api) { Rex::Post::Meterpreter }
  let(:stdapi) { Rex::Post::Meterpreter::Extensions::Stdapi }
  let(:process_class) { Rex::Post::Meterpreter::Extensions::Stdapi::Sys::Process }
  let(:channel_class) { Rex::Post::Meterpreter::Channels::Pools::StreamPool }
  let(:client) { double('Synthetic Meterpreter client') }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:config) { double('Synthetic configuration transport') }
  let(:sys) { double('Synthetic stdapi transport', process: process_class, config: config) }
  let(:session_type) { 'meterpreter' }
  let(:platform) { 'linux' }
  let(:session) do
    double('Synthetic session', type: session_type, platform: platform, session_host: '192.0.2.44', sys: sys, arch: ARCH_X64)
  end
  let(:response_timeout) { [300] }
  let(:expected_output) { "EMPTY=\nSPACES=two words\nEQUALS=a=b\nUNICODE=café\nLINES=first\nsecond" }
  let(:wire_output) { expected_output + "\n" }
  let(:chunk_runs) { [[wire_output]] }
  let(:channels) { [] }
  let(:processes) { [] }
  let(:requests) { [] }
  let(:stored_loot) { [] }

  # Every environment string, packet reply and channel chunk below is an
  # explicit synthetic unit boundary. There are no native captures or genuine
  # sessions. The owner, create_process, Process.execute/new/capture_output,
  # alias map, packet construction and Process.close execute as real code.
  # Client I/O, channel creation/reads/close, session/framework access, output
  # and persistence are doubled. Existing helper output removes one terminal
  # newline; stdout and raw loot must contain those same normalized bytes.
  before do
    allow(mod).to receive_messages(framework: framework, session: session, sysinfo: { 'Computer' => 'synthetic-host', 'OS' => 'Synthetic unit OS' })
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_line)
    allow(session).to receive(:response_timeout) { response_timeout.first }
    allow(session).to receive(:response_timeout=) { |value| response_timeout[0] = value }
    allow(mod).to receive(:store_loot) do |*args|
      stored_loot << args
      "/loot/environment-#{stored_loot.length}"
    end
    allow(process_class).to receive(:client).and_return(client)
    allow(client).to receive(:unicode_filter_decode) { |value| value }
    allow(client).to receive(:send_request) do |request, *_args|
      requests << request
      response = api::Packet.create_response(request)
      if request.method == stdapi::COMMAND_ID_STDAPI_SYS_PROCESS_EXECUTE
        response.add_tlv(stdapi::TLV_TYPE_PID, 1234)
        response.add_tlv(stdapi::TLV_TYPE_PROCESS_HANDLE, 5678)
        response.add_tlv(api::TLV_TYPE_CHANNEL_ID, channels.length + 1)
      end
      response
    end
    allow(channel_class).to receive(:new) do |*_args|
      chunks = chunk_runs.fetch(channels.length) { chunk_runs.last }
      channel = double('Synthetic stdout channel', close: nil)
      allow(channel).to receive(:read).and_return(*chunks, nil)
      channels << channel
      channel
    end
    allow(process_class).to receive(:new).and_wrap_original do |constructor, *args|
      constructor.call(*args).tap { |process| processes << process }
    end
  end

  after do
    # Remove real Process finalizers before the client doubles leave scope,
    # including when the original owner exits without consuming its channel.
    processes.each(&:close)
  end

  it 'uses the actual initialized Process alias map without inventing a read method' do
    process = process_class.execute('/bin/sh', '-c env', 'Channelized' => true)

    expect([process.respond_to?(:read), process.read, process.channel, process.aliases.keys]).to eq(
      [false, nil, channels.first, %w[image io memory thread]]
    )
  end

  describe 'Unix Meterpreter' do
    it 'prints and stores complete helper-normalized output with unchanged metadata' do
      expect(mod).not_to receive(:create_credential)
      expect(mod).to receive(:print_line).with(expected_output)

      mod.run

      expect(stored_loot).to eq([['unix.environment', 'text/plain', session, expected_output]])
    end

    context 'with output split across channel reads' do
      let(:chunk_runs) { [["EMPTY=\nSPACES=two ", "words\nEQUALS=a=b\nUNI", "CODE=café\nLINES=first\nsecond\n"]] }

      it 'returns every chunk in order' do
        expect(mod.get_env_meterpreter).to eq(expected_output)
      end
    end

    context 'with an initially empty channel read' do
      let(:chunk_runs) { [['', wire_output]] }

      it 'waits for the following output through the existing helper' do
        expect(mod.get_env_meterpreter).to eq(expected_output)
      end
    end

    context 'with bounded large output' do
      let(:expected_output) { "LARGE=#{'x' * 131_072}\nTAIL=last" }
      let(:chunk_runs) { [[wire_output.byteslice(0, 65_536), wire_output.byteslice(65_536, 65_536), wire_output.byteslice(131_072..-1)]] }

      it 'retains the complete large value and final variable' do
        expect(mod.get_env_meterpreter).to eq(expected_output)
      end
    end

    it 'closes the channel and real process while restoring the response timeout' do
      mod.get_env_meterpreter

      expect([processes.map(&:pid), session.response_timeout]).to eq([[nil], 300])
      expect(channels.first).to have_received(:close).once
    end

    context 'with no output' do
      let(:chunk_runs) { [[]] }

      it 'preserves the existing failure and does not store loot' do
        expect { mod.run }.to raise_error(Msf::Post::Failed, /Could not retrieve environment variables/)
        expect(stored_loot).to be_empty
      end
    end

    context 'with repeated execution' do
      let(:chunk_runs) { [["UNIT=first\n"], ["UNIT=second\n"]] }

      it 'prints and stores fresh output for each invocation' do
        mod.run
        mod.run

        expect(stored_loot.map(&:last)).to eq(['UNIT=first', 'UNIT=second'])
      end
    end

    it 'preserves the /bin/sh -c env command semantics' do
      mod.get_env_meterpreter
      request = requests.find { |packet| packet.method == stdapi::COMMAND_ID_STDAPI_SYS_PROCESS_EXECUTE }
      path = request.get_tlv_value(stdapi::TLV_TYPE_PROCESS_UNESCAPED_PATH) || request.get_tlv_value(stdapi::TLV_TYPE_PROCESS_PATH)
      arguments = request.get_tlvs(stdapi::TLV_TYPE_PROCESS_ARGUMENT).map(&:value)
      arguments = Shellwords.split(request.get_tlv_value(stdapi::TLV_TYPE_PROCESS_ARGUMENTS)) if arguments.empty?

      expect([path, arguments]).to eq(['/bin/sh', ['-c', 'env']])
    end
  end

  context 'with a Unix command shell' do
    let(:session_type) { 'shell' }

    it 'preserves env transport and Unix raw-loot metadata' do
      expect(session).to receive(:shell_command_token).with('env', 15).and_return(wire_output)

      mod.run

      expect(stored_loot).to eq([['unix.environment', 'text/plain', session, expected_output]])
    end
  end

  context 'with a Windows command shell' do
    let(:session_type) { 'shell' }
    let(:platform) { 'windows' }

    it 'preserves set transport and Windows raw-loot metadata' do
      expect(session).to receive(:shell_command_token).with('set', 15).and_return(wire_output)

      mod.run

      expect(stored_loot).to eq([['windows.environment', 'text/plain', session, expected_output]])
    end
  end

  context 'with PowerShell' do
    let(:session_type) { 'powershell' }
    let(:platform) { 'windows' }

    it 'preserves CSV parsing and Windows raw-loot metadata' do
      csv = "#TYPE System.Collections.DictionaryEntry\n\"Key\",\"Value\"\n\"UNIT\",\"two words\"\n\"EMPTY\",\"\"\n"
      expect(session).to receive(:shell_command).with('Get-ChildItem Env: | ConvertTo-Csv', 15).and_return(csv)

      mod.run

      expect(stored_loot).to eq([['windows.environment', 'text/plain', session, "UNIT=two words\nEMPTY="]])
    end
  end

  context 'with Windows Meterpreter' do
    let(:platform) { 'windows' }

    it 'preserves registry enumeration, getenvs and Windows raw-loot metadata' do
      allow(mod).to receive(:registry_enumvals).with('HKEY_CURRENT_USER\\Volatile Environment').and_return(['UNIT', 'EMPTY'])
      allow(mod).to receive(:registry_enumvals).with('HKEY_CURRENT_USER\\Environment').and_return(nil)
      allow(mod).to receive(:registry_enumvals).with('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment').and_return(['UNIT'])
      expect(config).to receive(:getenvs).with('EMPTY', 'UNIT').and_return({ 'UNIT' => 'two words', 'EMPTY' => '' })

      mod.run

      expect(stored_loot).to eq([['windows.environment', 'text/plain', session, "UNIT=two words\nEMPTY="]])
    end
  end
end
