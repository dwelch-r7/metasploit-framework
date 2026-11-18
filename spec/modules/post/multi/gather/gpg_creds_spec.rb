require 'msfenv'
require 'msf/base'
require 'fileutils'
require 'open3'
require 'tmpdir'

RSpec.describe 'GnuPG directory collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/gpg_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:process_manager) { double('Host-backed process transport') }
  let(:sys) { double('Synthetic stdapi transport', process: process_manager) }
  let(:session) { double('Synthetic Unix session', type: session_type, platform: 'linux', arch: ARCH_X64, sys: sys) }
  let(:session_type) { 'shell' }
  let(:response_timeout) { [300] }
  let(:home_name) { 'ordinary' }
  let(:home) { File.join(@temporary_directory, home_name) }
  let(:gnupg) { File.join(home, '.gnupg') }
  let(:private_keys) { File.join(gnupg, 'private-keys-v1.d') }
  let(:keyring_data) { "\x99\x00synthetic-keyring\xff\n".b }
  let(:trust_data) { "synthetic-trust\x00data\n".b }
  let(:private_data) { "synthetic-private-key\x00\xfe\n".b }
  let(:stored_loot) { [] }
  let(:commands) { [] }
  let(:expected_loot) do
    [
      ['gpg.pubring.kbx', 'text/plain', session, keyring_data, 'gpg_pubring.kbx', 'GnuPG pubring.kbx File'],
      ['gpg.trustdb', 'text/plain', session, trust_data, 'gpg_trustdb.gpg', 'GnuPG trustdb.gpg File'],
      ['gpg.conf', 'text/plain', session, "use-agent\n", 'gpg_gpg.conf', 'GnuPG gpg.conf File'],
      ['gpg.test.key', 'text/plain', session, private_data, 'gpg_test.key', 'GnuPG test.key File']
    ]
  end

  around do |example|
    Dir.mktmpdir('gpg-collection') do |directory|
      @temporary_directory = directory
      example.run
    end
  end

  # Owner run/download_loot, Common create_process/cmd_exec, Unix escaping,
  # host ls and filesystem operations execute as real code. The remote session
  # and Meterpreter capture_output are host-backed adapters; file transport,
  # Framework, output and loot persistence are doubled. Payload bytes are
  # explicit synthetic binary data, not keyrings or cryptographic qualification.
  before do
    FileUtils.mkdir_p(File.join(private_keys, 'nested-directory'))
    File.binwrite(File.join(gnupg, 'pubring.kbx'), keyring_data)
    File.binwrite(File.join(gnupg, 'trustdb.gpg'), trust_data)
    File.binwrite(File.join(gnupg, 'gpg.conf'), "use-agent\n")
    File.binwrite(File.join(gnupg, 'empty.gpg'), '')
    File.binwrite(File.join(private_keys, 'test.key'), private_data)

    allow(mod).to receive_messages(framework: framework, session: session)
    allow(mod).to receive(:enum_user_directories).and_return([home])
    allow(mod).to receive(:directory?) { |path| File.directory?(path) }
    allow(mod).to receive(:read_file) { |path| File.file?(path) ? File.binread(path) : nil }
    allow(mod).to receive(:store_loot) do |*args|
      stored_loot << args
      "/loot/gpg-#{stored_loot.length}"
    end
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_error)
    allow(session).to receive(:response_timeout) { response_timeout.first }
    allow(session).to receive(:response_timeout=) { |value| response_timeout[0] = value }
    allow(session).to receive(:to_cmd) { |arguments| Msf::Sessions::CommandShellUnix.to_cmd(arguments) }
    allow(session).to receive(:shell_command_token) do |command, _timeout|
      arguments = ['/bin/sh', '-c', command]
      commands << arguments
      stdout, stderr, = Open3.capture3(*arguments)
      stdout + stderr
    end
    allow(process_manager).to receive(:capture_output) do |executable, arguments, _options, _timeout|
      # Modern Meterpreter receives an argument array. Legacy cmd_exec sends
      # a shell command string; run that through sh to reproduce its semantics.
      command = arguments.is_a?(Array) ? [executable, *arguments] : ['/bin/sh', '-c', [executable, arguments].compact.join(' ')]
      commands << command
      stdout, stderr, = Open3.capture3(*command)
      stdout + stderr
    end
  end

  shared_examples 'a Unix GnuPG collector' do
    shared_examples 'a literal home path' do |name|
      let(:home_name) { name }

      it "preserves binary raw data and loot metadata for #{name.inspect}" do
        mod.run

        expect(stored_loot.sort_by { |row| row[4] }).to eq(expected_loot.sort_by { |row| row[4] })
      end
    end

    it_behaves_like 'a literal home path', 'ordinary'
    it_behaves_like 'a literal home path', 'lab space'
    it_behaves_like 'a literal home path', "lab'quote"
    it_behaves_like 'a literal home path', 'lab"quote'
    it_behaves_like 'a literal home path', 'lab;semicolon'
    it_behaves_like 'a literal home path', 'café'

    it 'does not read directories or persist empty files' do
      expect(mod).not_to receive(:read_file).with(private_keys)
      expect(mod).not_to receive(:read_file).with(File.join(private_keys, 'nested-directory'))
      expect(mod).to receive(:vprint_error).with('No data found for empty.gpg')

      mod.run

      expect(stored_loot.map { |row| row[4] }).not_to include('gpg_empty.gpg')
    end

    it 'collects the same exact raw files on a second invocation' do
      mod.run
      mod.run

      expect(stored_loot.sort_by { |row| row[4] }).to eq((expected_loot * 2).sort_by { |row| row[4] })
    end

    it 'does not persist anything for an empty GnuPG directory' do
      FileUtils.remove_entry(gnupg)
      FileUtils.mkdir_p(gnupg)

      mod.run

      expect(stored_loot).to be_empty
    end

    it 'does not execute commands when no GnuPG directory exists' do
      FileUtils.remove_entry(gnupg)
      expect(mod).to receive(:print_error).with('No users found with a GnuPG directory')

      mod.run

      expect([commands, stored_loot]).to eq([[], []])
    end
  end

  context 'with a Unix shell' do
    let(:session_type) { 'shell' }

    it_behaves_like 'a Unix GnuPG collector'
  end

  context 'with Unix Meterpreter' do
    let(:session_type) { 'meterpreter' }

    it_behaves_like 'a Unix GnuPG collector'

    it 'restores the response timeout after listing both directories' do
      mod.run

      expect(session.response_timeout).to eq(300)
    end
  end
end
