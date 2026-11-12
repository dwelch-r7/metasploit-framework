require 'rspec'
require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'msf/core/exploit/local/saltstack'
require 'sshkey'
require 'open3'

RSpec.describe 'Salt post collection compatibility' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = ENV.fetch('SALT_GATHER_UNIT_MODULE', File.expand_path('../../../../../modules/post/multi/gather/saltstack_salt.rb', __dir__))
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:session) { double('Post session', type: 'meterpreter', platform: 'linux', session_host: '192.0.2.1') }
  let(:loot) { [] }
  let(:credentials) { [] }
  let(:hosts) { [] }
  let(:good) { [] }
  let(:errors) { [] }
  let(:warnings) { [] }
  let(:commands) { [] }
  let(:stderr) { '' }
  let(:roster) { YAML.safe_load(fixture('roster.yml')) }
  let(:files) do
    {
      '/etc/salt/minion' => "master: salt-master\n",
      '/etc/salt/roster' => roster.to_yaml,
      '/etc/salt/pki/collection/plain.pem' => fixture('public-test-key.pem'),
      '/etc/salt/pki/collection/encrypted.pem' => fixture('encrypted-test-key.pem')
    }
  end
  # No genuine grains response was captured in the original run. This explicit
  # synthetic OS projection tests the new cross-platform request contract only.
  let(:grains) { { 'kernel' => 'Linux', 'os' => 'Debian', 'osfullname' => 'Debian GNU/Linux', 'osrelease' => '10', 'kernelrelease' => 'captured-kernel' } }

  before do
    mod.datastore['MINIONS'] = '*'
    mod.datastore['TIMEOUT'] = 120
    allow(mod).to receive_messages(session: session, peer: '192.0.2.1:4506', myworkspace_id: 1, fullname: 'post/multi/gather/saltstack_salt')
    allow(mod).to receive(:command_exists?).and_return(true)
    allow(mod).to receive(:file?) { |name| files.key?(name) }
    allow(mod).to receive(:read_file) { |name| files.fetch(name) }
    allow(mod).to receive_messages(print_status: nil, vprint_status: nil, elog: nil, report_note: nil)
    allow(mod).to receive(:print_good) { |message| good << message }
    allow(mod).to receive(:print_error) { |message| errors << message }
    allow(mod).to receive(:print_warning) { |message| warnings << message }
    allow(mod).to receive(:report_host) { |data| hosts << data.dup }
    allow(mod).to receive(:store_loot) do |type, _mime, _session, data, *_rest|
      loot << { type: type, data: data }
      '/unit/loot'
    end
    # Reporting is a double; real SSHKey/OpenSSL parsing rejects encrypted input
    # without a password, matching the confirmed database boundary failure.
    allow(mod).to receive(:create_credential_and_login) do |data|
      SSHKey.new(data.fetch(:private_data), passphrase: '') if data[:private_type] == :ssh_key
      credentials << data.dup
    end
    allow(mod).to receive(:cmd_exec) { |*arguments| command_output(arguments.join(' ')) + stderr }
    allow(mod).to receive(:create_process) do |_executable, args:, **_options|
      commands << args
      marker = args.fetch(3)
      output = command_output(args.drop(4).join(' '))
      marker + "B\n" + output.lines.map { |line| marker + (line.end_with?("\n") ? 'L' : 'N') + line.delete_suffix("\n") + "\n" }.join + marker + "E0\n" + marker + "Z\n" + stderr
    end
  end

  # CLI payloads and warnings derive from the sealed genuine two-node run;
  # provenance.json discloses hostname/address substitutions. Transport, files,
  # sessions, UI and persistence are doubles. Parser, option defaults, sender
  # argument construction and SSHKey/OpenSSL processing remain real. No
  # Framework, database, thread manager, listener or Salt process is allocated.
  # The legacy compound command receives an individual captured projection;
  # it does not reproduce the separate native compound/partial-response defect.
  it 'parses captured pillar YAML with the supported Psych keyword API' do
    mod.gather_pillars

    expect(YAML.safe_load(loot.fetch(0).fetch(:data))).to eq(YAML.safe_load(fixture('pillars.yml')))
  end

  it 'prints each captured accepted minion rather than the key-category pair' do
    mod.list_minions_printer

    expect(good.join("\n")).to match(/Accepted\s+module-target-minion-a/)
  end

  context 'roster collection without optional data requests' do
    before do
      mod.datastore['GETHOSTNAME'] = false
      mod.datastore['GETIP'] = false
      mod.datastore['GETOS'] = false
      allow(mod).to receive_messages(list_minions_printer: nil, gather_pillars: nil)
    end

    it 'stores the parsed roster without invoking minion collection again' do
      allow(mod).to receive(:create_credential_and_login)
      mod.master

      expect(loot.select { |entry| entry[:type] == 'saltstack_roster' }.map { |entry| YAML.safe_load(entry[:data]) }).to eq([roster])
    end

    it 'does not add an unintended second minion-config loot' do
      allow(mod).to receive(:create_credential_and_login)
      mod.master

      expect(loot.map { |entry| entry[:type] }).not_to include('saltstack_minion')
    end

    it 'imports all four roster logins including the decrypted encrypted key' do
      mod.master

      expect(credentials.map { |entry| entry[:address] }.sort).to eq(%w[192.0.2.10 192.0.2.11 192.0.2.12 192.0.2.13])
    end

    it 'retains the original encrypted bytes as loot' do
      allow(mod).to receive(:create_credential_and_login)
      mod.master

      expect(loot.select { |entry| entry[:type] == 'ssh_key' }.map { |entry| entry[:data] }).to include(fixture('encrypted-test-key.pem'))
    end

    it 'continues to other accounts when a key passphrase is invalid' do
      roster.fetch('collection-encrypted')['priv_passwd'] = 'incorrect-test-passphrase'
      mod.master

      expect(credentials.map { |entry| entry[:address] }).to include('192.0.2.10')
    end

    it 'reuses a successfully parsed plain key without rereading its file' do
      roster.delete('collection-encrypted')
      expect(mod).to receive(:read_file).with('/etc/salt/pki/collection/plain.pem').once.and_return(fixture('public-test-key.pem'))

      mod.master
    end

    it 'skips a key path which is absent' do
      roster.delete('collection-encrypted')
      files.delete('/etc/salt/pki/collection/plain.pem')
      mod.master

      expect(credentials.map { |entry| entry[:address] }).to eq(['192.0.2.10'])
    end
  end

  context 'individual optional minion data' do
    before do
      mod.datastore['GETHOSTNAME'] = false
      mod.datastore['GETIP'] = false
      mod.datastore['GETOS'] = false
    end

    it 'normalizes the captured hostname-only scalar results' do
      mod.datastore['GETHOSTNAME'] = true
      mod.gather_minion_data

      expect(good.join("\n")).to include('Found minion: captured-salt-host')
    end

    it 'reports both captured IP-only node responses safely' do
      mod.datastore['GETIP'] = true
      mod.gather_minion_data

      expect(hosts.map { |entry| entry[:host] }).to eq(['192.0.2.20', '192.0.2.20'])
    end

    it 'omits disabled hostname and OS fields to preserve stored fingerprints' do
      mod.datastore['GETIP'] = true
      mod.gather_minion_data

      expect(hosts.map { |entry| entry.keys & %i[name os_name os_flavor] }).to eq([[], []])
    end

    it 'retains function-keyed OS loot using the synthetic grains projection' do
      mod.datastore['GETOS'] = true
      mod.gather_minion_data

      expect(YAML.safe_load(loot.fetch(0).fetch(:data)).fetch('module-target-minion-a')).to eq('grains.item' => grains)
    end

    it 'does not send an empty compound request when all flags are disabled' do
      expect(mod).not_to receive(:cmd_exec)
      expect(mod).not_to receive(:create_process)

      mod.gather_minion_data
    end
  end

  context 'captured startup warnings' do
    let(:stderr) { fixture('stderr.txt') }

    it 'keeps warning diagnostics visible without corrupting key-list YAML' do
      mod.list_minions_printer

      expect([good.join("\n").include?('module-target-minion-a'), warnings.join("\n").include?('DeprecationWarning')]).to eq([true, true])
    end
  end

  context 'actual local stdout framing protocol' do
    before do
      allow(mod).to receive(:create_process) { |executable, args:, **_options| Open3.capture2e(executable, *args).fetch(0) }
    end

    it 'preserves multiple trailing stdout newlines and reports stderr' do
      output = mod.salt_command_output('/bin/sh', ['-c', 'printf "value\\n\\n"; printf "unit diagnostic\\n" >&2'])

      expect([output, warnings.join("\n").include?('unit diagnostic')]).to eq(["value\n\n", true])
    end

    it 'preserves stdout without a final newline' do
      expect(mod.salt_command_output('/bin/sh', ['-c', 'printf value'])).to eq('value')
    end

    it 'preserves literal carriage returns within and at the end of stdout' do
      expect(mod.salt_command_output('/bin/sh', ['-c', "printf 'a\\r\\nb\\r'"])).to eq("a\r\nb\r")
    end

    it 'frames status after stderr without a final newline' do
      output = mod.salt_command_output('/bin/sh', ['-c', 'printf value; printf diagnostic >&2; exit 0'])

      expect([output, warnings.join("\n").include?('diagnostic')]).to eq(['value', true])
    end

    it 'forwards a literal selector argument without shell expansion' do
      expect(mod.salt_command_output('/bin/sh', ['-c', 'printf %s "$1"', 'unit', "*'$(printf unsafe)"])).to eq("*'$(printf unsafe)")
    end

    it 'rejects a nonzero command exit and retains its diagnostic' do
      output = mod.salt_command_output('/bin/sh', ['-c', 'printf "unit error\\n" >&2; exit 7'])

      expect([output, errors.join("\n").include?('7')]).to eq([nil, true])
    end

    it 'rejects a missing completion marker' do
      allow(mod).to receive(:create_process).and_return('incomplete unframed output')

      expect(mod.salt_command_output('salt-key', ['-L'])).to be_nil
    end

    it 'rejects an ambiguous duplicate frame' do
      allow(mod).to receive(:create_process) { |_executable, args:, **_options| "#{args[3]}B\n#{args[3]}B\n#{args[3]}E0\n#{args[3]}Z\n" }

      expect(mod.salt_command_output('salt-key', ['-L'])).to be_nil
    end

    it 'converts an expected transport timeout into a command failure' do
      allow(mod).to receive(:create_process).and_raise(Rex::TimeoutError)

      expect(mod.salt_command_output('salt-key', ['-L'])).to be_nil
    end
  end

  def fixture(name)
    File.binread(File.expand_path("../../../../file_fixtures/modules/post/multi/gather/saltstack_salt/#{name}", __dir__))
  end

  def command_output(command)
    return fixture('keys.yml') if command.include?('salt-key')
    return "native SLS marker\n" if command.include?('state.show_sls')
    return fixture('pillars.yml') if command.include?('pillar.items')
    return fixture('hostname.yml') if command.include?('network.get_hostname')
    return fixture('interfaces.yml') if command.include?('network.interfaces')
    return fixture('os-version.yml') if command.include?('status.version')
    return { 'module-target-minion-a' => grains, 'module-target-minion-b' => grains.dup }.to_yaml if command.include?('grains.item')

    raise ArgumentError, 'Unexpected unit command'
  end
end
