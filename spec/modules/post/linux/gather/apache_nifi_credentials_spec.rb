require 'rspec'
require 'json'
require 'zlib'

RSpec.describe 'NiFi stored credential collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'linux/gather/apache_nifi_credentials') }

  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true, 'DisableLogging' => true)
  end
  let(:fixture_dir) { File.join(FILE_FIXTURES_PATH, 'modules/post/linux/gather/apache_nifi_credentials') }
  let(:native) { JSON.parse(File.read(File.join(fixture_dir, 'provenance.json'))) }
  let(:crypto) { JSON.parse(File.read(File.join(fixture_dir, 'crypto.json'))) }
  let(:directory) { '/opt/nifi/nifi-current/conf' }
  let(:properties) { File.binread(File.join(fixture_dir, 'nifi.properties')) }
  let(:flow) { File.binread(File.join(fixture_dir, 'flow.json')) }
  let(:identity) { File.binread(File.join(fixture_dir, 'login-identity-providers.xml')) }
  let(:files) do
    {
      "#{directory}/nifi.properties" => properties,
      "#{directory}/flow.json.gz" => Zlib.gzip(flow),
      "#{directory}/login-identity-providers.xml" => identity,
      "#{directory}/authorizers.xml" => File.binread(File.join(fixture_dir, 'authorizers.xml'))
    }
  end
  let(:stored) { [] }
  let(:reported) { [] }
  let(:output) { [] }

  before do
    mod.datastore['NIFI_PATH'] = '/opt/nifi/nifi-current'
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:session_db_id).and_return(37)
    allow(mod).to receive(:myworkspace_id).and_return(17)
    allow(mod).to receive(:file_exist?) { |path| files.key?(path) }
    allow(mod).to receive(:readable?) { |path| files.key?(path) }
    allow(mod).to receive(:read_file) { |path| files[path] }
    allow(mod).to receive(:store_loot) do |kind, _type, _host, data, *_rest|
      stored << { kind: kind, data: data }
      "/tmp/module-target-unit-#{kind}"
    end
    allow(mod).to receive(:create_credential) { |data| reported << data }
    expect(mod).not_to receive(:create_credential_login)
    %i[print_good print_line print_warning print_error print_bad].each do |method|
      allow(mod).to receive(method) { |message| output << message }
    end
    allow(mod).to receive(:elog)
  end

  def decrypted_loot
    stored.find { |item| item.fetch(:kind) == 'nifi.flow.decrypted.json' }&.fetch(:data)
  end

  def expected_flow
    expected = JSON.parse(flow)
    crypto.fetch('decrypted').each do |item|
      parent = item.fetch('path')[0...-1].reduce(expected) { |value, key| value.fetch(key) }
      parent[item.fetch('path').last] = item.fetch('plaintext')
    end
    expected
  end

  def password_cores
    reported.select { |record| record[:private_type] == :password }
  end

  it 'keeps the captured native GetHTTP plaintext and username in output' do
    mod.run

    expect(output.join("\n")).to match(/module-test-user\s+module-test-password/)
  end

  it 'associates the native private-key password with its actual keystore file' do
    mod.run

    expect(output.join("\n")).to match(/Key Password\s+#{Regexp.escape(native.fetch('native_stores').fetch('keystore').fetch('path'))}/)
  end

  it 'retains the separate native truststore path and password' do
    mod.run
    store = native.fetch('native_stores').fetch('truststore')

    expect(output.join("\n")).to match(/Truststore\s+#{Regexp.escape(store.fetch('path'))}\s+#{Regexp.escape(store.fetch('password'))}/)
  end

  it 'stores the original native encrypted flow bytes unchanged' do
    mod.run

    expect(stored).to include(kind: 'nifi.flow.json', data: flow)
  end

  it 'stores valid decrypted JSON equal to all seven independent native decryptions' do
    mod.run

    expect(JSON.parse(decrypted_loot)).to eq(expected_flow)
  end

  it 'preserves the genuine quoted and backslash database password in decrypted loot' do
    mod.run
    expected = crypto.fetch('decrypted').find { |field| field.fetch('plaintext').start_with?('module-target-db-') }
    actual = expected.fetch('path').reduce(JSON.parse(decrypted_loot)) { |value, key| value.fetch(key) }

    expect(actual).to eq(expected.fetch('plaintext'))
  end

  context 'with a derived UTF-8 and replacement-escape secret encrypted independently by Node' do
    let(:derived) { JSON.parse(File.read(File.join(fixture_dir, 'derived-utf8-secret.json'))) }
    let(:flow) do
      data = JSON.parse(super())
      parent = derived.fetch('path')[0...-1].reduce(data) { |value, key| value.fetch(key) }
      parent[derived.fetch('path').last] = derived.fetch('encrypted')
      JSON.generate(data)
    end

    it 'preserves Unicode, quotes, newlines and literal substitution escapes as valid JSON' do
      mod.run
      value = derived.fetch('path').reduce(JSON.parse(decrypted_loot)) { |item, key| item.fetch(key) }

      expect(value).to eq(derived.fetch('plaintext'))
    end

    it 'records decrypted text as UTF-8 rather than an untyped binary string' do
      mod.run
      record = password_cores.find { |item| item[:username] == 'module-test-user' }

      expect(record.fetch(:private_data).encoding).to eq(Encoding::UTF_8)
    end
  end

  it 'persists all actual native secret values without treating the encrypted account name as a password' do
    mod.run

    expect(password_cores.map { |record| record.fetch(:private_data) }.uniq.sort).to eq(native.fetch('private_values').uniq.sort)
  end

  it 'persists the captured GetHTTP account with the actual session origin' do
    mod.run

    expect(password_cores).to include(hash_including(username: 'module-test-user', private_data: 'module-test-password', private_type: :password, origin_type: :session, session_id: 37, workspace_id: 17, post_reference_name: 'linux/gather/apache_nifi_credentials'))
  end

  it 'does not invent a service or authentication status for stored secrets' do
    mod.run

    expect(password_cores).not_to be_empty
    expect(password_cores.flat_map(&:keys) & %i[service_name service_id address port protocol status proof]).to be_empty
  end

  it 'does not report keystore filenames as account usernames' do
    mod.run
    secret = native.fetch('native_stores').fetch('keystore').fetch('password')
    records = password_cores.select { |record| record[:private_data] == secret }

    expect(records).not_to be_empty
    expect(records.map { |record| record[:username] }.compact).to be_empty
    expect(records).to all(satisfy { |record| !record.key?(:username) })
  end

  it 'retains the native identity hash type and session origin' do
    mod.run
    account = native.fetch('identity').fetch(0)

    expect(reported).to include(hash_including(username: account.fetch('username'), private_data: account.fetch('hash'), private_type: :nonreplayable_hash, origin_type: :session, session_id: 37, workspace_id: 17))
  end

  context 'with the native identity file alone' do
    before { files.delete_if { |path, _data| !path.end_with?('login-identity-providers.xml') } }

    it 'collects identity without reading or storing nonexistent properties' do
      expect { mod.run }.not_to raise_error

      expect(reported.length).to eq(1)
      expect(stored).to be_empty
    end
  end

  context 'with a derived missing sensitive key' do
    let(:properties) { super().gsub(/^nifi.sensitive.props.key=.*\n/, '') }

    it 'reports the missing key without an unhandled exception' do
      expect { mod.run }.not_to raise_error

      expect(output.join("\n")).to match(/(?:Unable|Missing|No).*sensitive.*key/i)
    end

    it 'retains independently readable identity data' do
      mod.run

      expect(reported.map { |record| record.fetch(:private_data) }).to eq([native.fetch('identity').fetch(0).fetch('hash')])
    end
  end

  context 'with a derived missing algorithm' do
    let(:properties) { super().gsub(/^nifi.sensitive.props.algorithm=.*\n/, '') }

    it 'reports the missing algorithm and retains readable identity' do
      expect { mod.run }.not_to raise_error

      expect(output.join("\n")).to match(/(?:Unable|Missing|No).*algorithm/i)
      expect(reported.length).to eq(1)
    end
  end

  context 'with the unsupported-algorithm file boundary used by the native lab' do
    let(:properties) { super().sub('nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256', 'nifi.sensitive.props.algorithm=MODULE_TARGET_UNSUPPORTED') }

    it 'retains the existing diagnostic and identity collection without decrypted loot' do
      mod.run

      expect(output.join("\n")).to include('Processor for MODULE_TARGET_UNSUPPORTED not implemented')
      expect(decrypted_loot).to be_nil
      expect(reported.length).to eq(1)
    end
  end

  context 'with a derived corrupt authentication tag from the actual native flow' do
    let(:flow) do
      data = JSON.parse(super())
      field = crypto.fetch('decrypted').fetch(0)
      parent = field.fetch('path')[0...-1].reduce(data) { |value, key| value.fetch(key) }
      original = parent.fetch(field.fetch('path').last)
      corrupted = original.dup
      corrupted[-2] = original[-2] == '0' ? '1' : '0'
      parent[field.fetch('path').last] = corrupted
      JSON.generate(data)
    end

    it 'reports the expected cryptographic failure without exposing a raw exception' do
      expect { mod.run }.not_to raise_error

      expect(output.join("\n")).to match(/(?:Unable|Failed|Invalid).*decrypt|authentication.*(?:fail|invalid)/i)
    end

    it 'does not claim or store successful decrypted loot after failed authentication' do
      mod.run

      expect(decrypted_loot).to be_nil
      expect(output.join("\n")).not_to include('Decrypted data saved in:')
    end

    it 'still collects the independent native identity hash' do
      mod.run

      expect(reported).to include(hash_including(private_data: native.fetch('identity').fetch(0).fetch('hash'), private_type: :nonreplayable_hash))
    end
  end

  it 'handles properties becoming unreadable between discovery and reading' do
    files["#{directory}/nifi.properties"] = nil

    expect { mod.run }.not_to raise_error
    expect(stored).not_to include(hash_including(data: nil))
    expect(reported.length).to eq(1)
  end

  it 'retains identity for a derived empty properties file' do
    files["#{directory}/nifi.properties"] = ''

    expect { mod.run }.not_to raise_error
    expect(reported.length).to eq(1)
  end

  it 'keeps a genuine flow with derived empty component collections readable' do
    data = JSON.parse(flow)
    data.fetch('rootGroup')['processors'] = []
    data.fetch('rootGroup')['controllerServices'] = []
    files["#{directory}/flow.json.gz"] = Zlib.gzip(JSON.generate(data))
    mod.run

    expect(decrypted_loot).to be_nil
    expect(reported.length).to eq(1)
  end

  it 'refuses wholly absent files with the existing targeted failure' do
    files.clear

    expect { mod.run }.to raise_error(Msf::Post::Failed, %r{Unable to find login-identity-providers.xml, nifi.properties and/or flow.json.gz files})
  end

  it 'resets discovered file paths before a second run on the same instance' do
    mod.run
    account = identity
    files.clear
    files['/tmp/module-target-next/conf/login-identity-providers.xml'] = account
    mod.datastore['NIFI_PATH'] = '/tmp/module-target-next'
    stored.clear
    reported.clear

    expect { mod.run }.not_to raise_error
    expect(reported.length).to eq(1)
    expect(stored).to be_empty
  end
end
