require 'acceptance_spec_helper'
require 'json'
require 'timeout'
require 'zlib'
require_relative '../../../test/module_targets/nifi_credentials/session'

RSpec.describe 'Genuine NiFi stored credentials through native sessions' do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native NiFi session'

  before(:all) do
    @native_sequence = 0
    @native = native_action('preflight')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    expect(report_sql('SELECT count(*) FROM metasploit_credential_cores').strip).to eq('0')
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    @workspace = "nifi_post_#{@case_id}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(rows).to eq([])
    @before = native_action('snapshot')
    expect(@before.fetch('files')).to eq(@native.fetch('initial_files'))
    expect(@before.fetch('graph')).to eq(@native.fetch('initial_graph'))
  end

  after do
    console_command('sessions -K')
    console_command('jobs -K')
    target_exec('linux', 'rm', '-f', '/tmp/module-target-session-proof', '/tmp/shell-session.elf', '/tmp/meterpreter-session.elf', '/tmp/module-target-session.log', '/tmp/module-target-nifi-session.log')
    expect(native_action('snapshot')).to eq(@before) if @before
    rows if @workspace
  end

  after(:all) do
    native_action('verify-canary') if @native
  end

  deliveries = {
    'shell' => { payload: 'linux/x64/shell_reverse_tcp', format: 'elf', file: 'shell-session.elf' },
    'meterpreter' => { payload: 'linux/x64/meterpreter_reverse_tcp', format: 'elf', file: 'meterpreter-session.elf' }
  }

  deliveries.each do |kind, delivery|
    it "recovers exact native secrets, loot and session-origin credentials twice as the NiFi #{kind}" do
      session_id = open_nifi_session(kind, delivery)
      2.times do
        output = collect(session_id)
        aggregate_failures('Native plaintext, actual loot and independent SQL conservation') do
          verify_live_result(output, session_id)
        end
      end
    end

    it "refuses genuinely unreadable private files twice as labuser #{kind}" do
      session_id = open_nifi_session(kind, delivery, user: 'labuser')
      2.times do
        output = collect(session_id, path: '/tmp/module-target-nifi-files/private', allow_errors: true)
        expect(output).to include('Unable to find login-identity-providers.xml, nifi.properties and/or flow.json.gz files')
        expect(output).not_to include('NiFi Flow Values', 'data saved in:')
        expect(rows).to eq([])
      end
    end
  end

  it 'recovers the same exact live configuration twice through a root shell' do
    session_id = open_nifi_session('shell', deliveries.fetch('shell'), user: 'root')
    2.times { verify_live_result(collect(session_id), session_id) }
  end

  it 'recovers a genuine identity-only file twice through the NiFi shell' do
    session_id = open_nifi_session('shell', deliveries.fetch('shell'))
    2.times do
      output = collect(session_id, path: '/tmp/module-target-nifi-files/identity-only')
      expect(output).to include(@native.fetch('native_files').fetch('identity').fetch(0).fetch('hash'))
      expect(output).not_to include('Decrypted data saved in:')
      verify_identity(rows.fetch(0), session_id)
      expect(rows.length).to eq(1)
    end
  end

  it 'uses explicit genuine copied file options with spaces twice through the NiFi shell' do
    session_id = open_nifi_session('shell', deliveries.fetch('shell'))
    directory = '/tmp/module-target-nifi-files/explicit files/conf'
    files = { 'NIFI_PROPERTIES' => "#{directory}/nifi.properties", 'NIFI_FLOW_JSON' => "#{directory}/flow.json.gz", 'NIFI_IDENTITY' => "#{directory}/login-identity-providers.xml", 'NIFI_AUTHORIZERS' => "#{directory}/authorizers.xml" }
    2.times { verify_live_result(collect(session_id, path: '/tmp/module-target-nifi-files/missing', overrides: files), session_id) }
  end

  it 'handles entirely missing files twice through native NiFi Meterpreter' do
    session_id = open_nifi_session('meterpreter', deliveries.fetch('meterpreter'))
    2.times do
      output = collect(session_id, path: '/tmp/module-target-nifi-files/missing', allow_errors: true)
      expect(output).to include('Unable to find login-identity-providers.xml, nifi.properties and/or flow.json.gz files')
      expect(rows).to eq([])
    end
  end

  it 'reports the missing-key boundary twice without losing readable identity data' do
    session_id = open_nifi_session('shell', deliveries.fetch('shell'))
    2.times do
      output = collect(session_id, path: '/tmp/module-target-nifi-files/missing-key', allow_errors: true)
      expect(output).to match(/(?:Unable|Missing|No).*sensitive.*key/i)
      expect(output).to include(@native.fetch('native_files').fetch('identity').fetch(0).fetch('hash'))
      expect(rows.length).to eq(1)
      verify_identity(rows.fetch(0), session_id)
    end
  end

  it 'reports an unsupported algorithm twice while retaining readable identity through Meterpreter' do
    session_id = open_nifi_session('meterpreter', deliveries.fetch('meterpreter'))
    2.times do
      output = collect(session_id, path: '/tmp/module-target-nifi-files/unsupported-algorithm', allow_errors: true)
      expect(output).to include('Processor for MODULE_TARGET_UNSUPPORTED not implemented')
      expect(output).not_to include('Decrypted data saved in:')
      expect(rows.length).to eq(1)
      verify_identity(rows.fetch(0), session_id)
    end
  end

  it 'reports a derived corrupt authentication tag twice without a successful decrypted-loot claim' do
    session_id = open_nifi_session('shell', deliveries.fetch('shell'))
    2.times do
      output = collect(session_id, path: '/tmp/module-target-nifi-files/corrupt-tag', allow_errors: true)
      expect(output).to match(/(?:Unable|Failed|Invalid).*decrypt|authentication.*(?:fail|invalid)/i)
      expect(output).not_to include('Decrypted data saved in:')
    end
  end

  def native_action(action)
    @native_sequence += 1
    tag = "#{@case_id || 'suite'}-#{@native_sequence}-#{action}"
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/nifi_credentials/native.py', action, tag)
    File.write(File.join(target_runtime.fetch('artifacts'), "native-status-#{tag}.json"), JSON.pretty_generate(exitstatus: status.exitstatus, stdout: output, stderr: error))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def collect(session_id, path: '/opt/nifi/nifi-current', overrides: {}, allow_errors: false)
    output = run_target_module('post/linux/gather/apache_nifi_credentials', 'linux', { 'VERBOSE' => false, 'SESSION' => session_id, 'NIFI_PATH' => path }.merge(overrides), allow_errors: allow_errors, endpoint_options: {})
    expect(output).to include('Post module execution completed')
    expect(output).not_to match(/Post failed|NoMethodError|TypeError|JSON::ParserError|OpenSSL::Cipher::CipherError|Unknown datastore option/)
    expect(output).not_to include('Post aborted') unless allow_errors
    output
  end

  def verify_live_result(output, session_id)
    facts = @native.fetch('native_files')
    values = facts.fetch('crypto').fetch('decrypted').map { |item| item.fetch('plaintext') }.uniq
    values.each { |value| expect(output).to include(value) }
    expect(output).to include('module-test-user', 'moduletargetaccount')
    expect(output).to match(/Key Password\s+#{Regexp.escape(@native.fetch('seed').fetch('stores').fetch('keystore').fetch('path'))}/)
    properties = output[/properties data saved in: (.+)$/, 1]&.strip
    original = output[/Original data containing encrypted fields saved in: (.+)$/, 1]&.strip
    decrypted = output[/Decrypted data saved in: (.+)$/, 1]&.strip
    expect(properties).not_to be_nil
    expect(original).not_to be_nil
    expect(decrypted).not_to be_nil
    expect(loot_bytes(properties)).to eq(File.binread(File.join(target_runtime.fetch('artifacts'), 'native-nifi.properties'))) if properties
    source_flow = Zlib.gunzip(File.binread(File.join(target_runtime.fetch('artifacts'), 'native-flow.json.gz')))
    expect(loot_bytes(original)).to eq(source_flow) if original
    if decrypted
      expected = JSON.parse(source_flow)
      facts.fetch('crypto').fetch('decrypted').each do |item|
        parent = item.fetch('path')[0...-1].reduce(expected) { |value, key| value.fetch(key) }
        parent[item.fetch('path').last] = item.fetch('plaintext')
      end
      expect(JSON.parse(loot_bytes(decrypted))).to eq(expected)
    end
    current = rows
    expected_private = facts.fetch('private_values') + [facts.fetch('identity').fetch(0).fetch('hash')]
    # Distinct stored contexts may legitimately share the same private value.
    # Require all native secrets, exact origins and repeat-stable core rows.
    expect(current.map { |item| item.fetch('private_data') }.uniq.sort).to eq(expected_private.uniq.sort)
    @credential_sets ||= {}
    key = [@workspace, session_id]
    if @credential_sets.key?(key)
      expect(current).to eq(@credential_sets.fetch(key))
    else
      @credential_sets[key] = current
    end
    current.each { |item| verify_origin(item, session_id) }
    identity = current.find { |item| item.fetch('private_type') == 'Metasploit::Credential::NonreplayableHash' }
    expect(identity).not_to be_nil
    verify_identity(identity, session_id) if identity
    basic = current.find { |item| item.fetch('private_data') == 'module-test-password' }
    expect(basic).to include('username' => 'module-test-user', 'private_type' => 'Metasploit::Credential::Password')
  end

  def verify_origin(record, session_id)
    expect(record).to include('origin_type' => 'Metasploit::Credential::Origin::Session', 'post_reference_name' => 'linux/gather/apache_nifi_credentials', 'workspace' => @workspace)
    expect(record.fetch('local_id').to_s).to eq(session_id)
    expect(record.fetch('host_workspace_id')).to eq(record.fetch('credential_workspace_id'))
  end

  def verify_identity(record, session_id)
    account = @native.fetch('native_files').fetch('identity').fetch(0)
    expect(record).to include('username' => account.fetch('username'), 'private_data' => account.fetch('hash'), 'private_type' => 'Metasploit::Credential::NonreplayableHash')
    verify_origin(record, session_id)
  end

  def report_sql(query)
    target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
  end

  def rows
    raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Anifi_post_[0-9_]+\z/)

    data = JSON.parse(report_sql(<<~SQL))
      SELECT coalesce(json_agg(record ORDER BY record.core_id), '[]'::json) FROM (
        SELECT core.id AS core_id, pub.username, secret.data AS private_data,
               secret.type AS private_type, core.origin_type, gathered.post_reference_name,
               gathered.session_id, sessions.local_id, workspace.name AS workspace,
               core.workspace_id AS credential_workspace_id, hosts.workspace_id AS host_workspace_id
        FROM metasploit_credential_cores core
        JOIN workspaces workspace ON workspace.id=core.workspace_id
        LEFT JOIN metasploit_credential_publics pub ON pub.id=core.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=core.private_id
        LEFT JOIN metasploit_credential_origin_sessions gathered ON gathered.id=core.origin_id AND core.origin_type='Metasploit::Credential::Origin::Session'
        LEFT JOIN sessions ON sessions.id=gathered.session_id
        LEFT JOIN hosts ON hosts.id=sessions.host_id
        WHERE workspace.name='#{@workspace}'
      ) record;
    SQL
    File.write(File.join(target_runtime.fetch('artifacts'), "database-#{@workspace}.json"), JSON.pretty_generate(data))
    data
  end

  def loot_bytes(path)
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    File.binread(path)
  end
end
