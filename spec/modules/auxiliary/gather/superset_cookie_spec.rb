require 'acceptance_spec_helper'
require 'base64'
require_relative '../../../../tools/dev/run_module_target_tests'

RSpec.describe 'Genuine Superset cookie and credential owners', acceptance: true do
  include_context 'module target'

  gather = 'auxiliary/gather/apache_superset_cookie_sig_priv_esc'
  flask = 'auxiliary/gather/python_flask_cookie_signer'

  before(:all) do
    native_phase('before')
    @native = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-before/native-result.json')))
    expect(@native.fetch('status')).to eq('native_passed')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to include('[-]')
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @database_address = target_exec('framework', 'ruby', '-rsocket', '-e', "puts IPSocket.getaddress('reporting_db')").strip
    @keys = File.join(target_runtime.fetch('artifacts'), 'superset-keys.txt')
    @wrong_keys = File.join(target_runtime.fetch('artifacts'), 'wrong-keys.txt')
    File.write(@keys, "module-target-incorrect-secret\nCHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET\n")
    File.write(@wrong_keys, "module-target-incorrect-secret\n")
  end

  before do |example|
    @workspace = "superset_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(credential_rows).to eq([])
  end

  after(:all) do
    native_phase('after') if @native && @native['status'] == 'native_passed'
  end

  it 'recognizes the genuine affected release' do
    output = run_target_module(gather, 'gateway', gather_options, action: 'check', allow_errors: true)
    expect(output).to include('Apache Supset 2.0.0 is vulnerable', 'The target appears to be vulnerable.')
  end

  it 'collects exact datasource credentials and Untried SQL rows twice' do
    rows = nil
    2.times do
      output = run_target_module(gather, 'gateway', gather_options, allow_errors: true)
      expect(output).to include('Cookie validated to user: lab-admin', 'Found Module Native PostgreSQL:')
      current = credential_rows
      expect(current.size).to eq(1)
      expect(current.first).to include('username' => 'module_native', 'password' => 'module-target-superset-database-password',
                                       'host' => @database_address, 'port' => 5432, 'service' => 'postgresql', 'status' => 'Untried', 'workspace' => @workspace,
                                       'module_full_name' => gather, 'origin_type' => 'Metasploit::Credential::Origin::Service', 'last_attempted_at' => nil)
      expect(current.first.fetch('host_workspace_id')).to eq(current.first.fetch('credential_workspace_id'))
      expect(current.first.fetch('origin_service_id')).to eq(current.first.fetch('service_id'))
      expect(current).to eq(rows) if rows
      rows = current
    end
  end

  it 'uses the native-proven anonymous cookie path after a rejected password' do
    expect(@native.fetch('cookie_controls').fetch('anonymous_cookie_escalation')).to be(true)
    output = run_target_module(gather, 'gateway', gather_options.merge('PASSWORD' => 'module-target-incorrect-password'), allow_errors: true)
    expect(output).to include('Cookie validated to user: lab-admin', 'Found Module Native PostgreSQL:')
    expect(credential_rows).to contain_exactly(include('username' => 'module_native', 'password' => 'module-target-superset-database-password',
                                                       'host' => @database_address, 'port' => 5432, 'service' => 'postgresql', 'status' => 'Untried', 'workspace' => @workspace))
  end

  it 'refuses an absent administrator identity without creating credentials' do
    output = run_target_module(gather, 'gateway', gather_options.merge('ADMIN_ID' => 99999), allow_errors: true)
    expect(output).to include('Cookie not accepted', 'Unable to sign cookie with a valid secret')
    expect(credential_rows).to eq([])
  end

  it 'refuses an incorrect key wordlist without creating credentials' do
    output = run_target_module(gather, 'gateway', gather_options.merge('SECRET_KEYS_FILE' => @wrong_keys), allow_errors: true)
    expect(output).to include('Unable to find secret key')
    expect(credential_rows).to eq([])
  end

  it 'does not identify unrelated Apache content as Superset' do
    output = run_target_module(gather, 'gateway', gather_options.merge('TARGETURI' => '/unrelated/'), action: 'check', allow_errors: true)
    expect(output).to include('Cannot reliably check exploitability.', 'Unexpected response code (404)')
    expect(output).not_to include('The target appears to be vulnerable.')
    expect(credential_rows).to eq([])
  end

  [
    ['correct', 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET', 'is correct.'],
    ['incorrect', 'module-target-incorrect-secret', 'is incorrect.'],
    ['absent', '', nil]
  ].each do |label, secret, expected|
    it "retrieves a real application cookie with a #{label} secret" do
      output = run_target_module(flask, 'gateway', { 'TARGETURI' => '/login/', 'ACTION' => 'Retrieve', 'SECRET' => secret })
      expect(output).to include('Decoded Cookie:', 'csrf_token')
      expect(output).to include(expected) if expected
      expect(output).not_to include('is correct.', 'is incorrect.') unless expected
    end
  end

  it 'finds the real application secret after an incorrect wordlist entry' do
    output = run_target_module(flask, 'gateway', { 'TARGETURI' => '/login/', 'ACTION' => 'FindSecret', 'SECRET_KEYS_FILE' => @keys }, allow_errors: true)
    expect(output).to include('Found secret key: CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET')
  end

  it 'refuses a cookie name the application never issued' do
    output = run_target_module(flask, 'gateway', { 'TARGETURI' => '/login/', 'ACTION' => 'Retrieve', 'CookieName' => 'absent-session' }, allow_errors: true)
    expect(output).to include('Response is missing the session cookie')
  end

  it 'preserves legacy literal String content in the installed serializer' do
    content = JSON.generate('user_id' => 1)
    output = run_target_module(flask, 'gateway', { 'ACTION' => 'Resign', 'CookieName' => 'session', 'SECRET' => 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET', 'NEWCOOKIECONTENT' => content })
    expect(inspect_cookie(output, 'literal').fetch('decoded')).to eq(content)
  end

  it 'resigns a structured session for genuine administrator identity' do
    records = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-before/native-http-observations.json')))
    signed = records.fetch('commands').map { |row| JSON.parse(row.fetch('argv').last) }.find { |row| row['action'] == 'sign' }
    content = signed.fetch('content')
    output = run_target_module(flask, 'gateway', { 'ACTION' => 'Resign', 'CookieName' => 'session', 'CookieContentFormat' => 'JSON', 'SECRET' => 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET', 'NEWCOOKIECONTENT' => JSON.generate(content) })
    inspected = inspect_cookie(output, 'identity')
    expect(inspected.fetch('decoded')).to eq(content)
    expect(inspected.fetch('status')).to eq(200)
    expect(JSON.parse(Base64.strict_decode64(inspected.fetch('body_base64'))).fetch('result').fetch('username')).to eq('lab-admin')
  end

  it 'rejects malformed JSON content without producing a signed cookie' do
    output = run_target_module(flask, 'gateway', { 'ACTION' => 'Resign', 'CookieContentFormat' => 'JSON', 'SECRET' => 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET', 'NEWCOOKIECONTENT' => '{invalid' }, allow_errors: true)
    expect(output).to include('NEWCOOKIECONTENT')
    expect(output).not_to include('New signed cookie:')
  end

  def inspect_cookie(output, mode)
    cookie = output[/New signed cookie: session=(\S+)/, 1]
    expect(cookie).not_to be_nil, output
    path = File.join(target_runtime.fetch('artifacts'), "owner-cookie-#{mode}.log")
    argv = ['python3', '-B', 'test/module_targets/superset_cookie/inspect_cookie.py', ENV.fetch('MODULE_TARGET_RUNTIME'), mode, cookie]
    expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 90, quiet: true)).to be(true)
    JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "owner-cookie-#{mode}/result.json")))
  end

  def gather_options
    { 'USERNAME' => 'lab-user', 'PASSWORD' => 'module-target-superset-user-password', 'SECRET_KEYS_FILE' => @keys }
  end

  def native_phase(phase)
    output = +''
    path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log")
    runner = ModuleTargetTests.new
    argv = ['python3', '-B', 'test/module_targets/superset_cookie/native_runtime.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
    passed = runner.send(:command, argv, path: path, timeout: 240, capture: output, quiet: true)
    expect(passed).to be(true), output
  end

  def credential_rows
    query = <<~SQL
      SELECT coalesce(json_agg(row), '[]'::json) FROM (
        SELECT c.id, l.id AS login_id, p.username, secret.data AS password,
               host(h.address::inet) AS host, s.id AS service_id, s.port, s.name AS service, l.status, l.last_attempted_at, w.name AS workspace,
               c.origin_type, o.module_full_name, o.service_id AS origin_service_id,
               c.workspace_id AS credential_workspace_id, h.workspace_id AS host_workspace_id
        FROM metasploit_credential_cores c
        JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id
        LEFT JOIN hosts h ON h.id=s.host_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        WHERE w.name='#{@workspace}' ORDER BY c.id,l.id
      ) row
    SQL
    JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
  end
end
