require 'acceptance_spec_helper'
require 'base64'

RSpec.describe 'MongoDB module targets' do
  include_context 'module target'

  profiles = {
    'open44' => { version: '4.4.30', shell: 'mongo', auth: false },
    'auth44' => { version: '4.4.30', shell: 'mongo', auth: true },
    'open83' => { version: '8.3.11', shell: 'mongosh', auth: false },
    'auth83' => { version: '8.3.11', shell: 'mongosh', auth: true }
  }

  let_it_be(:native_mongodb) do
    profiles.to_h do |service, profile|
      expect(target_exec(service, profile.fetch(:shell), '--quiet', '/opt/native_health.js')).to include(profile.fetch(:version))
      native = native_document(service, profile, '/opt/native_inspect.js', 'MONGODB_NATIVE=')
      policy = native_document(service, profile, '/opt/native_unauth.js', 'MONGODB_POLICY=')
      expect(native.fetch('version')).to eq(profile.fetch(:version))
      expect(native.fetch('app_count')).to eq(111)
      expect(native.fetch('evidence').first.fetch('marker')).to eq('native-mongodb-proof')
      if profile.fetch(:auth)
        expect(policy.slice('ok', 'code')).to eq('ok' => 0, 'code' => 13)
        limited = native_document(service, profile, '/opt/native_limited.js', 'MONGODB_LIMITED=', arguments: [
          '--username', 'testuser', '--password', 'testpass', '--authenticationDatabase', 'intranet'
        ])
        expect(limited.fetch('marker')).to eq('native-mongodb-proof')
        expect(limited.fetch('system_users').slice('ok', 'code')).to eq('ok' => 0, 'code' => 13)
      else
        expect(policy.fetch('cursor').fetch('firstBatch').first.fetch('marker')).to eq('native-mongodb-proof')
      end
      [service, native]
    end
  end

  before(:all) { native_mongodb }

  profiles.each do |service, profile|
    context service do
      let(:credentials) do
        profile.fetch(:auth) ? { 'USERNAME' => 'rootuser', 'PASSWORD' => 'rootpass', 'AUTH_DB' => 'admin' } : { 'USERNAME' => nil, 'PASSWORD' => nil, 'AUTH_DB' => 'admin' }
      end

      it 'detects the unauthenticated version or its documented authentication boundary' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_version', service, { 'USERNAME' => nil, 'PASSWORD' => nil })
        expected = service == 'auth83' ? '8.1+' : profile.fetch(:version)
        expect(output).to include("MongoDB version: #{expected}")
      end

      it 'distinguishes required authentication before attempting configured credentials' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_login', service, login_options.merge(credentials))
        if profile.fetch(:auth)
          expect(output).to include("SUCCESSFUL LOGIN 'rootuser' : 'rootpass' (SCRAM-SHA-1)")
          expect(output).not_to include("doesn't use authentication")
        else
          expect(output).to include("doesn't use authentication")
        end
      end

      it 'extracts the exact native SCRAM hashes' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_hashdump', service, credentials.merge('DB' => 'admin', 'COLLECTION' => nil))
        native_mongodb.fetch(service).fetch('users').each do |user|
          user.fetch('credentials').each do |mechanism, fields|
            next unless %w[SCRAM-SHA-1 SCRAM-SHA-256].include?(mechanism)

            kind = mechanism == 'SCRAM-SHA-1' ? 0 : 1
            expected = "$mongodb-scram$*#{kind}*#{Base64.strict_encode64(user.fetch('user'))}*#{fields.fetch('iterationCount')}*#{fields.fetch('salt')}*#{fields.fetch('serverKey')}"
            expect(output).to include(expected)
          end
        end
      end

      it 'drains an application cursor past the first 101 records' do
        application_credentials = profile.fetch(:auth) ? { 'USERNAME' => 'testuser', 'PASSWORD' => 'testpass', 'AUTH_DB' => 'intranet' } : credentials
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_hashdump', service, application_credentials.merge(
          'DB' => 'intranet', 'COLLECTION' => 'app_users', 'USER_FIELD' => 'username', 'HASH_FIELD' => 'hash'
        ))
        rows = output.scan(/\bapp-user-(\d+)\s+([0-9a-f]{32})\b/)
        expect(rows.map { |row| row.first.to_i }.sort).to eq((0..110).to_a)
        expect(rows.map(&:last).uniq).to eq([native_mongodb.fetch(service).fetch('app_first').fetch('hash')])
      end

      it 'stores the actual nested schema and preserves the empty collection' do
        schema_credentials = profile.fetch(:auth) ? { 'USERNAME' => 'testuser', 'PASSWORD' => 'testpass', 'AUTH_DB' => 'intranet' } : credentials
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_schemadump', service, schema_credentials.merge('DB_NAME' => 'intranet', 'SAMPLE_SIZE' => 2))
        path = output[/Schema dumped to loot: (.+)$/, 1]&.strip
        expect(path).not_to be_nil, output
        expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
        schema = JSON.parse(File.read(path)).fetch('intranet')
        expect(schema.fetch('evidence').keys).to include('marker', 'count', 'enabled', 'nested.kind', 'tags')
        expect(schema.fetch('evidence').fetch('marker')).to eq('String')
        expect(schema.fetch('empty_evidence')).to eq({})
      end

      next unless profile.fetch(:auth)

      it 'rejects an incorrect password in the login scanner' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_login', service, login_options.merge(credentials).merge('PASSWORD' => 'wrong-password'), allow_errors: true)
        expect(output).to include('Trying user: rootuser, password: wrong-password')
        expect(output).not_to include('SUCCESSFUL LOGIN', "doesn't use authentication")
      end

      it 'authenticates a database-scoped user against the correct database' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_login', service, login_options.merge(
          'USERNAME' => 'testuser', 'PASSWORD' => 'testpass', 'AUTH_DB' => 'intranet'
        ))
        expect(output).to include("SUCCESSFUL LOGIN 'testuser' : 'testpass' (SCRAM-SHA-1)")
      end

      it 'does not expose system hashes to the database-scoped account' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_hashdump', service, {
          'USERNAME' => 'testuser', 'PASSWORD' => 'testpass', 'AUTH_DB' => 'intranet', 'DB' => 'admin', 'COLLECTION' => nil
        }, allow_errors: true)
        expect(output).to include('Query on admin.system.users failed:')
        expect(output).to match(/not authorized|Unauthorized/)
        expect(output).not_to include('$mongodb-scram$')
      end

      it 'does not dump hashes after rejected authentication' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_hashdump', service, credentials.merge(
          'PASSWORD' => 'wrong-password', 'DB' => 'admin', 'COLLECTION' => nil
        ), allow_errors: true)
        expect(output).to include('Login failed')
        expect(output).not_to include('$mongodb-scram$')
      end

      it 'does not create schema loot after rejected authentication' do
        output = run_target_module('auxiliary/scanner/mongodb/mongodb_schemadump', service, credentials.merge(
          'PASSWORD' => 'wrong-password', 'DB_NAME' => 'intranet'
        ), allow_errors: true)
        expect(output).to include('Stopping scan due to authentication failure.')
        expect(output).not_to include('Schema dumped to loot:')
      end
    end
  end

  it 'authenticates to retrieve the exact version beyond the buildInfo boundary' do
    output = run_target_module('auxiliary/scanner/mongodb/mongodb_version', 'auth83', {
      'USERNAME' => 'rootuser', 'PASSWORD' => 'rootpass', 'AUTH_DB' => 'admin'
    })
    expect(output).to include('MongoDB version: 8.3.11')
  end

  def native_document(service, profile, path, prefix, arguments: [])
    output = target_exec(service, profile.fetch(:shell), '--quiet', *arguments, path)
    line = output.lines.find { |entry| entry.start_with?(prefix) }
    expect(line).not_to be_nil, output
    JSON.parse(line.delete_prefix(prefix))
  end

  def login_options
    {
      'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => true
    }
  end
end
