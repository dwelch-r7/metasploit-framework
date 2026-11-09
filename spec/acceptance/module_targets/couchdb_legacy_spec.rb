require 'acceptance_spec_helper'
require 'rbconfig'
require_relative '../../../test/module_targets/couchdb/native_client'

RSpec.describe 'Legacy CouchDB module targets' do
  include_context 'module target'

  let_it_be(:native_couchdb) do
    %w[open auth].to_h do |service|
      endpoint = target_endpoint(service)
      argv = [RbConfig.ruby, File.expand_path('test/module_targets/couchdb_legacy/native_probe.rb'), endpoint.fetch('host'), endpoint.fetch('port').to_s, service]
      output, error, status = Open3.capture3(*argv)
      File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-native-preflight.json"), output)
      File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-native-command.json"), JSON.pretty_generate(argv: argv, error: error, exitstatus: status.exitstatus))
      expect(status.success?).to be(true), error
      [service, JSON.parse(output)]
    end
  end

  before(:all) { native_couchdb }

  %w[open auth].each do |service|
    it "detects the actual affected version on #{service}" do
      output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', service, { 'CREATEUSER' => false }, action: 'check', allow_errors: true)
      expect(output).to include('CouchDB version 1.6.1 is in the vulnerable range')
    end

    it "validates the real reader credentials on #{service}" do
      output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', service, login_options('readerpassword'))
      expect(output).to include("Successful login with: 'labreader' : 'readerpassword'")
    end

    it "rejects incorrect reader credentials on #{service}" do
      output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', service, login_options('wrong-password'), allow_errors: true)
      expect(output).to include("Trying username:'labreader' with password:'wrong-password'")
      expect(output).not_to include('Successful login')
    end

    it "extracts exact native databases and document bytes on #{service}" do
      options = { 'CREATEUSER' => false }
      options.merge!('HttpUsername' => 'labadmin', 'HttpPassword' => 'labpassword') if service == 'auth'
      output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', service, options)
      expect(JSON.parse(File.read(loot_path(output, 'File saved in:')))).to eq(native_couchdb.fetch(service).fetch('databases'))
      expect(JSON.parse(File.read(loot_path(output, 'module_evidence saved in:')))).to eq(native_couchdb.fetch(service).fetch('documents'))
    end
  end

  it 'creates actual administrator accounts twice and permits native operator cleanup' do
    endpoint = target_endpoint('auth')
    native = CouchDBNativeClient.new(endpoint.fetch('host'), endpoint.fetch('port'))
    %w[module_create_first module_create_second].each do |username|
      path = "/_users/org.couchdb.user:#{username}"
      expect(native.request('get', path).first).to eq(404)
      begin
        output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', 'auth', {
          'CREATEUSER' => true, 'HttpUsername' => username, 'HttpPassword' => 'module-user-password'
        }, allow_errors: true)
        code, identity = native.request('get', '/_session', nil, [username, 'module-user-password'])
        expect(code).to eq(200)
        expect(identity.fetch('userCtx').slice('name', 'roles')).to eq('name' => username, 'roles' => ['_admin'])
        expect(output).to include("User #{username} created with password module-user-password")
        expect(output).not_to include('Change Failed')
      ensure
        code, user = native.request('get', path)
        if code == 200
          removed, = native.request('delete', "#{path}?rev=#{user.fetch('_rev')}")
          expect([200, 202]).to include(removed)
        end
        File.write(File.join(target_runtime.fetch('artifacts'), 'native-created-user-commands.json'), JSON.pretty_generate(native.commands))
      end
      expect(native.request('get', path).first).to eq(404)
    end
  end

  def login_options(password)
    {
      'USERNAME' => 'labreader', 'PASSWORD' => password, 'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => false
    }
  end

  def loot_path(output, label)
    path = output[/#{Regexp.escape(label)} (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    path
  end
end
