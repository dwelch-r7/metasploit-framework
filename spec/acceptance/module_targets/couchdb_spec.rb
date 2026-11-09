require 'acceptance_spec_helper'
require 'net/http'
require 'rbconfig'

RSpec.describe 'CouchDB module targets' do
  include_context 'module target'

  let_it_be(:native_couchdb) do
    endpoint = target_endpoint('couchdb')
    argv = [RbConfig.ruby, File.expand_path('test/module_targets/couchdb/native_probe.rb'), endpoint.fetch('host'), endpoint.fetch('port').to_s]
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-couchdb-preflight.json'), output)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-couchdb-preflight-command.json'), JSON.pretty_generate(argv: argv, error: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  before(:all) do
    native_couchdb
    endpoint = target_endpoint('apache')
    client = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    client.open_timeout = 3
    client.read_timeout = 3
    response = client.get('/_users/_all_docs')
    expect(response.code).to eq('200')
    expect(response['server']).to start_with('Apache/')
    expect(response.body).to eq(File.binread('test/module_targets/http/htdocs/index.html'))
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-unrelated-http.json'), JSON.pretty_generate(status: response.code, headers: response.to_hash, body: response.body))
  end

  it 'validates the native administrator login' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', 'couchdb', login_options('labadmin', 'labpassword'))
    expect(output).to include("Successful login with: 'labadmin' : 'labpassword'")
  end

  it 'does not validate an incorrect password' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', 'couchdb', login_options('labadmin', 'wrong-password'), allow_errors: true)
    expect(output).to include("Trying username:'labadmin' with password:'wrong-password'")
    expect(output).not_to include('Successful login')
  end

  it 'distinguishes a valid reader login from permission to list user records' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', 'couchdb', login_options('labreader', 'readerpassword'))
    expect(output).to include("Successful login with: 'labreader' : 'readerpassword'")
  end

  it 'does not validate a login on an unrelated HTTP 200 fallback' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_login', 'apache', login_options('labadmin', 'labpassword'), allow_errors: true)
    expect(output).not_to include('Successful login')
  end

  it 'recognizes the fixed version on the native database' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', 'couchdb', enumeration_options, action: 'check', allow_errors: true)
    expect(output).to include('CouchDB version is not in the vulnerable range')
  end

  it 'collects the exact native database list and full document/attachment loot' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', 'couchdb', enumeration_options.merge('SERVERINFO' => true))
    expect(output).to include(native_couchdb.fetch('version').fetch('version'))
    list_path = loot_path(output, 'File saved in:')
    expect(JSON.parse(File.read(list_path))).to eq(native_couchdb.fetch('databases'))
    documents = JSON.parse(File.read(loot_path(output, 'module_evidence saved in:')))
    expect(documents).to eq(native_couchdb.fetch('documents'))
  end

  it 'does not save database loot after rejected authentication' do
    original_loot = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', 'couchdb', enumeration_options.merge('HttpPassword' => 'wrong-password'), allow_errors: true)
    expect(output).to include('401')
    expect(output).not_to include('File saved in:', 'module_evidence saved in:')
    expect(Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]).to eq(original_loot)
  end

  it 'does not identify unrelated HTTP as a vulnerable CouchDB release' do
    output = run_target_module('auxiliary/scanner/couchdb/couchdb_enum', 'apache', enumeration_options, action: 'check', allow_errors: true)
    expect(output).to include('Failed to retrieve CouchDB version')
  end

  def login_options(username, password)
    {
      'USERNAME' => username, 'PASSWORD' => password, 'USER_FILE' => nil, 'PASS_FILE' => nil, 'USERPASS_FILE' => nil,
      'BLANK_PASSWORDS' => false, 'USER_AS_PASS' => false, 'STOP_ON_SUCCESS' => false
    }
  end

  def enumeration_options
    { 'HttpUsername' => 'labadmin', 'HttpPassword' => 'labpassword', 'CREATEUSER' => false, 'TARGETURI' => '/_all_dbs' }
  end

  def loot_path(output, label)
    path = output[/#{Regexp.escape(label)} (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    path
  end
end
