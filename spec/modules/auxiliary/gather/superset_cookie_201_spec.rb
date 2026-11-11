require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/superset_cookie/acceptance'

RSpec.describe 'Genuine Superset 2.0.1 check and disclosure boundaries', acceptance: true do
  include_context 'Superset cookie owner evidence'

  gather = 'auxiliary/gather/apache_superset_cookie_sig_priv_esc'
  rce = 'exploit/linux/http/apache_superset_cookie_sig_rce'

  before(:all) do
    native_phase('before')
    @native = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-before/native-result.json')))
    expect(@native.fetch('status')).to eq('native_passed')
    expect(@native.fetch('identity').fetch('packages').fetch('apache-superset')).to eq('2.0.1')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to include('[-]')
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @database_address = target_exec('framework', 'ruby', '-rsocket', '-e', "puts IPSocket.getaddress('reporting_db')").strip
    @keys = File.join(target_runtime.fetch('artifacts'), 'superset-keys.txt')
    File.write(@keys, "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET\n")
  end

  before do |example|
    @workspace = "superset_201_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(credential_rows).to eq([])
  end

  after(:all) do
    native_phase('after') if @native && @native['status'] == 'native_passed'
  end

  [gather, rce].each do |owner|
    it "recognizes the native-proven cookie vulnerability through #{owner}" do
      output = run_target_module(owner, 'gateway', gather_options, action: 'check', allow_errors: true)
      expect(output).to include('Apache Supset 2.0.1 is vulnerable', 'The target appears to be vulnerable.')
    end
  end

  it 'collects real credentials through the default AutoCheck path' do
    output = run_target_module(gather, 'gateway', gather_options, allow_errors: true)
    expect(output).to include('Cookie validated to user: lab-admin', 'Found Module Native PostgreSQL:')
    expect(credential_rows).to contain_exactly(include('host' => @database_address, 'username' => 'module_native',
                                                       'password' => 'module-target-superset-database-password', 'status' => 'Untried', 'workspace' => @workspace))
  end

  it 'collects repeatable SQL evidence with an explicit operator bypass' do
    previous = nil
    2.times do
      output = run_target_module(gather, 'gateway', gather_options.merge('ForceExploit' => true), allow_errors: true)
      expect(output).to include('Cookie validated to user: lab-admin', 'Found Module Native PostgreSQL:')
      current = credential_rows
      expect(current).to contain_exactly(include('host' => @database_address, 'username' => 'module_native',
                                                 'password' => 'module-target-superset-database-password', 'status' => 'Untried', 'workspace' => @workspace))
      expect(current).to eq(previous) if previous
      previous = current
    end
  end
end
