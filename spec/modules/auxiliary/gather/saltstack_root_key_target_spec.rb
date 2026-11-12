require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/saltstack_zeromq/acceptance'

RSpec.describe 'Genuine Salt master root-key disclosure', acceptance: true do
  include_context 'module target'
  include Acceptance::SaltstackZeromq

  before(:all) do
    @vulnerable = ENV.fetch('SALT_VERSION') == '3000.1'
    @native = salt_native('before')
    expect(@native.fetch('master').fetch('auth_info_bytes')).to be > 255 if ENV['SALT_ACL'] == 'true'
    expect(salt_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    proof = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"SALT_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"SALT_REFUSED=true\"; end'")
    expect(proof).to include('SALT_REFUSED=true')
  end

  after(:all) do
    if @native
      current = salt_native('after')
      %w[version python pyzmq libzmq vendor_files packages fixture_files root_key_sha256 identity command].each do |key|
        expect(current.fetch('master').fetch(key)).to eq(@native.fetch('master').fetch(key))
      end
    end
  end

  before do |example|
    @workspace = "salt_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(salt_reports.values).to all(eq([]))
  end

  after { salt_reports if @workspace }

  it 'dumps twice with the default action and preserves actual credential identities' do
    first = salt_collection
    expect(salt_collection).to eq(first)
  end

  it 'recovers after a refused connection without leaking its port into later calls' do
    output = salt_call('RPORT' => 1)
    expect(output).to match(/Rex::ConnectionRefused|[Cc]onnection (?:was )?refused/)
    expect(output).not_to include('Root key:')
    expect(salt_reports.values).to all(eq([]))
    first = salt_collection
    expect(salt_collection).to eq(first)
  end

  it 'handles a hostname and explicit Dump action with correct resolved reporting' do
    first = salt_collection('RHOSTS' => 'target', 'ACTION' => 'Dump')
    expect(salt_collection).to eq(first)
  end
end
