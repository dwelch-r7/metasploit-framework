require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/saltstack_gather/acceptance'

RSpec.describe 'Genuine Salt configuration and inventory collection', acceptance: true, order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::SaltstackGather

  before(:all) do
    @native = sg_native('before')
    expect(@native.fetch('status')).to eq('native_passed')
    expect(sx_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    code = "load 'test/module_targets/saltstack_rce/session_control.rb'; puts 'SALT_OBSERVER=' + DruidSessionControl.install(framework).to_json"
    expect(console_command("irb -e #{code.inspect}")).to include('SALT_OBSERVER=', 'installed')
  end

  after(:all) do
    if @native && @native.fetch('status') == 'native_passed'
      current = sg_native('after')
      %w[roles processes vendor_files packages inputs minion_config keys].each do |key|
        expect(current.fetch('cluster').fetch(key)).to eq(@native.fetch('cluster').fetch(key))
      end
    end
  end

  before do |example|
    @workspace = "sr_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(sx_sessions_sql).to eq([])
    sx_cleanup
  end

  after { sx_cleanup }

  ['python/meterpreter/reverse_https', 'cmd/unix/reverse_python'].each do |payload|
    { 'default' => {}, 'inventory_only' => { 'GETHOSTNAME' => false, 'GETIP' => false, 'GETOS' => false } }.each do |label, options|
      it "collects #{label} through #{payload}" do
        identifier = sg_session(payload)
        snapshot = sg_call(identifier, options, label)
        expect(snapshot.fetch(:loot)).not_to be_empty
        proof = sx_proof(identifier, payload, owner: 'exploit/multi/handler')
        expect(proof.fetch('role')).to eq('master')
      end
    end
  end
end
