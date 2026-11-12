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
      %w[roles processes vendor_files packages inputs minion_config keys system_package].each do |key|
        expect(current.fetch('cluster').fetch(key)).to eq(@native.fetch('cluster').fetch(key))
      end
    end
  end

  before do |example|
    @workspace = "sr_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    @gather_session = nil
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(sx_sessions_sql).to eq([])
    sx_cleanup
  end

  after do |example|
    if @gather_session && sx_json('framework.sessions.keys').include?(@gather_session)
      proof = sx_proof(@gather_session, @gather_payload, owner: 'exploit/multi/handler')
      expect(proof.fetch('role')).to eq('master')
      sx_poll(20) do
        rows = sx_sessions_sql
        expect(rows.map { |row| row.fetch('id') }).to include(proof.fetch('db_id'))
        expect(rows.map { |row| row.fetch('closed_at') }).not_to include(nil)
      end
    end
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    sx_record('cleanup-proof-errors.jsonl', workspace: @workspace, error: e.class.name, message: e.message)
    raise if example.exception.nil?
  ensure
    sx_cleanup
  end

  {
    'default' => {},
    'inventory_only' => { 'GETHOSTNAME' => false, 'GETIP' => false, 'GETOS' => false },
    'hostname_only' => { 'GETHOSTNAME' => true, 'GETIP' => false, 'GETOS' => false },
    'interfaces_only' => { 'GETHOSTNAME' => false, 'GETIP' => true, 'GETOS' => false },
    'os_only' => { 'GETHOSTNAME' => false, 'GETIP' => false, 'GETOS' => true },
    'selected_minion' => { 'MINIONS' => 'module-target-minion-a' }
  }.each do |label, options|
    it "collects exact #{label} data through #{ENV.fetch('SALT_GATHER_PAYLOAD', 'python/meterpreter/reverse_https')}" do
      identifier = sg_session(ENV.fetch('SALT_GATHER_PAYLOAD', 'python/meterpreter/reverse_https'))
      first = sg_call(identifier, options, label)
      sg_verify(first, options)
      if %w[default inventory_only].include?(label)
        second = sg_call(identifier, options, "#{label}_repeat")
        sg_verify(second, options, previous_ids: first.fetch(:loot).map { |loot| loot.fetch('id') })
        expect(second.fetch('credentials')).to eq(first.fetch('credentials'))
      end
    end
  end
end
