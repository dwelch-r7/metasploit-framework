require 'spec_helper'
require_relative '../../../test/module_targets/redis_lua/acceptance'

RSpec.describe RedisLuaTarget do
  subject(:target) do
    Class.new do
      include RedisLuaTarget
      include RSpec::Matchers

      attr_reader :state, :target_runtime

      def initialize
        @rc = {}
        @state = @rc
        @target_runtime = { 'artifacts' => '/tmp/redis-lua-readiness-spec' }
      end
    end.new
  end

  before do
    allow(target).to receive(:rl_native).with('before').and_return('passed' => true, 'module_invoked' => false, 'settings' => { 'vulnerable' => true })
    allow(target).to receive(:rl_state).and_return('processes' => [], 'connections' => [])
    allow(target).to receive(:rc_json).and_return('installed' => true)
    allow(target).to receive(:rc_save)
    allow(target).to receive(:rc_resources).with('before')
    allow(target).to receive(:rl_idle)
  end

  it 'permits owner examples after every native readiness condition succeeds' do
    target.rl_ready

    expect(target.state[:prepared]).to be(true)
  end

  it 'withholds owner examples if resource qualification fails' do
    allow(target).to receive(:rc_resources).with('before').and_raise(IOError, 'Native resource limit was exceeded')

    expect { target.rl_ready }.to raise_error(IOError, 'Native resource limit was exceeded')
    expect(target.state[:prepared]).to be_falsey
  end

  it 'withholds owner examples if final native preservation fails' do
    allow(target).to receive(:rl_idle).and_raise(IOError, 'Native preservation did not pass')

    expect { target.rl_ready }.to raise_error(IOError, 'Native preservation did not pass')
    expect(target.state[:prepared]).to be_falsey
  end

  it 'withdraws previous readiness when a new qualification fails' do
    target.rl_ready
    allow(target).to receive(:rl_idle).and_raise(IOError, 'Requalification failed')

    expect { target.rl_ready }.to raise_error(IOError, 'Requalification failed')
    expect(target.state[:prepared]).to be_falsey
  end
end
