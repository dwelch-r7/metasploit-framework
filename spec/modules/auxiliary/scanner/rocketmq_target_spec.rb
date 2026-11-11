require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/rocketmq/acceptance'

RSpec.describe 'Native RocketMQ discovery and check paths', acceptance: true do
  include_context 'module target'
  include Acceptance::Rocketmq

  before(:all) do
    @native = %w[vulnerable fixed].to_h do |role|
      result = rocketmq_native(role, 'before', 'control')
      expect(result).to include('status' => 'native_passed', 'logical_config_restored' => true, 'marker_absent' => true)
      expect(result.fetch('executed')).to be(role == 'vulnerable')
      expect(result.fetch('marker_uid')).to eq(3000) if role == 'vulnerable'
      expect(result.fetch('allowed_noop_update').fetch('code')).to eq(0)
      expect(result.fetch('restore').fetch('code')).to eq(0)
      native = result.fetch('before')
      version = role == 'vulnerable' ? '4.9.4' : '5.1.1'
      expect(native.fetch('client_version')).to eq("V#{version.tr('.', '_')}")
      expect(native.fetch('route').fetch('version')).to eq(native.fetch('client_version'))
      expect(native.fetch('uid')).to eq(3000)
      expect(native.fetch('config')).to include('listenPort' => '10921', 'filterServerNums' => '0', 'rocketmqHome' => "/home/rocketmq/rocketmq-#{version}")
      address = target_runtime.fetch('module_endpoints').fetch(role).fetch('host')
      expect(native.fetch('route_data').fetch('brokerDatas').first.fetch('brokerAddrs').fetch('0')).to eq("#{address}:10921")
      expect(target_exec(role, 'cat', "/proc/#{native.fetch('broker_pid')}/status")).to match(/^Uid:\s+3000\s+3000\s+3000\s+3000$/)
      [role, native]
    end
    code = 'load "test/module_targets/rocketmq/observer.rb"; ' \
           '["auxiliary/scanner/misc/rocketmq_version", "exploit/multi/http/apache_rocketmq_update_config"].each { |name| framework.modules.create(name).class.prepend(ModuleTargetRocketmqObservations) }'
    expect(console_command("irb -e '#{code}'")).not_to match(/Error|Exception/)
  end

  after(:all) do
    if @native
      %w[vulnerable fixed].each do |role|
        result = rocketmq_native(role, 'after')
        expect(result.fetch('config')).to eq(@native.fetch(role).fetch('config'))
        expect(result.fetch('route_data')).to eq(@native.fetch(role).fetch('route_data'))
        expect(result.fetch('broker_pid')).to eq(@native.fetch(role).fetch('broker_pid'))
      end
    end
  end

  %w[vulnerable fixed].each do |role|
    it "enumerates the genuine #{role} version and nondefault broker twice" do
      2.times do
        native = @native.fetch(role)
        version = native.fetch('route').fetch('version').tr('_', '.')
        output, wire = rocketmq_call('scan', role)
        expect(output).to include("RocketMQ version #{version} found with brokers:")
        broker = native.fetch('route_data').fetch('brokerDatas').first
        expect(output).to include(broker.fetch('brokerName'), broker.fetch('brokerAddrs').fetch('0'))
        expect(wire.size).to eq(1)
        expect(wire.first.fetch('bytes')).to be > 100
      end
    end

    it "classifies the genuine #{role} release twice" do
      2.times do
        output, wire = rocketmq_call('check', role, {}, allow_errors: role == 'fixed')
        expect(output).to include(role == 'vulnerable' ? 'The target appears to be vulnerable' : 'The target is not exploitable')
        expect(output).to include("RocketMQ version: #{role == 'vulnerable' ? '4.9.4' : '5.1.1'}")
        expect(wire.size).to eq(1)
      end
    end
  end

  %w[scan check].each do |kind|
    it "handles the real Broker's unsupported route request as a #{kind} negative twice" do
      2.times do
        output, wire = rocketmq_call(kind, 'fixed', { 'RPORT' => 10921 }, allow_errors: true)
        expect(output).not_to include('found with brokers:', 'appears to be vulnerable')
        expect(output).to include(kind == 'scan' ? 'RocketMQ version V5.1.1' : 'The target is not exploitable. RocketMQ version: 5.1.1')
        expect(wire.size).to eq(1)
      end
    end

    it "handles a refused connection as a #{kind} negative twice" do
      2.times do
        output, wire = rocketmq_call(kind, 'fixed', { 'RPORT' => 9988 }, allow_errors: true)
        expect(output).not_to include('found with brokers:', 'appears to be vulnerable')
        expect(output).not_to match(%r{/usr/src/metasploit-framework/[^\n]+:\d+:in})
        expect(wire.map { |row| row['bytes'] }).to eq([nil])
      end
    end
  end
end
