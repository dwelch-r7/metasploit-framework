# frozen_string_literal: true

require_relative 'acceptance'

RSpec.shared_context 'n8n functional target' do
  include_context 'module target'
  include Acceptance::Ni8mare

  before(:all) do
    @native = native('before', 'before')
    @reader = @native.fetch('reader')
    expect(@reader.fetch('role')).to eq('global:member')
    expect(@reader.fetch('id')).not_to eq(@native.fetch('owner_id'))
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @case = example.metadata.fetch(:scoped_id).tr(':', '_')
    @workspace = "ni8mare_#{@case}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    @fixture = native('seed', 'ordinary')
    idle
  end

  after do |example|
    idle
  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
    record('cleanup-errors.jsonl', error: e.class.name, message: e.message)
    RSpec.world.wants_to_quit = true
    raise if example.exception.nil?
  end

  after(:all) do
    if @native
      result = native('after', 'after')
      expect(result).to include('restored' => true, 'flow_ids' => [], 'vendor' => @native.fetch('vendor'), 'calibration' => @native.fetch('calibration'))
    end
    %w[target framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end
end
