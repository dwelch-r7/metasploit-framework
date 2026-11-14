require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/langflow/acceptance'

profile = ENV.fetch('LANGFLOW_PROFILE', 'populated')

RSpec.describe 'Genuine Langflow MCP information collection', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::Langflow

  before(:all) do
    @native = langflow_native('seed', 'before')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    @ready = true
  end

  before do |example|
    @workspace = "langflow_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(langflow_reports).to eq([])
    langflow_idle
  end

  after { langflow_idle }

  after(:all) do
    if @ready
      expect(langflow_native('verify', 'after')).to eq(@native)
      expect(langflow_native('cleanup', 'cleanup')).to eq('flow_registry_restored' => true)
    end
    %w[target framework reporting_db].each do |role|
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  if profile == 'auth'
    it 'rejects anonymous collection on a native-proven working authenticated service twice on the same instance' do
      2.times do |index|
        output, paths = langflow_call({}, reuse: index.positive?)
        expect(output).to include('MCP SSE endpoint returned HTTP/1.1 403')
        expect(output).not_to include('MCP initialize accepted', 'MCP tools discovered', 'information stored in loot:')
        expect(paths).to eq([])
      end
      expect(langflow_reports).to eq([])
    end
  else
    it 'collects complete native MCP metadata twice on the same selected owner with fresh sessions' do
      2.times { |index| langflow_collect(reuse: index.positive?) }
      expect(langflow_reports.length).to eq(2)
    end
  end

  it 'rejects a nonexistent application path twice without persisting loot' do
    2.times do |index|
      output, paths = langflow_call({ 'TARGETURI' => '/module-target-missing/' }, reuse: index.positive?)
      expect(output).to include('MCP SSE endpoint returned HTTP/1.1 404')
      expect(paths).to eq([])
    end
    expect(langflow_reports).to eq([])
  end

  it 'handles a native-proven refused port twice without persisting loot' do
    target_exec('target', 'python', '-c', 'import socket; s=socket.socket(); assert s.connect_ex(("127.0.0.1",1)) != 0; s.close()')
    2.times do |index|
      output, paths = langflow_call({ 'RPORT' => 1 }, reuse: index.positive?)
      expect(output).to include('MCP communication failed:')
      expect(paths).to eq([])
    end
    expect(langflow_reports).to eq([])
  end
end
