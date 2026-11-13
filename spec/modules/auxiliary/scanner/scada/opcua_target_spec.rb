require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/opcua/acceptance'

RSpec.describe 'Genuine OPC-UA handshake detection and reporting', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::Opcua

  before(:all) do
    @native = opcua_native('before')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = 'opcua_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    @call = 0
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(opcua_services).to eq([])
  end

  after do
    expect(fx_json('framework.sessions.keys')).to eq([])
    expect(fx_json('framework.jobs.keys')).to eq([])
    opcua_services if @workspace
  end

  after(:all) do
    if @native
      current = opcua_native('after')
      %i[identity binary_manifest packages_sha256].each { |field| expect(current.fetch(field)).to eq(@native.fetch(field)) }
      expect(current.fetch(:protocol).fetch('records')).to eq(@native.fetch(:protocol).fetch('records'))
      File.write(File.join(target_runtime.fetch('artifacts'), 'target-proxy-journal.jsonl'), target_exec('target', 'cat', '/tmp/opcua-lab/proxy.jsonl'))
      fx_resources
    end
  end

  [
    [4840, 'default native ACK'],
    [4841, 'custom-buffer native ACK'],
    [4842, 'genuine error from the configured native server'],
    [5840, 'fragmented genuine ACK'],
    [5842, 'fragmented genuine ERR']
  ].each do |port, label|
    it "detects and persists the #{label} twice without duplicates" do
      first = nil
      2.times do
        opcua_verify(port)
        rows = opcua_services
        expect(rows.length).to eq(1)
        expect(rows).to eq(first) if first
        first = rows
      end
    end
  end

  [[5841, 'truncated native frame'], [2525, 'unrelated native SMTP server'], [1, 'refused port']].each do |port, label|
    it "does not report a service for the #{label}, twice" do
      2.times do
        expect(opcua_call(port)).not_to include('OPC-UA server detected')
        expect(opcua_services).to eq([])
      end
    end
  end

  it 'preserves both actual endpoint records when switching ports repeatedly' do
    [4840, 4841, 4840, 4841].each { |port| opcua_verify(port) }
    expect(opcua_services.map { |row| row.fetch('port') }).to eq([4840, 4841])
  end
end
