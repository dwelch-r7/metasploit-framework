require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/concretecms/acceptance'

RSpec.describe 'Genuine Concrete CMS file-usage collection', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::ConcreteCms

  before(:all) do
    @unrelated = ENV['CONCRETE_UNRELATED'] == 'true'
    @version = ENV['CONCRETE_VERSION']
    @prefix = ENV.fetch('CONCRETE_PREFIX', '')
    @exposed = @version == '9.5.0'
    @birth = target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)
    @state = cms_state unless @unrelated
    cms_native_control('before')
    expect(cms_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    refused = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"CMS_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"CMS_REFUSED=true\"; end'")
    expect(refused).to include('CMS_REFUSED=true')
    @native_ready = true
  end

  before do |example|
    @workspace = "cms_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(cms_reports).to eq([])
  end

  after do
    %w[sessions jobs].each do |kind|
      expect(console_command("irb -e 'puts \"CMS_IDLE=\" + framework.#{kind}.keys.to_json'")).to include('CMS_IDLE=[]')
    end
    expect(target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19)).to eq(@birth)
  end

  after(:all) do
    cms_native_control('after') if @native_ready
    %w[target reporting_db framework].each do |role|
      events = target_exec(role, 'cat', '/sys/fs/cgroup/memory.events')
      expect(events).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(role, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end

  if ENV['CONCRETE_UNRELATED'] == 'true'
    it 'rejects the unrelated Apache endpoint twice without loot or vulnerabilities' do
      cms_collect_twice({ 'FID_START' => 1, 'COUNT' => 3 }, start: 1, count: 3)
    end
  else
    it 'collects public and private paths once per page despite duplicate blocks and versions' do
      fid = @state.fetch('seed').fetch('files').fetch('public')
      rows = @state.fetch('usage').select { |row| row.fetch('file_id') == fid }
      expect(rows.map { |row| row.fetch('collection_version_id') }.uniq.length).to be > 1
      expect(@state.fetch('expected_usage').fetch(fid.to_s).length).to eq(2)
      cms_collect_twice({ 'FID_START' => fid, 'COUNT' => 1 }, start: fid, count: 1)
    end

    it 'collects the Unicode private-only reference twice' do
      fid = @state.fetch('seed').fetch('files').fetch('private')
      expect(@state.fetch('pages').fetch('private').fetch('path')).to include('Ω')
      cms_collect_twice({ 'FID_START' => fid, 'COUNT' => 1 }, start: fid, count: 1)
    end

    it 'enumerates the exact bounded range across an unused file' do
      fid = @state.fetch('seed').fetch('files').fetch('public')
      expect(@state.fetch('seed').fetch('files').fetch('private')).to eq(fid + 2)
      cms_collect_twice({ 'FID_START' => fid, 'COUNT' => 3 }, start: fid, count: 3)
    end

    it 'does not save loot or report a vulnerability for an unused real file' do
      fid = @state.fetch('seed').fetch('files').fetch('unused')
      cms_collect_twice({ 'FID_START' => fid, 'COUNT' => 1 }, start: fid, count: 1)
    end

    it 'handles nonexistent IDs twice without inventing references' do
      cms_collect_twice({ 'FID_START' => 999_999, 'COUNT' => 2 }, start: 999_999, count: 2)
    end

    it 'honors the default start and 50-ID count twice with exact exports' do
      cms_collect_twice
    end

    it 'rejects a genuinely missing application path twice without loot or reports' do
      missing = cms_path('/module-target-missing')
      response = cms_request(missing + '/ccm/system/dialogs/file/usage/1', 'missing-path-control')
      expect(response.code.to_i).to eq(404)
      cms_collect_twice({ 'TARGETURI' => missing, 'COUNT' => 2 }, count: 2, rejected: true)
    end
  end

  it 'handles a native-proven refused port twice without loot or reports' do
    cms_collect_twice({ 'RPORT' => 1, 'COUNT' => 2 }, count: 2, rejected: true)
  end
end
