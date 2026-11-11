require 'acceptance_spec_helper'
require 'shellwords'
require_relative '../../../../test/module_targets/owncloud_phpinfo/acceptance'

profile = ENV.fetch('OWNCLOUD_PROFILE', 'root')

RSpec.describe 'Genuine ownCloud phpinfo collection', acceptance: true do
  include_context 'module target'
  include Acceptance::OwncloudPhpinfo

  before(:all) do
    @fixed = profile == 'fixed'
    @native = owncloud_native('before')
    expect(owncloud_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    if @native
      current = owncloud_native('after')
      %w[environment graph_version test_file_sha256 app_tree_sha256 app_file_count identity owncloud_status addresses].each do |key|
        expect(current.fetch(key)).to eq(@native.fetch(key))
      end
    end
  end

  before do |example|
    @workspace = "owncloud_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(owncloud_reports.values).to all(eq([]))
  end

  after { owncloud_reports if @workspace }

  it 'uses default discovery twice and preserves the complete actual response in loot' do
    original = nil
    2.times do
      owncloud_collection({ 'HttpTrace' => true, 'HttpTraceColors' => '/' })
      rows = owncloud_reports.fetch('credentials')
      expect(rows).to eq(original) if original
      original = rows
    end
  end

  it 'accepts the explicit empty root at the native application base twice' do
    2.times { owncloud_collection({ 'TARGETURI' => @native.fetch('prefix') + '/', 'ROOT' => '' }) }
    if profile == 'prefix'
      # Empty ROOT at / must not silently fall back to discovery of /owncloud.
      2.times { owncloud_collection({ 'ROOT' => '', 'TARGETURI' => '/' }, exposed: false) }
    end
  end

  it 'handles the explicit owncloud root according to the real deployment twice' do
    2.times { owncloud_collection({ 'ROOT' => 'owncloud' }, exposed: !@fixed && profile == 'prefix') }
  end

  Acceptance::OwncloudPhpinfo::SUFFIXES.each do |suffix|
    it "handles the native-proven explicit #{suffix} suffix" do
      owncloud_collection({ 'ENDFILE' => suffix })
    end
  end

  it 'uses the explicit application base URI twice' do
    2.times { owncloud_collection({ 'TARGETURI' => @native.fetch('prefix') + '/' }) }
  end

  it 'does not create loot or credentials for a nonexistent application base twice' do
    2.times { owncloud_collection({ 'TARGETURI' => '/module-target-missing/' }, exposed: false) }
  end

  it 'refuses the native-proven closed port twice without false collection' do
    2.times do
      output, paths = owncloud_call({ 'RPORT' => 1 })
      expect(output).to include('Could not connect to web service')
      expect(output).not_to include('Found phpinfo page', 'Loot stored to:', 'Credentials')
      expect(paths).to eq([])
      expect(owncloud_reports.values).to all(eq([]))
    end
  end
end
