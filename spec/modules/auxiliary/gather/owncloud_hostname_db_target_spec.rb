require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/owncloud_phpinfo/acceptance'

RSpec.describe 'ownCloud hostname-only database credential collection', acceptance: true do
  include_context 'module target'
  include Acceptance::OwncloudPhpinfo

  def native_application(phase)
    output = +''
    argv = ['python3', 'test/module_targets/owncloud_graph_hostname_db/native_application.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
    passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-application-#{phase}.log"), timeout: 90, capture: output, quiet: true)
    expect(passed).to be(true), output
    data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-application-#{phase}.json")))
    expect(data.fetch('status')).to eq('application_port_verified')
    data
  end

  before(:all) do
    @fixed = false
    @native = owncloud_native('before')
    @application = native_application('before')
    expect(@native.fetch('environment').fetch('OWNCLOUD_DB_HOST')).to eq('reporting_db:5432')
    connection = @application.fetch('application').fetch('connection')
    expect(connection.fetch('port').to_i).to eq(5432)
    expect(connection.fetch('server_address')).to eq(@native.fetch('addresses').fetch('reporting_db'))
    expect(owncloud_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    expect(native_application('after').fetch('application')).to eq(@application.fetch('application')) if @application
    if @native
      current = owncloud_native('after')
      %w[environment graph_version test_file_sha256 app_tree_sha256 app_file_count identity owncloud_status addresses].each do |key|
        expect(current.fetch(key)).to eq(@native.fetch(key))
      end
    end
  end

  it 'stores credentials twice after the vendor normalizes a hostname-only database setting' do |example|
    @workspace = "owncloud_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(owncloud_reports.values).to all(eq([]))
    original = nil
    2.times do
      owncloud_collection
      rows = owncloud_reports.fetch('credentials')
      expect(rows).to eq(original) if original
      original = rows
    end
  ensure
    owncloud_reports if @workspace
  end
end
