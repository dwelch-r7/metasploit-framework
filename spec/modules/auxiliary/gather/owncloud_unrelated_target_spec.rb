require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/owncloud_phpinfo/acceptance'

RSpec.describe 'ownCloud phpinfo reader against genuine Apache', acceptance: true do
  include_context 'module target'
  include Acceptance::OwncloudPhpinfo

  before(:all) do
    @native = owncloud_native('before')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    if @native
      current = owncloud_native('after')
      %w[ordinary_http identity].each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
    end
  end

  before do |example|
    @workspace = "owncloud_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(owncloud_reports.values).to all(eq([]))
  end

  after { owncloud_reports if @workspace }

  it 'does not collect or report phpinfo from the unrelated server twice' do
    2.times { owncloud_collection({}, exposed: false) }
  end

  it 'handles an explicit suffix on the unrelated server twice' do
    2.times { owncloud_collection({ 'ENDFILE' => 'css' }, exposed: false) }
  end
end
