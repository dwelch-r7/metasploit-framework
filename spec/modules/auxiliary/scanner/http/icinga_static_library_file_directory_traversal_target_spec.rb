require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/icinga/acceptance'

RSpec.describe 'Genuine Icinga static-library file collection', acceptance: true, order: :defined do
  include_context 'module target'
  include Acceptance::Icinga

  before(:all) do
    @version = ENV.fetch('ICINGA_VERSION')
    @prefix = ENV.fetch('ICINGA_PREFIX')
    @native = icinga_native('before')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  before do |example|
    @workspace = 'icinga_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(icinga_reports).to eq([])
  end

  after do
    expect(fx_json('framework.sessions.keys')).to eq([])
    expect(fx_json('framework.jobs.keys')).to eq([])
    icinga_reports if @workspace
  end

  after(:all) do
    if @native
      current = icinga_native('after')
      %i[source version identity apache proofs].each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
      fx_resources
    end
  end

  it 'detects the real anonymous application twice without claiming the bug was exercised' do
    2.times do
      output = icinga_call({}, action: 'check')
      expect(output).to include('Icinga Web 2 found, unable to determine version.'.b)
      expect(icinga_reports).to eq([])
    end
  end

  it 'does not detect the unrelated PHP static server twice' do
    2.times do
      output = icinga_call({ 'RPORT' => 8081, 'TARGETURI' => '/' }, action: 'check')
      expect(output).to include("Web server found, but couldn't detect Icinga".b)
      expect(icinga_call({ 'RPORT' => 8081, 'TARGETURI' => '/', 'FILE' => '/lab/proof/proof.txt' })).not_to include(' saved to '.b)
      expect(icinga_reports).to eq([])
    end
  end

  [
    ['proof.txt', 'exact multiline text'],
    ['whitespace.txt', 'leading and trailing whitespace'],
    ['binary.bin', 'all 256 binary octets'],
    ['empty.txt', 'a genuine empty file without false loot'],
    ['space name.txt', 'a filename with a space using the independently observed HTTP refusal'],
    ['unicode-Ω.txt', 'a UTF-8 filename using the native request result'],
    ['denied.txt', 'an existing unreadable file'],
    ['missing.txt', 'a missing file'],
    ['directory', 'a directory']
  ].each do |name, label|
    it "handles #{label} twice" do
      icinga_collect(name)
    end
  end

  it 'handles a refused port twice without collecting error-page loot' do
    2.times do
      expect(icinga_call({ 'RPORT' => 1 }, action: 'check')).to include('Could not connect to web service - no response'.b)
      expect(icinga_call({ 'RPORT' => 1, 'FILE' => '/lab/proof/proof.txt' })).not_to include(' saved to '.b)
      expect(icinga_reports).to eq([])
    end
  end
end
