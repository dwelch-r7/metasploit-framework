require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/forgejo_file/acceptance'

profile_version = ENV.fetch('FORGEJO_VERSION', '15.0.5')

RSpec.describe 'Genuine Forgejo org-mode file reads', acceptance: true do
  include_context 'module target'
  include Acceptance::ForgejoFile

  before(:all) do
    @vulnerable = %w[15.0.5 16.0.1].include?(profile_version)
    @native = forgejo_native('before')
    expect(forgejo_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    if @native
      current = forgejo_native('after')
      %w[files negative ordinary_markup contexts repositories search_first account identity configuration_sha256 binary_sha256].each do |key|
        expect(current.fetch(key)).to eq(@native.fetch(key))
      end
    end
  end

  before do |example|
    @workspace = "forgejo_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(forgejo_reports.values).to all(eq([]))
  end

  after { forgejo_reports if @workspace }

  it 'checks the native affected or fixed release twice and deduplicates its HTTP service' do
    first = nil
    2.times do
      output, paths = forgejo_call({}, action: 'check')
      expect(output).to include(@vulnerable ? 'The target appears to be vulnerable.' : 'The target is not exploitable.')
      expect(paths).to eq([])
      rows = forgejo_assert_reports(service: true)
      expect(rows.fetch('services').fetch(0).fetch('info')).to eq('Forgejo ' + @native.fetch('server_version'))
      expect(rows).to eq(first) if first
      first = rows
    end
  end

  it 'uses default file, repository discovery and loot settings twice' do
    2.times do
      output = forgejo_read(default_options: true)
      expect(output).to include('Found public repository: ' + @native.fetch('search_first')) if @vulnerable
    end
  end

  it 'prints exact native rendered text without loot and with AutoCheck disabled twice' do
    2.times { forgejo_read('short', options: { 'REPO' => Acceptance::ForgejoFile::PUBLIC_REPO, 'STORE_LOOT' => false, 'AutoCheck' => false }) }
  end

  it 'reads or refuses the explicit private-repository Unicode context twice' do
    2.times { forgejo_read('unicode', options: { 'REPO' => Acceptance::ForgejoFile::PRIVATE_REPO, 'AutoCheck' => false }) }
  end

  it 'checks invalid credentials and refuses authenticated API reads twice' do
    2.times do
      output, paths = forgejo_call({ 'PASSWORD' => 'module-target-rejected-password' }, action: 'check')
      expect(output).to include(@vulnerable ? 'credentials are invalid' : 'is patched')
      expect(paths).to eq([])
      forgejo_negative({ 'PASSWORD' => 'module-target-rejected-password' }, service: true)
    end
  end

  {
    'missing file' => '/opt/module-target-files/missing-task.txt',
    'directory' => '/opt/module-target-files',
    'unreadable file' => '/etc/shadow'
  }.each do |label, path|
    it "does not claim successful collection of the native-proven #{label}" do
      forgejo_negative({ 'FILEPATH' => path })
    end
  end

  %w[empty whitespace].each do |kind|
    it "does not report or store a file from the native #{kind} rendering" do
      forgejo_negative({ 'FILEPATH' => @native.fetch('files').fetch(kind).fetch('path') })
    end
  end

  it 'rejects an invalid repository option twice without false reporting' do
    2.times { forgejo_negative({ 'REPO' => 'invalid repository' }) }
  end

  it 'rejects the explicitly unsupported quoted file path twice' do
    2.times { forgejo_negative({ 'FILEPATH' => '/tmp/quote"name.txt' }) }
  end

  it 'returns unknown for the native-proven refused port twice without a false service' do
    2.times do
      output, paths = forgejo_call({ 'RPORT' => 1 }, action: 'check')
      expect(output).to include('Cannot reliably check exploitability.')
      expect(paths).to eq([])
      forgejo_assert_reports(service: false)
    end
  end

  if %w[15.0.5 16.0.1].include?(profile_version)
    it 'stores the entire large rendering beyond one receive block' do
      forgejo_read('large', options: { 'REPO' => Acceptance::ForgejoFile::PUBLIC_REPO })
    end

    it 'preserves the rendering of a path containing spaces twice' do
      2.times { forgejo_read('space_name', options: { 'STORE_LOOT' => false }) }
    end

    it 'retains the genuine renderer behavior for a file without a final newline' do
      forgejo_read('no_newline', options: { 'STORE_LOOT' => false })
    end
  end
end
