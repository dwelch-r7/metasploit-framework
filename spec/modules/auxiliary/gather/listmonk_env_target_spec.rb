require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/listmonk/acceptance'

profile_key = ENV.fetch('LISTMONK_PROFILE', '4.0.0')
profile_data = JSON.parse(File.read(File.expand_path('../../../../test/module_targets/listmonk/profiles.json', __dir__))).fetch(profile_key)

RSpec.describe "Listmonk environment disclosure on #{profile_key}", acceptance: true do
  include_context 'module target'
  include Acceptance::Listmonk

  let_it_be(:listmonk_profile) { profile_data }

  before(:all) { @native = listmonk_native('before') }

  after(:all) do
    if @native
      current = listmonk_native('after')
      expect(current.fetch('status')).to eq('native_passed')
      expect(current.fetch('identity')).to eq(@native.fetch('identity'))
      expect(current.fetch('state')).to eq(@native.fetch('state'))
    end
  end

  it 'checks the actual affected or fixed release twice' do
    2.times do
      output, files = listmonk_call(action: 'check')
      expect(files).to eq([])
      expect(output).to include(profile_key)
      expect(output).to include(listmonk_profile.fetch('vulnerable') ? 'appears to be vulnerable' : 'not exploitable')
    end
  end

  it 'extracts all six default variables or rejects the fixed template twice' do
    2.times { listmonk_extract }
  end

  it 'preserves a fresh marker, HTML characters, Unicode, empty and unset values' do
    listmonk_extract('custom')
  end

  it 'cleans up an explicit campaign name so a second execution succeeds' do
    2.times { listmonk_extract('custom', options: { 'CAMPAIGN_NAME' => 'Module target explicit name' }) }
  end

  it 'works with a campaign manager who has no user or settings administration' do
    listmonk_extract('custom', options: { 'USERNAME' => 'labmanager', 'PASSWORD' => 'module-target-user-password' })
  end

  it 'reports insufficient campaign creation rights without storing false loot' do
    output, files = listmonk_call(options: { 'USERNAME' => 'labreader', 'PASSWORD' => 'module-target-user-password', 'ENVVAR' => Acceptance::Listmonk::CUSTOM })
    expect(output).to include('Failed to create campaign: 403')
    expect(files).to eq([])
  end

  it 'rejects invalid credentials on both public entry points twice' do
    2.times do
      output, files = listmonk_call(action: 'check', options: { 'PASSWORD' => 'module-target-wrong-password' })
      expect(output).to include('Cannot reliably check exploitability.', 'Authentication failed')
      expect(files).to eq([])
      output, files = listmonk_call(options: { 'PASSWORD' => 'module-target-wrong-password' })
      expect(output).to include('Login failed with code 200')
      expect(files).to eq([])
    end
  end

  it 'handles a native-verified refused target port twice' do
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    script = "begin; Socket.tcp(ARGV.fetch(0), 1, connect_timeout: 2) { abort 'Unexpected open port' }; rescue Errno::ECONNREFUSED; puts 'REFUSED'; end"
    command = target_runtime.fetch('console_command')
    user = command[command.index('--user') + 1]
    output, status = Open3.capture2e(*target_runtime.fetch('compose'), 'exec', '-T', '--user', user, 'framework', 'ruby', '-rsocket', '-e', script, host)
    expect(status.success?).to be(true), output
    expect(output.strip).to eq('REFUSED')
    File.write(File.join(target_runtime.fetch('artifacts'), 'refused-port.json'), JSON.generate(user: user, host: host, port: 1, output: output, exitstatus: status.exitstatus))
    2.times do
      output, files = listmonk_call(action: 'check', options: { 'RPORT' => 1 })
      expect(output).to include('Cannot reliably check exploitability.')
      expect(files).to eq([])
    end
  end
end
