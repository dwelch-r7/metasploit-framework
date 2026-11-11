require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/selenium_file/acceptance'

profile_key = ENV.fetch('SELENIUM_PROFILE', 'firefox3')
profile_data = JSON.parse(File.read(File.expand_path('../../../../test/module_targets/selenium_file/profiles.json', __dir__))).fetch(profile_key)

RSpec.describe "Selenium file reads with #{profile_key}", acceptance: true do
  include_context 'module target'
  include Acceptance::SeleniumFile

  let_it_be(:selenium_profile) { profile_data }

  before(:all) { @native = selenium_native('before') }

  after(:all) do
    if @native
      current = selenium_native('after')
      expect(current.fetch('status')).to eq('native_passed')
      expect(current.fetch('identity')).to eq(@native.fetch('identity'))
      expect(current.fetch('browser_version')).to eq(@native.fetch('browser_version'))
      current.fetch('files').each do |kind, file|
        expect(file.values_at('path', 'base64', 'sha256', 'text')).to eq(@native.fetch('files').fetch(kind).values_at('path', 'base64', 'sha256', 'text'))
      end
    end
  end

  it 'checks the actual ready Grid twice without opening a browser' do
    2.times do
      output = selenium_call(action: 'check')
      reason = selenium_profile.fetch('version').start_with?('3.') ? "Version #{selenium_profile.fetch('version')} detected" : 'Selenium Grid version 4.x detected and ready.'
      expect(output).to include(reason)
    end
  end

  it 'reads the default system file and releases the browser twice' do
    2.times { selenium_read('default', default: true) }
  end

  %w[short empty unicode large nested space].each do |kind|
    it "reads the native #{kind} text file exactly" do
      selenium_read(kind)
    end
  end

  it 'reads a real target-loopback HTTP text response through the browser' do
    output = selenium_call(options: { 'SCHEME' => 'http', 'FILEPATH' => '127.0.0.1:8123/short.txt' })
    expect(output).to include('[+] 127.0.0.1:8123/short.txt')
    expect(output.b).to include(@native.fetch('http_document').fetch('text').b)
    expect(output).to include('Deleted session (')
  end

  it 'initializes cleanup correctly with AutoCheck disabled on repeated runs' do
    2.times { selenium_read('hostname', options: { 'AutoCheck' => false }) }
  end

  it 'reports a native-proven missing file without claiming a successful read' do
    path = '/opt/module-target-files/module-target-missing.txt'
    output = selenium_call(options: { 'FILEPATH' => path })
    expect(output).to include('[-]')
    expect(output).not_to include("[+] #{path}")
  end

  it 'reports a native-proven permission denial without claiming a successful read' do
    output = selenium_call(options: { 'FILEPATH' => '/etc/shadow' })
    expect(output).to include('[-]')
    expect(output).not_to include('[+] /etc/shadow')
  end

  it 'handles the same-namespace native-verified refused port twice' do
    2.times do
      output = selenium_call(action: 'check', options: { 'RPORT' => 1 })
      expect(output).to include('Cannot reliably check exploitability.')
      expect(output).not_to include('Started session (')
    end
  end
end
