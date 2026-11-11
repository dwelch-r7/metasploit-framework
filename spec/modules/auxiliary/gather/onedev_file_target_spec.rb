require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/onedev_file/acceptance'

profile_version = ENV.fetch('ONEDEV_VERSION', '11.0.8')

RSpec.describe 'Genuine OneDev arbitrary file reads', acceptance: true do
  include_context 'module target'
  include Acceptance::OneDevFile

  before(:all) do
    @vulnerable = profile_version == '11.0.8'
    @native = onedev_native('before')
  end

  after(:all) do
    if @native
      onedev_native('mode-final-off')
      current = onedev_native('after')
      %w[files identity project security].each do |key|
        expect(current.fetch(key)).to eq(@native.fetch(key))
      end
    end
  end

  before do |example|
    @anonymous = example.metadata.fetch(:anonymous, false)
    index = Dir[File.join(target_runtime.fetch('artifacts'), 'native-mode-*.json')].size + 1
    onedev_native("mode-#{index}-#{@anonymous ? 'on' : 'off'}")
  end

  [false, true].each do |anonymous|
    context "with anonymous access #{anonymous ? 'enabled' : 'disabled'}", anonymous: anonymous do
      it 'checks the actual affected or fixed service twice without loot' do
        2.times do
          output, paths = onedev_call({}, action: 'check')
          expect(output).to include(@vulnerable ? 'is vulnerable.' : 'is not vulnerable.')
          expect(paths).to eq([])
        end
      end

      it 'reads or refuses the real default file twice through AutoCheck' do
        2.times { onedev_read('default') }
      end

      it 'stores exact default bytes or refuses without false loot twice' do
        2.times { onedev_read('default', loot: true) }
      end

      it 'handles AutoCheck-disabled reads or refusals twice' do
        2.times { onedev_read('short', loot: true, options: { 'AutoCheck' => false }) }
      end

      it 'supports the documented wordlist path with no supplied project name twice' do
        2.times { onedev_read('short', options: { 'PROJECT_NAMES_FILE' => Acceptance::OneDevFile::WORDLIST }, omit_project: true) }
      end

      if profile_version == '11.0.8'
        it 'initializes wordlist lookup without AutoCheck twice' do
          2.times { onedev_read('short', options: { 'PROJECT_NAMES_FILE' => Acceptance::OneDevFile::WORDLIST, 'AutoCheck' => false }, omit_project: true) }
        end
      end
    end
  end

  if profile_version == '11.0.8'
    %w[short empty unicode space large error_phrase].each do |kind|
      it "prints the native #{kind} file exactly", anonymous: false do
        onedev_read(kind)
      end
    end

    it 'stores the explicitly generated binary bytes without text conversion' do
      onedev_read('binary', loot: true)
    end

    it 'reports a missing target file without false output or loot' do
      output, paths = onedev_call({ 'TARGETFILE' => '/opt/module-target-files/missing-task.txt', 'STORE_LOOT' => true })
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
      expect(paths).to eq([])
    end

    it 'does not report a directory redirect as a successful file read' do
      output, paths = onedev_call({ 'TARGETFILE' => '/opt/module-target-files', 'STORE_LOOT' => true })
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
      expect(paths).to eq([])
    end

    it 'reports an invalid project as unknown rather than a patched product' do
      output, paths = onedev_call({ 'PROJECT_NAME' => 'module-target-missing' }, action: 'check')
      expect(output).to include('Cannot reliably check exploitability.')
      expect(paths).to eq([])
    end

    it 'rejects an invalid project without producing file loot' do
      output, paths = onedev_call({ 'PROJECT_NAME' => 'module-target-missing', 'STORE_LOOT' => true })
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
      expect(paths).to eq([])
    end

    it 'rejects a missing wordlist through public option validation' do
      output, paths = onedev_call({ 'PROJECT_NAMES_FILE' => '/opt/module-target-wordlist-missing', 'AutoCheck' => false }, omit_project: true, expected_invalid_option: 'PROJECT_NAMES_FILE')
      expect(output).to include('[-]')
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.', 'Errno::ENOENT')
      expect(paths).to eq([])
    end

    it 'handles a native-proven wordlist with no matching project' do
      file = '/usr/src/metasploit-framework/test/module_targets/onedev_file/wordlists/missing-projects.txt'
      output, paths = onedev_call({ 'PROJECT_NAMES_FILE' => file, 'AutoCheck' => false }, omit_project: true)
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
      expect(paths).to eq([])
    end
  end

  it 'handles a native-proven refused target port twice' do
    2.times do
      output, paths = onedev_call({ 'RPORT' => 1 }, action: 'check')
      expect(output).to include('Cannot reliably check exploitability.')
      expect(paths).to eq([])
    end
  end
end
