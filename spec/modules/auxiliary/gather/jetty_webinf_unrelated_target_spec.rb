require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/jetty_webinf/acceptance'

RSpec.describe 'Jetty module against genuine Apache HTTPD', acceptance: true do
  include_context 'module target'
  include Acceptance::JettyWebinf

  before(:all) { @native = jetty_native('before', program: 'native_unrelated.py') }

  after(:all) do
    if @native
      current = jetty_native('after', program: 'native_unrelated.py')
      expect(current.fetch('identity')).to eq(@native.fetch('identity'))
      expect(current.fetch('files')).to eq(@native.fetch('files'))
    end
  end

  it 'does not classify Apache as either Jetty vulnerability' do
    %w[CVE-2021-28164 CVE-2021-34429].each do |cve|
      2.times do
        output, files = jetty_call(cve, action: 'check')
        expect(output).to include('The target is not exploitable.', 'Unable to detect Jetty version from server header: Apache/')
        expect(files).to eq([])
      end
    end
  end

  it 'refuses both CVE choices without creating false file loot' do
    %w[CVE-2021-28164 CVE-2021-34429].each do |cve|
      2.times do
        output, files = jetty_call(cve)
        expect(output).to include('not-vulnerable', 'Unable to detect Jetty version from server header: Apache/')
        expect(output).not_to include('File stored to')
        expect(files).to eq([])
      end
    end
  end
end
