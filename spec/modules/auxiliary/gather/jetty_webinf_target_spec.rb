require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/jetty_webinf/acceptance'

profile_key = ENV.fetch('JETTY_PROFILE', '9.4.38')
profile_data = JSON.parse(File.read(File.expand_path('../../../../test/module_targets/jetty_webinf/profiles.json', __dir__))).fetch(profile_key)

RSpec.describe "Jetty WEB-INF file reads on #{profile_key}", acceptance: true do
  include_context 'module target'
  include Acceptance::JettyWebinf

  let_it_be(:jetty_profile) { profile_data }

  before(:all) { @native = jetty_native('before') }

  after(:all) do
    if @native
      current = jetty_native('after')
      expect(current.fetch('identity')).to eq(@native.fetch('identity'))
      expect(current.fetch('files')).to eq(@native.fetch('files'))
    end
  end

  %w[CVE-2021-28164 CVE-2021-34429].each do |cve|
    it "checks the real #{cve} boundary twice" do
      2.times do
        output, files = jetty_call(cve, action: 'check')
        expect(files).to eq([])
        if jetty_profile.fetch('vulnerable').fetch(cve)
          expect(output).to match(/target appears to be vulnerable|service is running, but could not be validated/i)
          expect(output).to include(jetty_profile.fetch('server_version'))
        else
          expect(output).to include('The target is not exploitable.', "Jetty #{jetty_profile.fetch('server_version')} is not vulnerable")
        end
      end
    end

    it "reads the default descriptor or refuses #{cve} twice without false loot" do
      2.times { jetty_loot(cve, default: true) }
    end
  end

  if profile_data.fetch('vulnerable').fetch('CVE-2021-34429')
    %w[short.txt empty.txt unicode.txt binary.dat large.txt classes/settings.properties].each do |name|
      it "stores exact native #{name} bytes" do
        jetty_loot('CVE-2021-34429', name)
      end
    end
  end

  it 'does not store missing-resource or rejected-path errors with AutoCheck disabled' do
    %w[CVE-2021-28164 CVE-2021-34429].each do |cve|
      output, files = jetty_call(cve, file: 'module-target-missing.txt', options: { 'AutoCheck' => false })
      expect(output).to include('unexpected HTTP response code:')
      expect(output).not_to include('File stored to')
      expect(files).to eq([])
    end
  end

  it 'handles a native-verified refused connection twice without discovering Jetty' do
    2.times do
      output, files = jetty_call('CVE-2021-34429', action: 'check', options: { 'RPORT' => 1 })
      expect(output).to include('Could not connect to web service - no response')
      expect(output).not_to include('target appears to be vulnerable', 'File stored to')
      expect(files).to eq([])
    end
  end
end
