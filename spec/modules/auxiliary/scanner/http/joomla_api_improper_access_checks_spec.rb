require 'rspec'
require 'json'

RSpec.describe 'Joomla API access check boundaries' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/joomla_api_improper_access_checks') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/joomla_api_improper_access_checks/discovery.json'))) }
  let(:host) { '192.0.2.53' }

  before do
    mod.datastore['RHOST'] = host
    mod.datastore['RHOSTS'] = host
    allow(mod).to receive(:joomla_and_online?).and_return(true)
    allow(mod).to receive(:joomla_version).and_return('4.2.7')
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:elog)
  end

  { 'vulnerable' => Msf::Exploit::CheckCode::Appears, 'fixed' => Msf::Exploit::CheckCode::Safe, 'hidden' => Msf::Exploit::CheckCode::Unknown }.each do |profile, expected|
    it "returns the correct check for the native #{profile} metadata and access policy" do
      native = captures.fetch('profiles').fetch(profile)
      version = native.fetch('manifest').fetch('code') == 200 ? native.fetch('version') : nil
      expect(native.fetch('public_users_status')).to eq(profile == 'fixed' ? 401 : 200)
      allow(mod).to receive(:joomla_version).and_return(version)

      result = mod.check_host(host)

      expect(result).to eq(expected)
      expect(result.reason).not_to be_empty
    end
  end

  {
    '3.10.12' => Msf::Exploit::CheckCode::Safe,
    '4.0.0' => Msf::Exploit::CheckCode::Appears,
    '4.3.0' => Msf::Exploit::CheckCode::Safe,
    '5.0.0' => Msf::Exploit::CheckCode::Safe
  }.each do |version, expected|
    it "handles the derived release boundary #{version}" do
      allow(mod).to receive(:joomla_version).and_return(version)

      expect(mod.check_host(host)).to eq(expected)
    end
  end

  ['', '  '].each do |version|
    it "keeps derived blank version metadata #{version.inspect} unknown" do
      allow(mod).to receive(:joomla_version).and_return(version)

      expect(mod.check_host(host)).to eq(Msf::Exploit::CheckCode::Unknown)
    end
  end

  it 'returns an unknown check instead of raising for derived malformed version metadata' do
    allow(mod).to receive(:joomla_version).and_return('not-a-version')

    expect(mod.check_host(host)).to eq(Msf::Exploit::CheckCode::Unknown)
  end

  it 'keeps unrelated native HTTP unknown without asking it for a Joomla version' do
    expect(captures.fetch('unrelated').fetch('body')).to include('module-target-http-marker')
    allow(mod).to receive(:joomla_and_online?).and_return(false)

    expect(mod.check_host(host)).to eq(Msf::Exploit::CheckCode::Unknown)
    expect(mod).not_to have_received(:joomla_version)
  end
end
