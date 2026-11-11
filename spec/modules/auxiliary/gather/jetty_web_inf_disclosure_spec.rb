require 'rspec'
require 'json'
require 'tmpdir'

RSpec.describe 'Jetty WEB-INF disclosure check boundaries' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/jetty_web_inf_disclosure') }

  let(:modules_path) { ENV.fetch('JETTY_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('jetty-check-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures) do
    JSON.parse(File.read(File.expand_path('../../../file_fixtures/modules/auxiliary/jetty_webinf/server_headers.json', __dir__))).fetch('captures')
  end
  let(:cve) { 'CVE-2021-34429' }
  let(:server_header) { 'Jetty(10.0.5)' }
  let(:response) do
    result = Rex::Proto::Http::Response.new(200)
    result.headers['Server'] = server_header unless server_header.nil?
    result
  end

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['CVE'] = cve
    allow(mod).to receive(:send_request_cgi).with('uri' => '/').and_return(response)
    allow(mod).to receive(:print_good)
  end

  # Real native root-response headers. Expected CVE ranges come from Jetty's
  # GHSA-v7ff-8wcx-gmc5 and GHSA-vjv5-gp2w-65vm advisories.
  [
    ['9438', true, true],
    ['9443', false, false],
    ['1005', false, true],
    ['1006', false, false],
    ['1105', false, true],
    ['1106', false, false]
  ].each do |profile, affected_28164, affected_34429|
    { 'CVE-2021-28164' => affected_28164, 'CVE-2021-34429' => affected_34429 }.each do |selected_cve, affected|
      context "with native #{profile} header and #{selected_cve}" do
        let(:cve) { selected_cve }
        let(:server_header) { captures.fetch(profile).fetch('server') }

        it 'classifies the selected CVE and preserves the advertised version' do
          version = server_header[/Jetty\(([^)]+)\)/, 1]
          expect_check(affected, version)
        end
      end
    end
  end

  # Explicit vendor release-boundary variants, not additional runtime captures.
  {
    'CVE-2021-28164' => [
      ['9.4.36', false], ['9.4.37', true], ['9.4.37.v20210219', true],
      ['9.4.38', true], ['9.4.39', false], ['9.4.39.v20210325', false],
      ['9.4.42', false], ['10.0.1', false], ['11.0.1', false]
    ],
    'CVE-2021-34429' => [
      ['9.4.36', false], ['9.4.37', true], ['9.4.37.v20210219', true],
      ['9.4.39.v20210325', true], ['9.4.42.v20210604', true],
      ['9.4.43', false], ['9.4.44', false],
      ['10.0.0', false], ['10.0.1', true], ['10.0.7', false],
      ['11.0.0', false], ['11.0.1', true], ['11.0.7', false], ['12.0.1', false]
    ]
  }.each do |selected_cve, releases|
    releases.each do |version, affected|
      context "with vendor boundary #{version} and #{selected_cve}" do
        let(:cve) { selected_cve }
        let(:server_header) { "Jetty(#{version})" }

        it 'uses inclusive affected starts and exclusive fixed releases' do
          expect_check(affected, version)
        end
      end
    end
  end

  context 'with the native unrelated Apache header' do
    let(:server_header) { captures.fetch('unrelated').fetch('server') }

    it 'does not identify Jetty' do
      expect(mod.check.reason).to include('Unable to detect Jetty version')
    end
  end

  context 'with a synthetic unrelated product containing Jetty in its name' do
    let(:server_header) { 'NotJetty(10.0.5)' }

    it 'does not classify the other product as an affected Jetty release' do
      result = mod.check
      expect([result.code, result.reason]).to eq(['safe', "192.0.2.1:8080 - Unable to detect Jetty version from server header: #{server_header}"])
    end
  end

  context 'without a response' do
    let(:response) { nil }

    it 'retains the reason-bearing unknown result' do
      result = mod.check
      expect([result.code, result.reason]).to eq(['unknown', '192.0.2.1:8080 - Could not connect to web service - no response'])
    end
  end

  context 'with an unexpected HTTP status' do
    before { response.code = 404 }

    it 'retains the reason-bearing safe result' do
      result = mod.check
      expect([result.code, result.reason]).to eq(['safe', '192.0.2.1:8080 - Check URI Path, unexpected HTTP response code: 404'])
    end
  end

  context 'without a Server header' do
    let(:server_header) { nil }

    it 'retains the reason-bearing safe result' do
      result = mod.check
      expect([result.code, result.reason]).to eq(['safe', '192.0.2.1:8080 - No Server header found'])
    end
  end

  ['Jetty()', 'Jetty(not-a-version)', 'Jetty(10.0.5/invalid)', 'Jetty(10.0.5', 'Jetty(10.0.5-SNAPSHOT)', 'Jetty(10.0.5.custom)'].each do |header|
    context "with synthetic malformed or unsupported Jetty header #{header}" do
      let(:server_header) { header }

      it 'does not conclude an unparseable Jetty release is safe' do
        result = mod.check
        expect([result.code, result.reason]).to eq(['unknown', "192.0.2.1:8080 - Unable to parse Jetty version from server header: #{header}"])
      end
    end
  end

  def expect_check(affected, version)
    result = mod.check
    code = affected ? 'appears' : 'safe'
    reason = affected ? "Jetty #{version} vulnerable to #{cve}" : "Jetty #{version} is not vulnerable"
    expect([result.code, result.reason]).to eq([code, reason])
  end
end
