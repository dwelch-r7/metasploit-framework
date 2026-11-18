require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'SuiteCRM export passive version checks' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('SUITECRM_CHECK_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/suite_crm_export_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:fragment) { File.binread(File.expand_path('../../../file_fixtures/modules/auxiliary/gather/suite_crm_export_sqli/about_header.html', __dir__)) }
  let(:authenticated) { true }
  let(:page) { reply(200, fragment) }

  before do
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:authenticate).and_return(authenticated)
    allow(mod).to receive(:send_request_cgi).and_return(page)
    %i[print_status elog].each { |method| allow(mod).to receive(method) }
  end

  def reply(code, body)
    Rex::Proto::Http::Response.new(code).tap { |response| response.body = body }
  end

  def checked
    result = mod.check
    [result.code, result.reason]
  end

  # Only the 7.12.5 header is a native capture. Version, locale and malformed
  # variants exercise parser boundaries; HTTP/authentication remain doubles.
  it 'returns reason-bearing Appears for the captured vulnerable release' do
    expect(checked).to eq(['appears', 'SuiteCRM version 7.12.5 appears to be vulnerable'])
  end

  {
    '7.10.36' => 'appears',
    '7.11.23' => 'appears',
    '7.12.4' => 'appears',
    '7.12.6' => 'safe',
    '7.14.1' => 'safe'
  }.each do |version, expected|
    context "synthetic version #{version}" do
      let(:page) { reply(200, fragment.sub('7.12.5', version)) }

      it 'retains the export fix boundary rather than another SQL injection identifier' do
        reason = expected == 'safe' ? "SuiteCRM version #{version} is not vulnerable" : "SuiteCRM version #{version} appears to be vulnerable"
        expect(checked).to eq([expected, reason])
      end
    end
  end

  context 'authentication is denied' do
    let(:authenticated) { false }

    it 'does not claim the target is safe without version evidence' do
      expect(checked).to eq(['unknown', 'Unable to authenticate to SuiteCRM'])
    end

    it 'does not request the version page' do
      mod.check
      expect(mod).not_to have_received(:send_request_cgi)
    end
  end

  context 'the About page does not respond' do
    let(:page) { nil }

    it 'returns reason-bearing Unknown' do
      expect(checked).to eq(['unknown', 'The SuiteCRM version page did not respond'])
    end
  end

  [302, 404, 500].each do |status|
    context "the About page returns HTTP #{status}" do
      let(:page) { reply(status, fragment) }

      it 'rejects even a vulnerable version marker in an unsuccessful response' do
        expect(checked).to eq(['unknown', "The SuiteCRM version page returned HTTP #{status}"])
      end
    end
  end

  context 'the About page has a nil body' do
    let(:page) { reply(200, nil) }

    it 'returns Unknown without dereferencing the missing document' do
      expect(checked).to eq(['unknown', 'The SuiteCRM version page has no response body'])
    end
  end

  context 'the About page is empty' do
    let(:page) { reply(200, '') }

    it 'returns Unknown without dereferencing a failed version match' do
      expect(checked).to eq(['unknown', 'Could not determine the SuiteCRM version from the About page'])
    end
  end

  context 'the SuiteCRM version element is absent' do
    let(:page) { reply(200, fragment.sub(%r{<b>.*?</b>}m, '')) }

    it 'does not confuse the embedded Sugar version for the SuiteCRM release' do
      expect(checked).to eq(['unknown', 'Could not determine the SuiteCRM version from the About page'])
    end
  end

  context 'an unrelated page mentions a vulnerable version' do
    let(:page) { reply(200, '<html><p>Unrelated application Version 7.12.5</p></html>') }

    it 'does not accept a marker outside the actual SuiteCRM version element' do
      expect(checked).to eq(['unknown', 'Could not determine the SuiteCRM version from the About page'])
    end
  end

  context 'the SuiteCRM version element is malformed' do
    let(:page) { reply(200, fragment.sub('7.12.5', 'not-a-version')) }

    it 'returns Unknown without raising from a failed match' do
      expect(checked).to eq(['unknown', 'Could not determine the SuiteCRM version from the About page'])
    end
  end

  context 'the version label is localized' do
    let(:page) { reply(200, fragment.sub('Version 7.12.5', 'Versión 7.12.5')) }

    it 'uses the actual version element without assuming an English label' do
      expect(checked).to eq(['appears', 'SuiteCRM version 7.12.5 appears to be vulnerable'])
    end
  end

  context 'a custom version label follows the native version' do
    let(:page) { reply(200, fragment.sub('7.12.5', '7.12.5&nbsp;&nbsp;Owned custom build')) }

    it 'retains the genuine SuiteCRM release number' do
      expect(checked).to eq(['appears', 'SuiteCRM version 7.12.5 appears to be vulnerable'])
    end
  end

  context 'authentication raises an expected connection error' do
    let(:connection_error) { Rex::ConnectionRefused.new('192.0.2.10') }

    before { allow(mod).to receive(:authenticate).and_raise(connection_error) }

    it 'returns reason-bearing Unknown instead of leaking the expected exception' do
      expect(checked).to eq(['unknown', "Could not complete the SuiteCRM check: #{connection_error.message}"])
    end
  end

  context 'the version request times out' do
    let(:connection_error) { Rex::ConnectionTimeout.new('192.0.2.10') }

    before { allow(mod).to receive(:send_request_cgi).and_raise(connection_error) }

    it 'returns reason-bearing Unknown instead of leaking the expected exception' do
      expect(checked).to eq(['unknown', "Could not complete the SuiteCRM check: #{connection_error.message}"])
    end
  end
end
