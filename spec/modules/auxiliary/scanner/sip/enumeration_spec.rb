require 'spec_helper'
require 'base64'
require 'json'
require 'tmpdir'

RSpec.describe 'SIP enumeration native response contracts' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:modules_path) { ENV.fetch('SIP_UNIT_MODULE_ROOT', File.expand_path('../../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('sip-enumeration-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  let(:captures_path) { ENV.fetch('SIP_UNIT_CAPTURE_ROOT', File.expand_path('../../../../file_fixtures/modules/auxiliary/sip', __dir__)) }
  let(:captures) { JSON.parse(File.read(File.join(captures_path, 'enumeration.json'))).fetch('captures') }

  %w[enumerator enumerator_tcp].each do |reference|
    context "with #{reference}" do
      subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: "scanner/sip/#{reference}") }

      it 'preserves digits when padding is shorter than the extension' do
        expect(mod.padnum(1000, 0)).to eq('1000')
      end

      it 'preserves digits at the exact padding boundary' do
        expect(mod.padnum(1000, 4)).to eq('1000')
      end

      it 'retains requested zero padding for shorter extensions' do
        expect(mod.padnum(1000, 6)).to eq('001000')
      end
    end
  end

  context 'with the TCP response parser' do
    subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/sip/enumerator_tcp') }

    before do
      mod.datastore['RHOST'] = '192.0.2.42'
      mod.datastore['RPORT'] = 5061
      allow(mod).to receive(:print_good)
      allow(mod).to receive(:report_note)
    end

    { '1000' => 'Open', '1001' => 'Auth' }.each do |account, status|
      it "reports the genuine #{account} status with the TCP service context" do
        response = native_response(account)
        user = response[/^To:\s*(.+)\r?$/, 1].strip.split(';').first
        mod.parse_reply(response, 'REGISTER')

        expect(mod).to have_received(:report_note).with(host: '192.0.2.42', port: 5061, proto: 'tcp', sname: 'sip', type: "Found user: #{user} [#{status}]", data: { user: user })
      end
    end

    it 'does not report the genuine absent-account reply' do
      mod.parse_reply(native_response('1002'), 'REGISTER')

      expect(mod).not_to have_received(:report_note)
    end

    it 'does not report a non-SIP status line derived from the native response' do
      mod.parse_reply(native_response('1000').sub('SIP/2.0', 'HTTP/1.1'), 'REGISTER')

      expect(mod).not_to have_received(:report_note)
    end

    it 'does not invent a user when the native To header is removed' do
      mod.parse_reply(native_response('1000').sub(/^To:[^\r\n]*\r\n/, ''), 'REGISTER')

      expect(mod).not_to have_received(:report_note)
    end
  end

  def native_response(account)
    row = captures.find { |capture| capture.fetch('operation').fetch('account') == account }
    Base64.strict_decode64(row.fetch('result').fetch('responses').first.fetch('raw_base64'))
  end
end
