require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/wps_hide_login/control'

RSpec.describe 'Native WPS Hide Login discovery', acceptance: true, order: :defined do
  include_context 'native WPS Hide Login target'

  if WpsHideLoginProfiles.fetch.fetch(:disclosure)
    it 'reveals the independently configured working login URL twice' do
      2.times do
        output = wps_owner
        urls = output.scan(/^\[\+\] Login page: (\S+)\s*$/).flatten
        expect(urls.length).to eq(1), output
        uri = URI(urls.first)
        endpoint = target_runtime.fetch('module_endpoints').fetch('app')
        expect([uri.scheme, uri.host, uri.port, uri.path]).to eq(['http', endpoint.fetch('host'), endpoint.fetch('port'), @wps_expected_path])
        expect(URI.decode_www_form(uri.query).to_h).to include('reauth' => '1')
        expect(wps_login_form?(wps_request(uri.request_uri))).to be(true)
      end
    end

    it 'does not report a login URL for a missing installation' do
      output = wps_owner('TARGETURI' => '/module-target-missing/')
      expect(output).not_to include('Login page:')
      expect(output).to include('Server not online or not detected as wordpress')
    end

    it 'does not report a login URL on a native closed TCP port' do
      expect(target_exec('app', 'php', '-r', '$s=stream_socket_server("tcp://0.0.0.0:9",$e,$m);if(!$s){exit(1);}fclose($s);')).to eq('')
      output = wps_owner('RPORT' => 9)
      expect(output).not_to include('Login page:')
      expect(output).to include('Server not online or not detected as wordpress')
    end
  else
    it 'does not report a non-login redirect or an unavailable plugin as a login URL on either run' do
      2.times do
        output = wps_owner
        expect(output).not_to include('Login page:')
        expect(output).to match(/not found|not detected|not vulnerable|login page|redirect/i)
      end
    end
  end
end
