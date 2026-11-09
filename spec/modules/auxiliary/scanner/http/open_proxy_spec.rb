require 'rspec'
require 'json'

RSpec.describe 'HTTP open proxy request authorities' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/open_proxy') }

  let(:host) { '192.0.2.53' }
  let(:requests) { [] }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/open_proxy/native.json'))) }

  before do
    mod.datastore['RHOSTS'] = host
    mod.datastore['RPORT'] = 8080
    mod.datastore['MULTIPORTS'] = false
    mod.datastore['VERIFYCONNECT'] = true
    allow(mod).to receive(:verify_target) do |target_host, port, method, uri, _headers|
      requests << { host: target_host, port: port, method: method, uri: uri }
    end
  end

  {
    'destination' => 'destination:443',
    'https://destination:443/' => 'destination:443',
    'https://destination:8443/' => 'destination:8443'
  }.each do |input, authority|
    it "uses the native working CONNECT authority for #{input}" do
      port = authority.split(':').last.to_i
      native = captures.fetch('native_operations').find { |entry| entry['service'] == 'open' && entry['tls'] && entry['destination_port'] == port }
      expect(native.fetch('code')).to eq('200')
      expect(native.fetch('certificate_subject')).to eq('/CN=destination')
      mod.datastore['CHECKURL'] = input

      mod.run_host(host)

      expect(requests).to eq([{ host: host, port: 8080, method: 'CONNECT', uri: authority }])
    end
  end

  {
    'destination:8443' => 'destination:8443',
    'HTTPS://destination:8443/path?query=value#fragment' => 'destination:8443',
    'http://destination/' => 'destination:443',
    'http://destination:8080/' => 'destination:8080',
    'destination:1' => 'destination:1',
    'destination:65535' => 'destination:65535',
    'https://192.0.2.17:8443/' => '192.0.2.17:8443',
    'https://[2001:db8::17]/' => '[2001:db8::17]:443',
    '[2001:db8::17]:8443' => '[2001:db8::17]:8443'
  }.each do |input, authority|
    it "preserves the derived valid authority #{input}" do
      mod.datastore['CHECKURL'] = input

      mod.run_host(host)

      expect(requests.last.fetch(:uri)).to eq(authority)
    end
  end

  ['destination', 'http://destination:8080/'].each do |input|
    it "retains the native GET target for #{input}" do
      mod.datastore['CHECKURL'] = input
      mod.datastore['VERIFYCONNECT'] = false

      mod.run_host(host)

      expect(requests.last).to include(method: 'GET', uri: input.start_with?('http://') ? input : "http://#{input}")
    end
  end

  [
    '',
    'https:///',
    'https://destination:not-a-port/',
    'https://destination:0/',
    'https://destination:65536/',
    'ftp://destination/',
    'https://user:password@destination/',
    'https://destination name/',
    'https://[2001:db8::17'
  ].each do |input|
    it "refuses derived invalid CONNECT target #{input.inspect} before scanning" do
      mod.datastore['CHECKURL'] = input

      expect { mod.run_host(host) }.to raise_error(Msf::Auxiliary::Failed, /CHECKURL/)
      expect(requests).to be_empty
    end
  end
end
