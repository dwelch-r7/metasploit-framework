require 'rspec'

RSpec.describe 'Jenkins system information parsing' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/jenkins_enum') }

  let(:fixture_directory) { File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/jenkins_enum') }
  let(:html) { File.read(File.join(fixture_directory, 'system_info_2_442.html')) }
  let(:plain_html) { File.read(File.join(fixture_directory, 'system_info_plain.html')) }
  let(:notes) { [] }
  let(:service) { { host: '192.0.2.1', port: 8080, proto: 'tcp' } }
  let(:properties) do
    {
      'os.name' => 'Linux',
      'os.version' => '7.0.14-linuxkit',
      'os.arch' => 'amd64',
      'user.name' => 'jenkins',
      'user.home' => '/var/jenkins_home',
      'user.language' => 'en',
      'user.timezone' => 'Etc/UTC'
    }
  end

  before do
    mod.datastore['RPORT'] = 8080
    allow(mod).to receive(:rhost).and_return('192.0.2.1')
    allow(mod).to receive(:full_uri).and_return('http://192.0.2.1:8080/jenkins/')
    allow(mod).to receive(:report_note) { |note| notes << note }
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_line)
  end

  describe '#parse_system_info' do
    it 'reports captured modern property values without the hidden-value control text' do
      mod.parse_system_info(html)

      expect(notes).to include(service.merge(ntype: 'jenkins.info', data: properties))
    end

    it 'keeps the existing fingerprint field names and service context' do
      mod.parse_system_info(html)

      expect(notes).to include(service.merge(ntype: 'fingerprint.match', data: {
        'os.product' => 'Linux', 'os.version' => '7.0.14-linuxkit', 'os.arch' => 'amd64', 'os.language' => 'en'
      }))
    end

    it 'prints the actual home path despite word-break elements and nested controls' do
      mod.parse_system_info(html)

      expect(mod).to have_received(:vprint_line).with('   Home Directory: /var/jenkins_home')
    end

    it 'continues to accept plain property cells through the existing String API' do
      mod.parse_system_info(plain_html)

      expect(notes).to include(service.merge(ntype: 'jenkins.info', data: properties))
    end

    it 'does not mutate the supplied page' do
      original = html.dup
      mod.parse_system_info(html)

      expect(html).to eq(original)
    end

    it 'accepts a frozen page body' do
      expect { mod.parse_system_info(html.freeze) }.not_to raise_error
    end

    it 'keeps empty notes rather than inventing fields for an empty page' do
      mod.parse_system_info('')

      expect(notes).to eq([service.merge(ntype: 'fingerprint.match', data: {}), service.merge(ntype: 'jenkins.info', data: {})])
    end

    it 'does not take a missing value from the next table row' do
      mod.parse_system_info('<table><tr><td>os.name</td></tr><tr><td>user.home</td><td>/var/jenkins_home</td></tr></table>')

      expect(notes).to include(service.merge(ntype: 'jenkins.info', data: { 'user.home' => '/var/jenkins_home' }))
    end

    it 'does not recognize a property name appearing in the value column' do
      mod.parse_system_info('<table><tr><td>unrelated</td><td>os.name</td></tr><tr><td>another</td><td>Linux</td></tr></table>')

      expect(notes).to include(service.merge(ntype: 'jenkins.info', data: {}))
    end

    it 'does not report the reveal-control label when the actual value is empty' do
      document = Nokogiri::HTML(html)
      document.css('tr').each { |row| row.remove unless row.css('> td').first&.text&.strip == 'os.name' }
      document.at_css('.app-hidden-info-hide').content = ''
      mod.parse_system_info(document.to_html)

      expect(notes).to include(service.merge(ntype: 'jenkins.info', data: {}))
    end
  end

  describe '#check_app' do
    let(:response) { Rex::Proto::Http::Response.new(200) }

    before do
      response.body = html
      allow(mod).to receive(:send_request_cgi).and_return(response)
    end

    it 'uses the HTTP response HTML parser for a successful systemInfo page' do
      expect(response).to receive(:get_html_document).and_call_original

      mod.check_app('systemInfo')
    end

    it 'does not parse a protected systemInfo response' do
      response.code = 403
      expect(mod).not_to receive(:parse_system_info)

      mod.check_app('systemInfo')
    end
  end
end
