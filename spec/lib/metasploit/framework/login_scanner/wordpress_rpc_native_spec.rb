require 'spec_helper'
require 'metasploit/framework/login_scanner/wordpress_rpc'

RSpec.describe Metasploit::Framework::LoginScanner::WordpressRPC do
  subject(:scanner) { described_class.new(host: '192.0.2.53', port: 80, uri: '/xmlrpc.php') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'lib/metasploit/framework/login_scanner/wordpress_rpc/responses.json'))).fetch('responses') }
  let(:credential) { Metasploit::Framework::Credential.new(public: 'module_admin', private: 'module-target-password') }

  describe '#check_setup' do
    before { allow(scanner).to receive(:report_service) }

    it 'recognizes the actual POST-only HTTP 405 endpoint' do
      allow(scanner).to receive(:send_request).and_return(response('availability'))

      expect(scanner.check_setup).to be(false)
    end

    it 'preserves compatibility with an HTTP 200 POST-only identity' do
      allow(scanner).to receive(:send_request).and_return(response('availability', code: 200))

      expect(scanner.check_setup).to be(false)
    end

    it 'does not accept the native Apache endpoint refusal' do
      allow(scanner).to receive(:send_request).and_return(response('blocked'))

      expect(scanner.check_setup).to include('Unable to locate')
    end

    it 'does not accept the actual unrelated Apache page' do
      allow(scanner).to receive(:send_request).and_return(response('unrelated'))

      expect(scanner.check_setup).to include('Unable to locate')
    end

    it 'does not accept an identity string returned with an unexpected status' do
      allow(scanner).to receive(:send_request).and_return(response('availability', code: 403))

      expect(scanner.check_setup).to include('Unable to locate')
    end

    it 'reports an absent HTTP response' do
      allow(scanner).to receive(:send_request).and_return(nil)

      expect(scanner.check_setup).to include('Unable to connect')
    end
  end

  describe '#attempt_login' do
    %w[admin subscriber special].each do |label|
      it "recognizes the actual #{label} authenticated response" do
        allow(scanner).to receive(:send_request).and_return(response(label))

        expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end
    end

    %w[wrong missing].each do |label|
      it "rejects the actual #{label} credentials response" do
        allow(scanner).to receive(:send_request).and_return(response(label))

        expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::INCORRECT)
      end
    end

    it 'preserves the credential and genuine response as proof' do
      captured = response('admin')
      allow(scanner).to receive(:send_request).and_return(captured)

      result = scanner.attempt_login(credential)

      expect([result.credential, result.proof]).to eq([credential, captured])
    end

    it 'returns an unable-to-connect result when the HTTP operation returns nil' do
      allow(scanner).to receive(:send_request).and_return(nil)

      expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    end

    it 'does not authenticate a non-200 response containing a user result' do
      allow(scanner).to receive(:send_request).and_return(response('admin', code: 403))

      expect(scanner.attempt_login(credential).status).not_to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'does not mistake a user_id string embedded in unrelated HTML for an authenticated result' do
      unrelated = response('unrelated')
      unrelated.body += '<name>user_id</name>'
      allow(scanner).to receive(:send_request).and_return(unrelated)

      expect(scanner.attempt_login(credential).status).not_to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'recognizes equivalent XML whitespace in the native permission fault' do
      captured = response('subscriber')
      captured.body = captured.body.gsub('<value><int>', "<value>\n<int>")
      allow(scanner).to receive(:send_request).and_return(captured)

      expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    it 'preserves an unavailable-method result without treating it as a bad password' do
      captured = response('subscriber')
      captured.body = captured.body.sub('<int>401</int>', '<int>-32601</int>')
      allow(scanner).to receive(:send_request).and_return(captured)

      expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::UNABLE_TO_CONNECT)
    end

    it 'does not authenticate a truncated native result' do
      captured = response('admin')
      captured.body = captured.body.delete_suffix("</methodResponse>\n")
      allow(scanner).to receive(:send_request).and_return(captured)

      expect(scanner.attempt_login(credential).status).not_to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end

    { 'empty' => '', 'non-numeric' => 'module_admin', 'zero' => '0', 'negative' => '-1' }.each do |label, identifier|
      it "does not authenticate a derived user list containing only #{label} identifiers" do
        captured = response('admin')
        document = captured.get_xml_document
        document.xpath('//member[name="user_id"]/value/string').each { |node| node.content = identifier }
        captured.body = document.to_xml
        allow(scanner).to receive(:send_request).and_return(captured)

        expect(scanner.attempt_login(credential).status).not_to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end
    end

    %w[int i4].each do |type|
      it "preserves valid #{type}-typed user identifiers as well as native string identifiers" do
        captured = response('admin')
        document = captured.get_xml_document
        document.xpath('//member[name="user_id"]/value/string').each { |node| node.name = type }
        captured.body = document.to_xml
        allow(scanner).to receive(:send_request).and_return(captured)

        expect(scanner.attempt_login(credential).status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
      end
    end

    it 'does not authenticate a user list with boolean identifiers instead of numeric strings or integers' do
      captured = response('admin')
      document = captured.get_xml_document
      document.xpath('//member[name="user_id"]/value/string').each { |node| node.name = 'boolean' }
      captured.body = document.to_xml
      allow(scanner).to receive(:send_request).and_return(captured)

      expect(scanner.attempt_login(credential).status).not_to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
    end
  end

  describe '#generate_xml_request' do
    it 'retains the exact native XML-RPC method and blog argument' do
      document = Nokogiri::XML(scanner.generate_xml_request('module_admin', 'module-target-password'), &:strict)

      expect([document.at_xpath('/methodCall/methodName').text, request_values(document).first]).to eq(['wp.getUsers', '1'])
    end

    it 'round trips XML metacharacters and Unicode from the real successful native password' do
      password = 'module-target-&<café>'
      document = Nokogiri::XML(scanner.generate_xml_request('module_editor', password), &:strict)

      expect(request_values(document)).to eq(['1', 'module_editor', password])
    end

    it 'round trips XML metacharacters in a username without creating request elements' do
      username = 'module<&user>'
      document = Nokogiri::XML(scanner.generate_xml_request(username, 'module-target-password'), &:strict)

      expect(request_values(document)).to eq(['1', username, 'module-target-password'])
    end

    it 'declares UTF-8 for the actual Unicode password bytes' do
      document = Nokogiri::XML(scanner.generate_xml_request('module_editor', 'module-target-&<café>'))

      expect(document.encoding).to eq('UTF-8')
    end
  end

  def request_values(document)
    document.xpath('/methodCall/params/param/value').map { |value| (value.at_xpath('string') || value).text }
  end

  def response(name, code: nil)
    captured = captures.fetch(name)
    Rex::Proto::Http::Response.new(code || captured.fetch('code')).tap do |result|
      result.body = captured.fetch('body').dup
      captured.fetch('headers').each { |key, values| result.headers[key] = values.join(', ') }
    end
  end
end
