require 'spec_helper'

RSpec.describe Msf::Auxiliary::Etcd do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/etcd/version') }

  let(:fixture_dir) { File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/scanner/etcd') }
  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }

  before do
    response.body = File.binread(File.join(fixture_dir, 'version-3.5.18.json'))
    allow(mod).to receive(:send_request_raw).and_return(response)
    allow(mod).to receive(:report_service)
    allow(mod).to receive_messages(rhost: '192.0.2.1', rport: 2379)
  end

  describe '#fingerprint_service' do
    %w[3.4.35 3.5.18].each do |version|
      it "returns the actual #{version} version document" do
        response.body = File.binread(File.join(fixture_dir, "version-#{version}.json"))

        expect(mod.fingerprint_service('/')).to eq(JSON.parse(response.body))
      end
    end

    it 'reports a validated version with the target service address' do
      expect(mod).to receive(:report_service).with(host: '192.0.2.1', port: 2379, name: 'etcd', proto: 'tcp', info: JSON.parse(response.body))

      mod.fingerprint_service('/')
    end

    it 'normalizes the reverse proxy base path' do
      expect(mod).to receive(:send_request_raw).with('uri' => '/etcd/version', 'method' => 'GET').and_return(response)

      mod.fingerprint_service('/etcd/')
    end

    it 'does not identify unrelated Apache JSON or report an etcd service' do
      response.body = File.binread(File.join(fixture_dir, 'unrelated-version.json'))
      expect(mod).not_to receive(:report_service)
      expect(mod).not_to receive(:vprint_error)

      expect(mod.fingerprint_service('/')).to be_nil
    end

    ['[]', 'null', '{"etcdserver":"3.5.18"}', '{"etcdserver":null,"etcdcluster":"3.5.0"}', '{"etcdserver":"","etcdcluster":"3.5.0"}'].each do |body|
      it "rejects the synthetic unusable document #{body}" do
        response.body = body
        expect(mod).not_to receive(:report_service)

        expect(mod.fingerprint_service('/')).to be_nil
      end
    end

    it 'returns nil for an HTTP failure' do
      response.code = 404
      response.body = File.binread(File.join(fixture_dir, 'v2-disabled.txt'))
      expect(mod).not_to receive(:report_service)

      expect(mod.fingerprint_service('/')).to be_nil
    end

    it 'returns nil when the target does not reply' do
      allow(mod).to receive(:send_request_raw).and_return(nil)
      expect(mod).not_to receive(:report_service)

      expect(mod.fingerprint_service('/')).to be_nil
    end
  end
end
