require 'rspec'

RSpec.describe 'Etcd v2 key collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/etcd/open_key_scanner') }

  let(:fixture_dir) { File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/scanner/etcd') }
  let(:response) { Rex::Proto::Http::Response.new(200, 'OK') }

  before do
    response.body = File.binread(File.join(fixture_dir, 'recursive-keys.json'))
    allow(mod).to receive(:fingerprint_service).and_return({ 'etcdserver' => '3.5.18', 'etcdcluster' => '3.5.0' })
    allow(mod).to receive(:send_request_raw).and_return(response)
    allow(mod).to receive(:rhost).and_return('192.0.2.1')
    allow(mod).to receive(:store_loot).and_return('/loot/etcd.keys')
  end

  describe '#run_host' do
    it 'stores valid JSON with every native key field and value' do
      expected = JSON.parse(response.body)
      expect(mod).to receive(:store_loot) do |type, content_type, host, data, filename, description|
        expect([type, content_type, host, filename, description]).to eq(['etcd.data', 'text/json', '192.0.2.1', 'etcd.keys', 'etcd keys'])
        expect(JSON.parse(data)).to eq(expected)
      end

      mod.run_host('192.0.2.1')
    end

    it 'does not store an unrelated actual Apache inventory document' do
      response.body = File.binread(File.join(fixture_dir, 'unrelated-keys.json'))
      expect(mod).not_to receive(:store_loot)

      mod.run_host('192.0.2.1')
    end

    it 'handles actual authentication refusal without a logging-method exception' do
      response.code = 401
      response.body = File.binread(File.join(fixture_dir, 'auth-denied.json'))
      expect(mod).not_to receive(:store_loot)

      expect { mod.run_host('192.0.2.1') }.not_to raise_error
    end

    it 'handles the actual disabled v2 API without a logging-method exception' do
      response.code = 404
      response.body = File.binread(File.join(fixture_dir, 'v2-disabled.txt'))
      expect(mod).not_to receive(:store_loot)

      expect { mod.run_host('192.0.2.1') }.not_to raise_error
    end

    it 'handles a missing reply without a logging-method exception' do
      allow(mod).to receive(:send_request_raw).and_return(nil)
      expect(mod).not_to receive(:store_loot)

      expect { mod.run_host('192.0.2.1') }.not_to raise_error
    end

    it 'sends configured Basic credentials without requiring a server challenge' do
      mod.datastore['HttpUsername'] = 'root'
      mod.datastore['HttpPassword'] = 'module-target-etcd-root-password'
      expect(mod).to receive(:send_request_raw).with(hash_including('authorization' => 'Basic cm9vdDptb2R1bGUtdGFyZ2V0LWV0Y2Qtcm9vdC1wYXNzd29yZA==')).and_return(response)

      mod.run_host('192.0.2.1')
    end

    it 'respects explicitly disabled HTTP authentication' do
      mod.datastore['HttpUsername'] = 'root'
      mod.datastore['HttpPassword'] = 'module-target-etcd-root-password'
      mod.datastore['HTTP::Auth'] = 'none'
      expect(mod).to receive(:send_request_raw).with(hash_excluding('authorization')).and_return(response)

      mod.run_host('192.0.2.1')
    end

    ['[]', 'null', '{}', '{"action":"get","node":[]}'].each do |body|
      it "does not store the synthetic unusable key document #{body}" do
        response.body = body
        expect(mod).not_to receive(:store_loot)

        expect { mod.run_host('192.0.2.1') }.not_to raise_error
      end
    end
  end
end
