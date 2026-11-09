require 'rspec'
require 'json'
require 'csv'

RSpec.describe 'Elasticsearch enumeration data and replies' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/elasticsearch_enum') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/elasticsearch_enum/responses.json'))).fetch('responses') }
  let(:host) { '192.0.2.53' }
  let(:stored_data) { [] }

  before do
    mod.datastore['RHOSTS'] = host
    mod.datastore['DOWNLOADROWS'] = 5
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_bad)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:store_loot) do |*arguments|
      stored_data << arguments
      '/tmp/module-target.csv'
    end
  end

  describe 'captured search results' do
    before { allow(mod).to receive(:send_request_cgi).and_return(response('search')) }

    it 'retains exact native CSV fields including embedded newline, quotes, Unicode and empty text' do
      mod.get_results('module_target_records')

      expected = JSON.parse(captures.fetch('search').fetch('body')).fetch('hits').fetch('hits').map { |hit| hit.fetch('_source').transform_values(&:to_s) }
      expect(CSV.parse(stored_data.first.fetch(3), headers: true).map(&:to_h)).to match_array(expected)
    end

    it 'preserves the public loot name, content type, target and file name' do
      mod.get_results('module_target_records')

      expect(stored_data.first.values_at(0, 1, 2, 4)).to eq(['elasticserch.index.data', 'application/csv', host, 'module_target_records_data.csv'])
    end

    it 'retains the exact configured row count in the real search request' do
      mod.datastore['DOWNLOADROWS'] = 1

      mod.get_results('module_target_records')

      expect(mod).to have_received(:send_request_cgi).with(hash_including('data' => satisfy { |body| JSON.parse(body).fetch('size') == 1 }))
    end

    it 'does not invent data when the native zero-row response has no hits' do
      allow(mod).to receive(:send_request_cgi).and_return(response('zero'))
      mod.datastore['DOWNLOADROWS'] = 0

      mod.get_results('module_target_records')

      expect(stored_data).to be_empty
    end

    it 'does not dereference an absent hit list' do
      allow(mod).to receive(:send_request_cgi).and_return(derived_response('search', 'hits' => {}))

      mod.get_results('module_target_records')

      expect(stored_data).to be_empty
    end

    it 'does not dereference a document without source fields' do
      body = JSON.parse(captures.fetch('search').fetch('body'))
      body.fetch('hits').fetch('hits').first.delete('_source')
      allow(mod).to receive(:send_request_cgi).and_return(derived_response('search', body))

      mod.get_results('module_target_records')

      expect(stored_data).to be_empty
    end
  end

  describe 'captured product and permission replies' do
    it 'retains native product metadata and service reporting' do
      allow(mod).to receive(:send_request_cgi).and_return(response('root'))

      mod.get_version_info

      expect(mod).to have_received(:report_service).with(hash_including(host: host, port: 9200, name: 'elasticsearch'))
    end

    it 'refuses actual unrelated HTML before attempting the remaining collection phases' do
      allow(mod).to receive(:send_request_cgi).and_return(response('unrelated'))

      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /not Elasticsearch|cluster name not found|Unable to parse JSON/i)
      expect(mod).to have_received(:send_request_cgi).once
    end

    it 'retains the credential failure contract for the native HTTP 401 challenge' do
      allow(mod).to receive(:send_request_cgi).and_return(response('unauthorized'))

      expect { mod.get_version_info }.to raise_error(Msf::Auxiliary::Failed, /Credentials required, or incorrect/)
    end

    { get_version_info: 'forbidden_root', get_node_info: 'forbidden_nodes', get_cluster_info: 'forbidden_root' }.each do |method, capture|
      it "reports native permission refusal from #{method} without a nil parser exception" do
        allow(mod).to receive(:send_request_cgi).and_return(response(capture))

        expect { mod.public_send(method) }.to raise_error(Msf::Auxiliary::Failed, /permission|denied|privilege/i)
      end
    end

    it 'retains optional user-enumeration refusal for a real read/monitor role' do
      allow(mod).to receive(:send_request_cgi).and_return(response('forbidden_users'))

      mod.get_users

      expect(mod).to have_received(:print_bad).with('Unable to pull user data')
    end

    it 'retains optional user-enumeration refusal when native security is disabled' do
      allow(mod).to receive(:send_request_cgi).and_return(response('disabled_users'))

      mod.get_users

      expect(mod).to have_received(:print_bad).with('Unable to pull user data')
    end

    it 'handles a legitimately empty native-style node list' do
      allow(mod).to receive(:send_request_cgi).and_return(derived_response('nodes', []))

      mod.get_node_info

      expect(mod).not_to have_received(:report_service)
    end

    it 'handles a legitimately empty native-style index list without downloading data' do
      allow(mod).to receive(:send_request_cgi).and_return(derived_response('indices', []))

      mod.get_indices

      expect(stored_data).to be_empty
    end

    it 'reports the actual captured index names instead of a nil numeric Hash entry' do
      notes = []
      allow(mod).to receive(:send_request_cgi).and_return(response('indices'))
      allow(mod).to receive(:get_results)
      allow(mod).to receive(:report_note) { |options| notes << options }

      mod.get_indices

      expected = JSON.parse(captures.fetch('indices').fetch('body')).map { |index| index.fetch('index') }
      expect(notes.map { |options| options.fetch(:data).fetch(:index) }).to match_array(expected)
    end

    it 'rejects an unexpected JSON object where a node list is required' do
      allow(mod).to receive(:send_request_cgi).and_return(derived_response('nodes', { 'error' => 'Unexpected data' }))

      expect { mod.get_node_info }.to raise_error(Msf::Auxiliary::Failed, /response|JSON|node/i)
    end

    %i[get_version_info get_node_info get_cluster_info].each do |method|
      it "identifies the operation when #{method} has no HTTP reply" do
        allow(mod).to receive(:send_request_cgi).and_return(nil)

        expect { mod.public_send(method) }.to raise_error(Msf::Auxiliary::Failed, /no response|not respond/i)
      end
    end
  end

  def response(name)
    capture = captures.fetch(name)
    Rex::Proto::Http::Response.new(capture.fetch('code')).tap do |result|
      result.headers['Content-Type'] = capture.fetch('content_type')
      result.body = capture.fetch('body')
    end
  end

  def derived_response(name, body)
    response(name).tap { |result| result.body = JSON.generate(body) }
  end
end
