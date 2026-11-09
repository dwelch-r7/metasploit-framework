require 'rspec'
require 'json'

RSpec.describe 'CouchDB Enum Utility' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/couchdb/couchdb_enum')
  end

  # Bodies captured from the original pinned CouchDB 3.3.1 disposable target.
  # Failure/type/header variants below are explicitly synthetic unit controls.
  let(:capture) do
    JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/couchdb_enum_3_3_1.json')))
  end
  let(:authorization) { 'Basic bGFiYWRtaW46bGFicGFzc3dvcmQ=' }
  let(:requests) { [] }
  let(:loot) { {} }
  let(:listing) { response(capture.fetch('databases')) }
  let(:documents) { response(capture.fetch('documents')) }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['HttpUsername'] = 'labadmin'
    mod.datastore['HttpPassword'] = 'labpassword'
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:print_bad)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:store_loot) do |kind, _type, _host, data, _name|
      loot[kind] = JSON.parse(data)
      '/tmp/couchdb-loot.json'
    end
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      requests.length == 1 ? listing : documents
    end
  end

  describe '#get_dbs' do
    it 'authenticates the initial database-list request' do
      mod.get_dbs(authorization)

      expect(requests.first).to include('uri' => '/_all_dbs', 'authorization' => authorization)
    end

    it 'retrieves documents from sibling database resources' do
      mod.get_dbs(authorization)

      expect(requests.drop(1).map { |request| request.fetch('uri') }).to eq([
        '/_global_changes/_all_docs', '/_replicator/_all_docs', '/_users/_all_docs', '/module_evidence/_all_docs'
      ])
    end

    it 'authenticates every document request and requests attachment contents' do
      mod.get_dbs(authorization)

      expect(requests.drop(1)).to all(include('authorization' => authorization, 'vars_get' => { 'include_docs' => 'true', 'attachments' => 'true' }))
    end

    it 'stores the actual native list and full document response' do
      mod.get_dbs(authorization)

      expect(loot.slice('couchdb.enum', 'couchdb.module_evidence')).to eq(
        'couchdb.enum' => capture.fetch('databases'), 'couchdb.module_evidence' => capture.fetch('documents')
      )
    end

    context 'with a prefixed list endpoint and trailing slash' do
      before { mod.datastore['TARGETURI'] = '/proxy/_all_dbs/' }

      it 'retains the list endpoint and uses its parent for documents' do
        mod.get_dbs(authorization)

        expect(requests.map { |request| request.fetch('uri') }).to eq([
          '/proxy/_all_dbs/', '/proxy/_global_changes/_all_docs', '/proxy/_replicator/_all_docs', '/proxy/_users/_all_docs', '/proxy/module_evidence/_all_docs'
        ])
      end
    end

    context 'when the list request does not respond' do
      let(:listing) { nil }

      it 'reports the failed operation without storing loot' do
        expect { mod.get_dbs(authorization) }.not_to raise_error
        expect(loot).to be_empty
        expect(mod).to have_received(:print_error).with(a_string_including('list databases', 'did not respond'))
      end
    end

    context 'when the server rejects authentication' do
      let(:listing) { response(capture.fetch('unauthorized'), code: 401) }

      it 'does not request documents or store error JSON as database loot' do
        mod.get_dbs(authorization)

        expect(requests.length).to eq(1)
        expect(loot).to be_empty
      end
    end

    ['not JSON', '{}', '["module_evidence",42]'].each do |body|
      context "with invalid list body #{body.inspect}" do
        let(:listing) { response(body, raw: true) }

        it 'reports an invalid list rather than using it as database names' do
          expect { mod.get_dbs(authorization) }.not_to raise_error
          expect(loot).to be_empty
          expect(mod).to have_received(:print_error).with(a_string_including('database list'))
        end
      end
    end

    context 'with an empty database list' do
      let(:listing) { response([]) }

      it 'stores the empty list without attempting document requests' do
        mod.get_dbs(authorization)

        expect(loot).to eq('couchdb.enum' => [])
        expect(requests.length).to eq(1)
      end
    end

    context 'when a document request does not respond' do
      let(:documents) { nil }

      it 'retains list loot but does not store a failed document response' do
        expect { mod.get_dbs(authorization) }.not_to raise_error
        expect(loot.keys).to eq(['couchdb.enum'])
        expect(mod).to have_received(:print_error).with(a_string_including('retrieve database', 'did not respond'))
      end
    end

    context 'when a database is denied' do
      let(:documents) { response(capture.fetch('unauthorized'), code: 403) }

      it 'does not store the denial response as database data' do
        mod.get_dbs(authorization)

        expect(loot.keys).to eq(['couchdb.enum'])
      end
    end

    ['not JSON', '[]', '{"rows":null}', '{"rows":[],"total_rows":"two"}'].each do |body|
      context "with invalid document body #{body.inspect}" do
        let(:documents) { response(body, raw: true) }

        it 'reports invalid document data without storing it as loot' do
          expect { mod.get_dbs(authorization) }.not_to raise_error
          expect(loot.keys).to eq(['couchdb.enum'])
          expect(mod).to have_received(:print_error).with(a_string_including('document response'))
        end
      end
    end
  end

  describe '#get_server_info' do
    let(:listing) { response(capture.fetch('server_info')) }

    it 'uses the configured authorization' do
      mod.get_server_info(authorization)

      expect(requests.first).to include('uri' => '/', 'authorization' => authorization)
    end

    it 'reports native server metadata' do
      mod.get_server_info(authorization)

      expect(mod).to have_received(:report_service).with(hash_including(info: JSON.generate(capture.fetch('server_info'))))
    end

    context 'with a prefixed list endpoint' do
      before { mod.datastore['TARGETURI'] = '/proxy/_all_dbs' }

      it 'retrieves metadata from the application root' do
        mod.get_server_info(authorization)

        expect(requests.first.fetch('uri')).to eq('/proxy/')
      end
    end

    context 'when the server does not respond' do
      let(:listing) { nil }

      it 'reports the failed operation rather than raising' do
        expect { mod.get_server_info(authorization) }.not_to raise_error
        expect(mod).not_to have_received(:report_service)
      end
    end

    context 'with malformed server JSON' do
      let(:listing) { response('not JSON', raw: true) }

      it 'does not report invalid server information' do
        expect { mod.get_server_info(authorization) }.not_to raise_error
        expect(mod).not_to have_received(:report_service)
      end
    end
  end

  describe '#valid_response' do
    it 'rejects an absent response' do
      expect(mod.valid_response(nil)).to be(false)
    end

    it 'rejects a response without a server header' do
      message = Rex::Proto::Http::Response.new(200)
      message.body = '{}'

      expect(mod.valid_response(message)).to be(false)
    end
  end

  describe '#run' do
    before do
      allow(mod).to receive(:get_dbs)
      allow(mod).to receive(:get_server_info)
      mod.datastore['SERVERINFO'] = true
    end

    it 'uses provided credentials for enumeration and server information' do
      mod.run

      expect(mod).to have_received(:get_dbs).with(authorization)
      expect(mod).to have_received(:get_server_info).with(authorization)
    end

    it 'uses newly generated credentials after account creation' do
      mod.datastore.import_defaults_from_hash({ 'HttpUsername' => 'generated-user', 'HttpPassword' => 'generated-password' }, imported_by: 'spec')
      mod.datastore.unset('HttpUsername')
      mod.datastore.unset('HttpPassword')
      mod.datastore['CREATEUSER'] = true
      allow(mod).to receive(:get_version) do
        mod.instance_variable_set(:@version, '1.6.1')
        true
      end
      allow(mod).to receive(:create_user)
      mod.run

      expect(mod).to have_received(:get_dbs).with(mod.basic_auth('generated-user', 'generated-password'))
    end

    it 'keeps generated credential defaults anonymous when not creating an account' do
      mod.datastore.import_defaults_from_hash({ 'HttpUsername' => 'generated-user', 'HttpPassword' => 'generated-password' }, imported_by: 'spec')
      mod.datastore.unset('HttpUsername')
      mod.datastore.unset('HttpPassword')
      mod.run

      expect(mod).to have_received(:get_dbs).with(nil)
      expect(mod).to have_received(:get_server_info).with(nil)
    end
  end

  def response(document, code: 200, raw: false)
    message = Rex::Proto::Http::Response.new(code)
    message.headers['Server'] = 'CouchDB/3.3.1 (Erlang OTP/24)'
    message.body = raw ? document : JSON.generate(document)
    message
  end
end
