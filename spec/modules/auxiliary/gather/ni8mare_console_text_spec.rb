require 'rspec'
require 'msfenv'
require 'msf/base'
require 'base64'

RSpec.describe 'Ni8mare console file text framing', console_text: true do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('NI8MARE_JWT_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/ni8mare_cve_2026_21858.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:unicode_path) { '/tmp/module target café 雪.txt' }
  let(:input_filename) { unicode_path.dup.freeze }
  let(:requests) { [] }
  let(:wire_proofs) { [] }
  let(:deleted_ids) { [] }
  let(:owned_id) { 'ConsoleTextOwn001' }
  let(:form_id) { '00000000-0000-4000-8000-000000000001' }

  before do
    mod.datastore.merge!(
      'RHOSTS' => '192.0.2.10', 'RPORT' => 5678,
      'USERNAME' => 'member@example.test', 'PASSWORD' => 'controlled-member-password',
      'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => input_filename
    )
    allow(mod).to receive(:rand).with(8..11).and_return(8)
    allow(Rex::Text).to receive(:rand_text_alpha) { |length| 'A' * length }
    allow(SecureRandom).to receive(:uuid).and_return(form_id)
    # HTTP is doubled; text conversion, JSON, workflow ownership/cleanup and
    # Rex::Proto::Http::ClientRequest serialization execute real source code.
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      case request.fetch('uri')
      when '/rest/login'
        response(200, 'data' => { 'id' => 'unit-member' })
      when '/rest/workflows'
        nodes = JSON.parse(request.fetch('data')).fetch('nodes')
        response(200, 'data' => { 'id' => owned_id, 'nodes' => nodes, 'versionId' => form_id })
      when "/rest/workflows/#{owned_id}/run"
        response(200, 'data' => { 'waitingForWebhook' => true })
      when "/rest/workflows/#{owned_id}/archive"
        response(200, 'data' => { 'id' => owned_id })
      when "/rest/workflows/#{owned_id}"
        deleted_ids << owned_id
        response(200, 'data' => true)
      when %r{\A/form-test/}
        response(200, 'status' => 'success')
      else
        raise ArgumentError, "Unexpected unit HTTP request: #{request}"
      end
    end
  end

  after do |example|
    if (path = ENV['NI8MARE_CONSOLE_TEXT_EVIDENCE'])
      File.open(path, 'a') do |file|
        file.puts(JSON.generate(example: example.full_description, requests: requests.map { |request| request.slice('method', 'uri') }, wire_proofs: wire_proofs, input_encoding: input_filename.encoding.name, input_bytes: input_filename.bytes, deleted_ids: deleted_ids))
      end
    end
  end

  def response(code, document)
    Rex::Proto::Http::Response.new(code).tap { |res| res.body = JSON.generate(document) }
  end

  def serialize_upload
    mod.content_type_confusion_upload('unit-form', input_filename)
    upload = requests.last
    wire = Rex::Proto::Http::ClientRequest.new(
      'method' => upload.fetch('method'), 'uri' => upload.fetch('uri'),
      'vhost' => '192.0.2.10', 'ctype' => upload.fetch('ctype'),
      'data' => upload.fetch('data'), 'cgi' => true
    ).to_s
    headers, body = wire.split("\r\n\r\n", 2)
    declared = headers[/Content-Length: (\d+)/i, 1].to_i
    decoded_path = JSON.parse(body).dig('files', 'field-0', 'filepath')
    wire_proofs << { declared_content_length: declared, actual_body_bytes: body.bytesize, decoded_path: decoded_path, request_data_encoding: upload.fetch('data').encoding.name }
    [declared, body, decoded_path]
  end

  shared_examples 'a byte-framed upload path' do |expected_path|
    it 'preserves the JSON path and declares the actual wire-body byte length' do
      encoding = input_filename.encoding
      bytes = input_filename.bytes
      declared, body, decoded_path = serialize_upload

      expect(decoded_path).to eq(expected_path)
      expect(declared).to eq(body.bytesize)
      expect(input_filename.encoding).to eq(encoding)
      expect(input_filename.bytes).to eq(bytes)
    end
  end

  context 'ordinary ASCII path' do
    let(:input_filename) { '/tmp/module target ascii.txt'.freeze }

    include_examples 'a byte-framed upload path', '/tmp/module target ascii.txt'
  end

  context 'UTF-8 Unicode path' do
    include_examples 'a byte-framed upload path', '/tmp/module target café 雪.txt'
  end

  context 'console ASCII-8BIT Unicode path' do
    let(:input_filename) { unicode_path.b.freeze }

    include_examples 'a byte-framed upload path', '/tmp/module target café 雪.txt'

    it 'normalizes valid text before JSON without emitting a binary-text warning' do
      expect { mod.content_type_confusion_upload('unit-form', input_filename) }.not_to output.to_stderr
      expect(input_filename.encoding).to eq(Encoding::BINARY)
    end
  end

  context 'invalid console filename bytes' do
    let(:input_filename) { "/tmp/invalid-\xff.txt".b.freeze }

    it 'reports explicit BadConfig and preserves cleanup ownership after workflow creation' do
      mod.instance_variable_set(:@workflow_id, 'ForeignControl01')
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, 'bad-config: Filename must contain valid UTF-8 text.')
      mod.cleanup

      expect(deleted_ids).to eq([owned_id])
      expect(requests.none? { |request| request['uri'].start_with?('/form-test/') }).to be true
      expect(mod.datastore['TARGET_FILENAME'].encoding).to eq(Encoding::BINARY)
      expect(mod.datastore['TARGET_FILENAME'].bytes).to eq(input_filename.bytes)
    end
  end
end
