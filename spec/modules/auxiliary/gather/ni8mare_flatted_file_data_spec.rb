require 'rspec'
require 'msfenv'
require 'msf/base'
require 'base64'

RSpec.describe 'Ni8mare execution file reference parsing' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('NI8MARE_FLATTED_OWNER_SOURCE', File.expand_path('../../../../modules/auxiliary/gather/ni8mare_cve_2026_21858.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:fixture_path) { File.expand_path('../../../file_fixtures/modules/auxiliary/ni8mare_execution_data', __dir__) }
  let(:oracle) { JSON.parse(File.binread(File.join(fixture_path, 'native-oracle.json'))) }
  let(:layout) { 'native-1.120.0-json.flatted.json' }
  let(:table) { JSON.parse(File.binread(File.join(fixture_path, layout))) }
  let(:file_data) { JSON.generate(table) }
  let(:execution_reply) { response(200, 'data' => { 'data' => file_data }) }
  let(:requests) { [] }
  let(:decoded_proofs) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RPORT' => 5678)
    # HTTP is doubled. Actual native Flatted tables, response/JSON parsing,
    # reference traversal, Base64 bytes and module failure/cleanup logic are real.
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      raise ArgumentError, "Unexpected parser request: #{request}" unless request['method'] == 'GET' && request['uri'] == '/rest/executions/407'

      execution_reply
    end
  end

  after do |example|
    if (path = ENV['NI8MARE_FLATTED_UNIT_EVIDENCE'])
      File.open(path, 'a') do |file|
        file.puts(JSON.generate(example: example.full_description, decoded_proofs: decoded_proofs, table_entries: table.is_a?(Array) ? table.length : nil, requests: requests.map { |request| request.slice('method', 'uri') }, fail_reason: mod.fail_reason))
      end
    end
  end

  def response(code, document)
    Rex::Proto::Http::Response.new(code).tap { |res| res.body = JSON.generate(document) }
  end

  def decoded_file
    result = mod.extract_content('407')
    # Canonical Base64 is exact byte equality and keeps failure JSON valid even
    # when the predecessor accidentally decodes metadata into non-UTF8 bytes.
    Base64.strict_encode64(result).tap { |value| decoded_proofs << value }
  end

  def reordered(values)
    order = [0] + (1...values.length).to_a.reverse
    positions = order.each_with_index.to_h
    order.map do |index|
      entry = values.fetch(index)
      # Only references nested in containers change; table-entry strings are
      # literals, including numeric-looking Base64. This is a fixture transform.
      case entry
      when Hash
        entry.transform_values { |value| value.is_a?(String) ? positions.fetch(value.to_i).to_s : value }
      when Array
        entry.map { |value| value.is_a?(String) ? positions.fetch(value.to_i).to_s : value }
      else
        entry
      end
    end
  end

  context 'genuine 32-entry multipart capture' do
    let(:layout) { 'native-1.120.0-multipart.flatted.json' }

    it 'returns all bytes verified by the installed native flatted.parse oracle' do
      expect(decoded_file).to eq(oracle.fetch('file_base64'))
    end
  end

  it 'follows the genuine 33-entry JSON capture instead of decoding literal txt at29' do
    expect(table.fetch(29)).to eq('txt')
    expect(decoded_file).to eq(oracle.fetch('file_base64'))
  end

  context 'reordered native references' do
    let(:file_data) { JSON.generate(reordered(table)) }

    it 'does not depend on table position or optional metadata ordering' do
      expect(decoded_file).to eq(oracle.fetch('file_base64'))
    end
  end

  it 'accepts the single randomized binary field label' do
    table[20] = { 'RandomizedField9' => '25' }

    expect(decoded_file).to eq(oracle.fetch('file_base64'))
  end

  it 'preserves an empty file' do
    table[30] = ''
    table[32] = '0 B'

    expect(decoded_file).to eq('')
  end

  it 'treats a numeric-looking Base64 table entry as a literal rather than another reference' do
    table[30] = '1234'
    table[32] = '3 B'

    expect(decoded_file).to eq('1234')
  end

  it 'preserves arbitrary byte values exactly' do
    encoded = Base64.strict_encode64((0..255).to_a.pack('C*'))
    table[30] = encoded
    table[32] = '256 B'

    expect(decoded_file).to eq(encoded)
  end

  it 'rejects a missing owned form result path' do
    table[0].delete('resultData')

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'not-found: The execution did not contain the uploaded file.')
  end

  it 'rejects a missing binary result even when unrelated metadata looks like Base64' do
    table[18].delete('binary')
    table[29] = oracle.fetch('file_base64')

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'not-found: The execution did not contain the uploaded file.')
  end

  it 'rejects an absent binary field' do
    table[20] = {}

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'not-found: The execution did not contain the uploaded file.')
  end

  it 'does not choose between ambiguous binary fields' do
    table[20]['Other_field'] = '25'

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Ambiguous n8n execution file data.')
  end

  it 'does not silently choose the first of multiple result items' do
    table[17] << '18'

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Ambiguous n8n execution file data.')
  end

  it 'rejects an out-of-range reference before lookup' do
    table[0]['resultData'] = '99'

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid or cyclic n8n execution file reference.')
  end

  it 'bounds numeric reference length before integer conversion' do
    table[0]['resultData'] = '9' * 2048

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid or cyclic n8n execution file reference.')
  end

  it 'rejects a cycle along the known result path without expanding the graph' do
    table[2]['runData'] = '0'

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid or cyclic n8n execution file reference.')
  end

  it 'rejects a self-referencing binary descriptor' do
    table[25]['data'] = '25'

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid or cyclic n8n execution file reference.')
  end

  it 'rejects an inline non-reference value in the reference table' do
    table[25]['data'] = 30

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid or cyclic n8n execution file reference.')
  end

  it 'rejects malformed Base64 rather than returning silently truncated bytes' do
    table[30] = 'not valid Base64!'
    expect(mod).to receive(:elog).with('Failed to decode file data from the n8n execution result', error: be_a(ArgumentError))

    expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Invalid Base64 file data in the n8n execution result.')
  end

  context 'malformed table root' do
    let(:table) { {} }

    it 'rejects a non-table document without dereferencing it' do
      expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unexpected-reply: Malformed n8n execution file data.')
    end
  end

  context 'malformed inner JSON' do
    let(:file_data) { '{' }

    it 'preserves the existing JSON parser failure contract' do
      expect { decoded_file }.to raise_error(Msf::Auxiliary::Failed, 'unknown: Failed to parse JSON data')
    end
  end

  it 'still removes only the created workflow after a parser failure' do
    table[25].delete('data')
    owned_id = 'ParserCreated001'
    deleted = []
    allow(mod).to receive(:send_request_cgi) do |request|
      requests << request
      case request.fetch('uri')
      when '/rest/workflows'
        nodes = JSON.parse(request.fetch('data')).fetch('nodes')
        response(200, 'data' => { 'id' => owned_id, 'nodes' => nodes, 'versionId' => 'unit-version' })
      when "/rest/workflows/#{owned_id}/run"
        response(200, 'data' => { 'waitingForWebhook' => true })
      when %r{\A/form-test/}
        response(200, 'status' => 'success')
      when '/rest/executions'
        response(200, 'data' => { 'results' => [{ 'id' => '407' }] })
      when '/rest/executions/407'
        execution_reply
      when "/rest/workflows/#{owned_id}/archive"
        response(200, 'data' => { 'id' => owned_id })
      when "/rest/workflows/#{owned_id}"
        deleted << owned_id
        response(200, 'data' => true)
      else
        raise ArgumentError, "Unexpected cleanup request: #{request}"
      end
    end
    mod.instance_variable_set(:@workflow_id, 'ForeignControl01')
    expect { mod.read_file('/tmp/native.bin') }.to raise_error(Msf::Auxiliary::Failed, 'not-found: The execution did not contain the uploaded file.')
    mod.cleanup

    expect(deleted).to eq([owned_id])
    expect(mod.fail_reason).to eq(Msf::Module::Failure::NotFound)
  end
end
