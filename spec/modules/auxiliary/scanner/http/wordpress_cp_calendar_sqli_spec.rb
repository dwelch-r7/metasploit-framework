require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'

RSpec.describe 'CP Multi-View Calendar request projection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('CP_CALENDAR_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wordpress_cp_calendar_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:capture) { JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wordpress_cp_calendar_sqli/editor_responses.json'))) }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:requests) { [] }
  let(:vulnerabilities) { [] }
  let(:response_kind) { 'native_positive' }
  let(:projection) { projection_of(requests.fetch(0)) }
  let(:columns) { capture.fetch('native_event_schema').map { |column| column.fetch('name') } }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/')
    allow(mod).to receive(:framework).and_return(framework)
    %i[print_good vprint_status vprint_error].each { |method| allow(mod).to receive(method) }
    allow(Rex::Text).to receive(:rand_text_alpha).with(5).and_return('right', 'leftM', 'flagX', 'other', 'Alpha', 'Proof')
    allow(mod).to receive(:report_vuln) { |details| vulnerabilities << details }
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      native_response(options)
    end
  end

  # HTTP, UI, framework access and reporting are explicit doubles. Replies are
  # native HTML excerpts with only the generated positive marker substituted.
  # This does not evaluate SQL or emulate PHP. Wire constraints below come from
  # the captured real table schema and PHP rendering failure; genuine targets
  # separately arbitrate execution and persistence.

  it 'excludes stored events from the first result consumed by the editor' do
    mod.run_host('192.0.2.10')

    expect(projection.fetch(:identifier)).to be_negative
  end

  %w[starttime endtime].each do |column_name|
    it "supplies a non-NULL #{column_name} for the native datetime parser" do
      mod.run_host('192.0.2.10')

      expect(projection.fetch(:fields).fetch(columns.index(column_name))).not_to eq('NULL')
    end
  end

  it 'keeps the complete native event column count' do
    mod.run_host('192.0.2.10')

    expect(projection.fetch(:fields).length).to eq(columns.length)
  end

  it 'projects the complete marker into the native location column' do
    mod.run_host('192.0.2.10')

    expect(projection.fetch(:fields).fetch(columns.index('location'))).to eq('CONCAT(0x6c6566744d,0x666c616758,0x7269676874)')
  end

  it 'keeps the injected expression free of quote escaping requirements' do
    mod.run_host('192.0.2.10')

    expect(requests.first.fetch('vars_get').fetch('id')).not_to match(/['"\\]/)
  end

  it 'reports the complete marker in the captured native location input' do
    mod.run_host('192.0.2.10')

    expect(vulnerabilities.length).to eq(1)
  end

  it 'retains the selected service endpoint in its vulnerability report' do
    mod.run_host('192.0.2.10')

    expect(vulnerabilities.first.slice(:host, :port, :proto)).to eq(host: '192.0.2.10', port: 80, proto: 'tcp')
  end

  it 'retains the existing exploit reference in its report' do
    mod.run_host('192.0.2.10')

    expect(vulnerabilities.first.fetch(:refs).map(&:ctx_val)).to eq(['36243'])
  end

  context 'with the ordinary native editor response' do
    let(:response_kind) { 'native_ordinary' }

    it 'does not infer an injection from the editor form alone' do
      mod.run_host('192.0.2.10')

      expect(vulnerabilities).to be_empty
    end
  end

  context 'with the captured patched response' do
    let(:response_kind) { 'native_patched' }

    it 'does not report a vulnerability without the marker' do
      mod.run_host('192.0.2.10')

      expect(vulnerabilities).to be_empty
    end
  end

  context 'with the native NULL-date rendering failure' do
    let(:response_kind) { 'native_null_date_failure' }

    it 'does not mistake the partial response for a successful probe' do
      mod.run_host('192.0.2.10')

      expect(vulnerabilities).to be_empty
    end
  end

  context 'without an HTTP response' do
    let(:response_kind) { 'no_response' }

    it 'returns without reporting a vulnerability' do
      mod.run_host('192.0.2.10')

      expect(vulnerabilities).to be_empty
    end
  end

  context 'with a missing response body' do
    let(:response_kind) { 'no_body' }

    it 'returns without reporting a vulnerability' do
      mod.run_host('192.0.2.10')

      expect(vulnerabilities).to be_empty
    end
  end

  it 'preserves the request route and operation parameters' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    mod.run_host('192.0.2.10')

    expect(requests.first).to include('uri' => '/wordpress/', 'vars_get' => hash_including('action' => 'data_management', 'cpmvc_do_action' => 'mvparse', 'f' => 'edit'))
  end

  it 'leaves the operator options unchanged' do
    settings = mod.datastore.to_h.dup
    mod.run_host('192.0.2.10')

    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'generates a fresh complete marker for a second execution' do
    mod.run_host('192.0.2.10')
    mod.run_host('192.0.2.10')

    expect(requests.map { |request| marker_of(request) }).to eq(%w[leftMflagXright AlphaProofother])
  end

  def projection_of(request)
    match = request.fetch('vars_get').fetch('id').match(/\A(-?\d+) UNION ALL SELECT (.*)--\z/)
    raise ArgumentError, 'Unexpected calendar projection' unless match

    # The known single-level projection contains commas inside CONCAT.
    { identifier: Integer(match[1]), fields: match[2].split(/,(?![^()]*\))/) }
  end

  def marker_of(request)
    match = request.fetch('vars_get').fetch('id').match(/CONCAT\(0x([[:xdigit:]]+),0x([[:xdigit:]]+),0x([[:xdigit:]]+)\)/)
    raise ArgumentError, 'Calendar request is missing its marker' unless match

    match.captures.map { |hex| [hex].pack('H*') }.join
  end

  def native_response(request)
    return nil if response_kind == 'no_response'
    return double('HttpResponse', code: 200, body: nil) if response_kind == 'no_body'

    response = capture.fetch('responses').fetch(response_kind)
    body = response.fetch('excerpt')
    body = body.sub(response.fetch('original_marker'), marker_of(request)) if response.key?('original_marker')
    double('HttpResponse', code: response.fetch('status'), body: body)
  end
end
