require 'rspec'
require 'msfenv'
require 'msf/base'
require 'base64'
require 'json'

RSpec.describe 'LearnPress request nonce contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('LEARNPRESS_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_learnpress_c_fields_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:capture) { JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_learnpress_c_fields_sqli/cache_response.json'))) }
  let(:sqli) { double('TimeBasedBlind') }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:requests) { [] }
  let(:queries) { ['if(1=1,sleep(0.4),0)', 'if(1=2,sleep(0.4),0)'] }
  let(:legacy_number) { '38' }
  let(:nonce_values) { [1_000_000_000, 9_999_999_999] }
  let(:reply) { Rex::Proto::Http::Response.new(capture.fetch('code')).tap { |response| response.body = Base64.strict_decode64(capture.fetch('body_base64')) } }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'TARGETURI' => '/', 'ACTION' => action_name)
    allow(mod).to receive(:framework).and_return(framework)
    %i[print_status print_good print_error vprint_status vprint_error].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:wordpress_sqli_initialize)
    allow(mod).to receive(:wordpress_sqli_get_users_credentials)
    allow(Rex::Text).to receive(:rand_text_numeric).and_call_original
    allow(Rex::Text).to receive(:rand_text_numeric).with(2).and_return(legacy_number)
    allow(mod).to receive(:rand).and_call_original
    allow(mod).to receive(:rand).with(1_000_000_000..9_999_999_999).and_return(*nonce_values)
    # SQLi timing, HTTP, UI and reporting are modeled. The real public run_host
    # action selection and per-query callback build every captured request.
    allow(mod).to receive(:create_sqli) do |dbms:, &query_proc|
      raise ArgumentError, 'Unexpected SQLi implementation' unless dbms == Msf::Exploit::SQLi::MySQLi::TimeBasedBlind

      allow(sqli).to receive(:test_vulnerable) do
        queries.each { |query| query_proc.call(query) }
        true
      end
      sqli
    end
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      reply
    end
  end

  shared_examples 'a fresh timing probe' do
    it 'leaves the complete recorded two-digit cache pool' do
      mod.run_host('192.0.2.10')

      expect(nonce_of(requests.first)).to be < -99
    end

    context 'when the original generator would return zero' do
      let(:legacy_number) { '00' }

      it 'keeps the COUNT comparator strictly negative' do
        mod.run_host('192.0.2.10')

        expect(nonce_of(requests.first)).to be_negative
      end
    end

    it 'chooses a fresh value for each callback request' do
      mod.run_host('192.0.2.10')

      expect(requests.map { |request| nonce_of(request) }).to eq([-1_000_000_000, -9_999_999_999])
    end

    it 'serializes the minimum generated nonce as a negative SQL integer' do
      mod.run_host('192.0.2.10')

      expect(nonce_of(requests.first)).to eq(-1_000_000_000)
    end

    it 'serializes the maximum generated nonce without overflow or quoting' do
      mod.run_host('192.0.2.10')

      expect(nonce_of(requests.last)).to eq(-9_999_999_999)
    end

    it 'preserves the SQLi implementation payloads' do
      mod.run_host('192.0.2.10')

      expect(requests.map { |request| injection_of(request).fetch('payload') }).to eq(queries)
    end

    it 'preserves the action endpoint and supporting parameters' do
      mod.run_host('192.0.2.10')

      expect(requests.first.slice('method', 'uri', 'vars_get')).to eq(
        'method' => 'GET', 'uri' => endpoint,
        'vars_get' => extra_parameters.merge(field_name => requests.first.fetch('vars_get').fetch(field_name))
      )
    end

    context 'when the target does not reply' do
      let(:reply) { nil }

      it 'retains the existing connection-failure contract' do
        expect { mod.run_host('192.0.2.10') }.to raise_error(Msf::Auxiliary::Scanner::AttemptFailed, /unreachable: Connection failed/)
      end
    end
  end

  context 'with the c_only_fields action' do
    let(:action_name) { 'CVE-2024-8522' }
    let(:field_name) { 'c_only_fields' }
    let(:endpoint) { '/learnpress/v1/courses' }
    let(:extra_parameters) { { 'rest_route' => '/learnpress/v1/courses' } }

    include_examples 'a fresh timing probe'
  end

  context 'with the c_fields action' do
    let(:action_name) { 'CVE-2024-8529' }
    let(:field_name) { 'c_fields' }
    let(:endpoint) { '/wp-json/lp/v1/courses/archive-course' }
    let(:extra_parameters) { { 'return_type' => 'json' } }

    include_examples 'a fresh timing probe'
  end

  def injection_of(request)
    match = request.fetch('vars_get').fetch(field_name).match(/\AIF\(COUNT\(\*\)!=(-?\d+),\((.*)\),0\)\z/)
    raise ArgumentError, 'Unexpected timing-probe shape' unless match

    { 'nonce' => Integer(match[1]), 'payload' => match[2] }
  end

  def nonce_of(request)
    injection_of(request).fetch('nonce')
  end
end
