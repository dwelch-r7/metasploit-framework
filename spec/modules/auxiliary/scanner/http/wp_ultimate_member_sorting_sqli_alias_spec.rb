require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'

RSpec.describe 'Ultimate Member SQLi alias generation' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('ULTIMATE_MEMBER_ALIAS_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_ultimate_member_sorting_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:sqli) { double('SQLi engine') }
  let(:http_response) { double('HTTP response') }
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_ultimate_member_sorting_sqli/alias_errors.json')))
  end
  let(:record) { capture.fetch('queries').find { |row| row.fetch('alias') == '6e5W2' } }
  let(:alias_token) { record.fetch('alias') }
  let(:scalar_magnitude) { record.fetch('outer_scalar').abs }
  let(:payload) { record.fetch('payload') }
  let(:injection_vulnerable) { true }
  let(:factories) { [] }
  let(:callbacks) { [] }
  let(:requests) { [] }
  let(:initialized) { [] }
  let(:gathered) { [] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 8080, 'TARGETURI' => '/', 'COUNT' => 1, 'SqliDelay' => 0.6)
    allow(mod).to receive(:framework).and_return(framework)
    allow(mod).to receive(:get_nonce).and_return(capture.fetch('nonce'))
    allow(mod).to receive(:get_directory_id).with(capture.fetch('nonce')).and_return(capture.fetch('directory_hash'))
    %i[print_status print_good].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:rand).with(99).and_return(scalar_magnitude)
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(5).and_return(alias_token)
    allow(mod).to receive(:create_sqli) do |arguments, &callback|
      factories << arguments
      callbacks << callback
      sqli
    end
    allow(sqli).to receive(:test_vulnerable) do
      callbacks.last.call(payload)
      injection_vulnerable
    end
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options.deep_dup
      http_response
    end
    allow(mod).to receive(:wordpress_sqli_initialize) { |instance| initialized << instance }
    allow(mod).to receive(:wordpress_sqli_get_users_credentials) { |count| gathered << count }
  end

  # The real run method creates and invokes its real SQLi callback. Discovery,
  # factory/probe, HTTP, UI, Framework and shared credential/reporting methods are
  # explicit doubles. Selected error/query/payload bytes are native captures;
  # extra alias variants below are synthetic unit inputs. These cases establish
  # generated payload contracts, not SQL execution or successful extraction.

  %w[982E2 6e5W2 5e88N 4E0y1].each do |captured_alias|
    context "with captured rejected alias #{captured_alias}" do
      let(:record) { capture.fetch('queries').find { |row| row.fetch('alias') == captured_alias } }

      it 'quotes the alias while preserving the entire captured sorting payload' do
        mod.run

        expected = record.fetch('sorting').delete_suffix(record.fetch('alias') + ')') + "`#{alias_token}`)"
        expect(requests.last.fetch('vars_post').fetch('sorting')).to eq(expected)
      end
    end
  end

  %w[12345 union order AbcX9].each do |synthetic_alias|
    context "with synthetic alias #{synthetic_alias}" do
      let(:alias_token) { synthetic_alias }

      it 'uses an identifier-quoted derived-table name' do
        mod.run

        expected = record.fetch('sorting').delete_suffix(record.fetch('alias') + ')') + "`#{alias_token}`)"
        expect(requests.last.fetch('vars_post').fetch('sorting')).to eq(expected)
      end
    end
  end

  it 'keeps the time-based engine and hexadecimal string option' do
    mod.run

    expect(factories).to eq([{ dbms: Msf::Exploit::SQLi::MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true } }])
  end

  it 'keeps the native nonce, directory and public AJAX operation' do
    mod.run

    expect(requests.last.slice('method', 'uri', 'vars_post')).to include(
      'method' => 'POST',
      'uri' => '/wp-admin/admin-ajax.php',
      'vars_post' => include('action' => 'um_get_members', 'nonce' => capture.fetch('nonce'), 'directory_id' => capture.fetch('directory_hash'))
    )
  end

  it 'joins the actual subdirectory to the public AJAX route' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    mod.run

    expect(requests.last.fetch('uri')).to eq('/wordpress/wp-admin/admin-ajax.php')
  end

  it 'passes the same engine and requested count to credential gathering' do
    mod.datastore['COUNT'] = 2
    mod.run

    expect([initialized, gathered]).to eq([[sqli], [2]])
  end

  it 'retains a fresh randomized alias for each callback invocation' do
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(5).and_return('982E2', '6e5W2')
    allow(sqli).to receive(:test_vulnerable) do
      callbacks.last.call(payload)
      callbacks.last.call(payload)
      true
    end
    mod.run

    expect(requests.map { |request| request.fetch('vars_post').fetch('sorting')[/`([^`]+)`\)\z/, 1] }).to eq(%w[982E2 6e5W2])
  end

  context 'with a zero scalar' do
    let(:scalar_magnitude) { 0 }

    it 'keeps the scalar and captured data-dependent condition unchanged' do
      mod.run

      expect(requests.last.fetch('vars_post').fetch('sorting')).to eq("user_login AND (SELECT 0 FROM (SELECT(#{payload}))`#{alias_token}`)")
    end
  end

  context 'when the HTTP request receives no response' do
    let(:http_response) { nil }

    it 'preserves the unreachable failure before gathering credentials' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /unreachable: Connection failed/)
      expect([initialized, gathered]).to eq([[], []])
    end
  end

  context 'when the SQLi test refuses the target' do
    let(:injection_vulnerable) { false }

    it 'preserves the not-vulnerable failure before gathering credentials' do
      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /not-vulnerable: Target is not vulnerable/)
      expect([initialized, gathered]).to eq([[], []])
    end
  end
end
