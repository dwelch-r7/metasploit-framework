require 'rspec'
require 'msfenv'
require 'msf/base'
require 'json'
require 'uri'

RSpec.describe 'Ultimate Member nonce discovery' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('ULTIMATE_MEMBER_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_ultimate_member_sorting_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:capture) do
    JSON.parse(File.read(File.join(__dir__, '../../../../file_fixtures/modules/auxiliary/scanner/http/wp_ultimate_member_sorting_sqli/nonce.json')))
  end
  let(:nonce) { capture.fetch('nonce') }
  let(:requests) { [] }
  let(:responses) { [registration] }
  let(:registration) { response_from_capture('registration') }
  let(:redirect) { response_from_capture('redirect') }
  let(:missing_nonce) { response_from_capture('negative_json') }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 8080, 'VHOST' => 'module-target.test', 'SSL' => false, 'TARGETURI' => '/', 'PAGE_ID_MIN' => 11, 'PAGE_ID_MAX' => 11)
    allow(mod).to receive(:framework).and_return(framework)
    %i[print_status print_good print_error print_warning vprint_status].each { |method| allow(mod).to receive(method) }
    allow(mod).to receive(:elog)
    allow(mod).to receive(:send_request_cgi) do |options, *_arguments|
      requests << options.deep_dup
      result = responses.shift
      raise result if result.is_a?(Exception)

      result
    end
  end

  # These tests execute the real nonce method and HttpClient redirect normalizer
  # over explicit HTTP/Framework/UI doubles. The selected native script, redirect
  # and negative JSON bytes are captured verbatim; redirect destinations and
  # malformed nonce variants below are synthetic unit inputs. No network,
  # WordPress installation, SQL or credential persistence is exercised here.

  it 'retrieves the complete nonce from the captured direct page' do
    expect(mod.get_nonce).to eq(nonce)
  end

  it 'keeps accepting a nonce script on a not-found page' do
    registration.code = 404

    expect(mod.get_nonce).to eq(nonce)
  end

  context 'with the captured canonical redirect' do
    let(:responses) { [redirect, registration] }

    it 'retrieves the nonce from the redirected registration page' do
      expect(mod.get_nonce).to eq(nonce)
    end

    it 'keeps the configured connection authority when WordPress omits its port' do
      mod.get_nonce

      expect(requests.last.values_at('uri', 'rhost', 'rport', 'vhost', 'SSL')).to eq(['/register/', '192.0.2.10', 8080, 'module-target.test', false])
    end

    it 'clears the old page query when following the pretty URL' do
      mod.get_nonce

      expect(requests.last.values_at('vars_get', 'query')).to eq([{}, ''])
    end
  end

  context 'with a relative redirect' do
    let(:responses) { [redirect_to('/register/'), registration] }

    it 'retrieves the nonce without changing the target authority' do
      expect(mod.get_nonce).to eq(nonce)
    end
  end

  context 'with a subdirectory and relative redirect' do
    let(:responses) { [redirect_to('register/'), registration] }

    it 'resolves the path against the actual installation base' do
      mod.datastore['TARGETURI'] = '/wordpress/'
      mod.get_nonce

      expect(requests.last.fetch('uri')).to eq('/wordpress/register/')
    end
  end

  context 'with an absolute subdirectory redirect' do
    let(:responses) { [redirect_to('http://module-target.test/wordpress/register/?stage=one'), registration] }

    it 'preserves the redirected path and query on the configured endpoint' do
      mod.datastore['TARGETURI'] = '/wordpress/'
      mod.get_nonce

      expect(requests.last.values_at('uri', 'query', 'rport')).to eq(['/wordpress/register/', 'stage=one', 8080])
    end
  end

  context 'with the configured explicit port' do
    let(:responses) { [redirect_to('http://module-target.test:8080/register/'), registration] }

    it 'retrieves the nonce on that same target' do
      expect(mod.get_nonce).to eq(nonce)
    end
  end

  context 'with a protocol-relative redirect' do
    let(:responses) { [redirect_to('//module-target.test/register/'), registration] }

    it 'keeps the existing scheme and endpoint' do
      expect(mod.get_nonce).to eq(nonce)
    end
  end

  context 'with a redirect naming the target address' do
    let(:responses) { [redirect_to('http://192.0.2.10/register/'), registration] }

    it 'keeps the operator-selected virtual host' do
      mod.get_nonce

      expect(requests.last.values_at('rhost', 'rport', 'vhost')).to eq(['192.0.2.10', 8080, 'module-target.test'])
    end
  end

  {
    'another host' => 'http://other.example.test/register/',
    'another scheme' => 'https://module-target.test/register/',
    'embedded credentials' => 'http://user:password@module-target.test/register/',
    'another explicit port' => 'http://module-target.test:8181/register/'
  }.each do |description, location|
    context "with a redirect to #{description}" do
      let(:responses) { [redirect_to(location), registration] }

      it 'stops without requesting the destination' do
        expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:/)
        expect(requests.length).to eq(1)
      end
    end
  end

  context 'with a redirect cycle' do
    let(:responses) { Array.new(5) { redirect_to('/register/') } }

    it 'bounds the redirected requests and reports missing nonce' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:/)
      expect(requests.length).to be <= 4
    end
  end

  context 'with three redirects followed by a page' do
    let(:responses) { [redirect_to('/one/'), redirect_to('/two/'), redirect_to('/register/'), registration] }

    it 'retrieves the nonce within the bounded chain' do
      expect(mod.get_nonce).to eq(nonce)
    end
  end

  context 'with a malformed redirect URI' do
    let(:responses) { [redirect_to('http://[invalid')] }

    it 'reports the missing nonce without a parser exception' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:/)
    end
  end

  context 'with the captured JSON response that has no nonce script' do
    let(:responses) { [missing_nonce] }

    it 'reports a reasoned not-found failure' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:.*nonce/i)
    end
  end

  context 'with an empty nonce value' do
    it 'reports a reasoned not-found failure' do
      registration.body = registration.body.sub(nonce, '')

      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:.*nonce/i)
    end
  end

  context 'with a whitespace nonce value' do
    it 'reports a reasoned not-found failure' do
      registration.body = registration.body.sub(nonce, '   ')

      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:.*nonce/i)
    end
  end

  context 'when the target gives no response' do
    let(:responses) { [nil] }

    it 'reports an unreachable failure' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /unreachable:.*nonce/i)
    end
  end

  context 'when the connection is refused' do
    let(:responses) { [Rex::ConnectionRefused.new] }

    it 'reports an unreachable failure without a raw connection exception' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /unreachable:.*nonce/i)
    end
  end

  context 'when a redirected request gives no response' do
    let(:responses) { [redirect, nil] }

    it 'reports an unreachable failure' do
      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /unreachable:.*nonce/i)
    end
  end

  context 'with the first page missing its nonce' do
    let(:responses) { [missing_nonce, registration] }

    it 'continues through the configured inclusive page range' do
      mod.datastore['PAGE_ID_MAX'] = 12
      mod.get_nonce

      expect(requests.map { |request| page_id(request) }).to eq(%w[11 12])
    end
  end

  context 'with a connection failure on the first page' do
    let(:responses) { [Rex::ConnectionRefused.new, registration] }

    it 'continues through the configured page range' do
      mod.datastore['PAGE_ID_MAX'] = 12

      expect(mod.get_nonce).to eq(nonce)
    end
  end

  context 'with mixed responses and missing nonce' do
    let(:responses) { [missing_nonce, nil] }

    it 'reports not-found when a page did respond' do
      mod.datastore['PAGE_ID_MAX'] = 12

      expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /not-found:/)
    end
  end

  it 'does not retain a nonce between separate calls' do
    expect(mod.get_nonce).to eq(nonce)
    expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /unreachable:/)
  end

  it 'rejects an inverted page range before making a request' do
    mod.datastore.merge!('PAGE_ID_MIN' => 12, 'PAGE_ID_MAX' => 11)

    expect { mod.get_nonce }.to raise_error(Msf::Auxiliary::Failed, /bad-config:.*PAGE_ID_MIN/)
    expect(requests).to eq([])
  end

  def response_from_capture(name)
    row = capture.fetch(name)
    response = Rex::Proto::Http::Response.new(row.fetch('status'))
    row.fetch('headers').each { |key, values| response.headers[key] = values.join(', ') }
    response.body = row[name == 'registration' ? 'script' : 'body']
    response
  end

  def redirect_to(location)
    response_from_capture('redirect').tap { |response| response.headers['Location'] = location }
  end

  def page_id(request)
    request.fetch('vars_get', {})['page_id']&.to_s || URI.decode_www_form(URI.parse(request.fetch('uri')).query.to_s).to_h.fetch('page_id')
  end
end
