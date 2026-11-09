require 'rspec'
require 'json'

RSpec.describe 'WordPress REST author discovery' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/wordpress_scanner') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/wordpress_scanner/responses.json'))).fetch('responses') }
  let(:host) { '192.0.2.53' }
  let(:reported_logins) { [] }

  before do
    mod.datastore['RHOSTS'] = host
    mod.datastore['TARGETURI'] = '/'
    mod.datastore['THEMES'] = false
    mod.datastore['PLUGINS'] = false
    allow(mod).to receive(:wordpress_and_online?).and_return(true)
    allow(mod).to receive(:wordpress_version).and_return('6.8.3')
    allow(mod).to receive(:rhost).and_return(host)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:create_credential).and_return(nil)
    allow(mod).to receive(:create_credential_login) { |data| reported_logins << data }
  end

  it 'retains the existing pretty REST URL and avoids a second request on success' do
    allow(mod).to receive(:send_request_cgi).and_return(response('pretty_root'))

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with('method' => 'GET', 'uri' => '/wp-json/wp/v2/users').once
  end

  it 'preserves a pretty REST URL under an installation subdirectory' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    allow(mod).to receive(:send_request_cgi).and_return(response('pretty_prefix'))

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with('method' => 'GET', 'uri' => '/wordpress/wp-json/wp/v2/users').once
  end

  it 'tries the native query REST route after the pretty route is absent' do
    allow(mod).to receive(:send_request_cgi).and_return(absent_response, response('query_plain'))

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with('method' => 'GET', 'uri' => '/index.php', 'vars_get' => { 'rest_route' => '/wp/v2/users' }).once
    expect(mod).to have_received(:print_good).with("#{host} - Detected user: Module café author with username: module_author")
  end

  it 'keeps a query-route fallback within the selected installation subdirectory' do
    mod.datastore['TARGETURI'] = '/wordpress/'
    allow(mod).to receive(:send_request_cgi).and_return(absent_response, response('query_plain'))

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with('method' => 'GET', 'uri' => '/wordpress/index.php', 'vars_get' => { 'rest_route' => '/wp/v2/users' }).once
  end

  it 'retains actual captured author data and untried credential reporting' do
    allow(mod).to receive(:send_request_cgi).and_return(response('query_plain'))

    mod.run_host(host)

    expect(mod).to have_received(:create_credential).with(hash_including(username: 'module_author', private_data: '', origin_type: :service, address: host, protocol: 'tcp'))
    expect(reported_logins.map { |data| data.fetch(:status) }).to eq([Metasploit::Model::Login::Status::UNTRIED])
  end

  it 'keeps an actual empty user list empty' do
    allow(mod).to receive(:send_request_cgi).and_return(derived_response([]))

    mod.run_host(host)

    expect(reported_logins).to be_empty
  end

  it 'does not dereference a missing initial response or attempt a fallback' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).once
    expect(mod).to have_received(:print_error).with(/response/i)
  end

  it 'does not dereference a missing fallback response' do
    allow(mod).to receive(:send_request_cgi).and_return(absent_response, nil)

    mod.run_host(host)

    expect(mod).to have_received(:print_error).with(/response/i)
  end

  it 'does not retry an explicit HTTP permission refusal through another route' do
    allow(mod).to receive(:send_request_cgi).and_return(derived_response({}, code: 403))

    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).once
    expect(reported_logins).to be_empty
  end

  it 'does not discover users in a refused fallback response' do
    allow(mod).to receive(:send_request_cgi).and_return(absent_response, response('query_forbidden_context'))

    mod.run_host(host)

    expect(reported_logins).to be_empty
  end

  it 'does not parse genuine unrelated HTML as a user list' do
    allow(mod).to receive(:send_request_cgi).and_return(response('unrelated'))

    mod.run_host(host)

    expect(reported_logins).to be_empty
  end

  it 'does not mistake a genuine individual author object for the REST user list' do
    allow(mod).to receive(:send_request_cgi).and_return(response('single_author'))

    mod.run_host(host)

    expect(reported_logins).to be_empty
  end

  [nil, 17, { 'code' => 'rest_forbidden', 'message' => 'Denied' }, ['module_author']].each do |document|
    it "does not invent users for a derived invalid user document #{document.inspect}" do
      allow(mod).to receive(:send_request_cgi).and_return(derived_response(document))

      mod.run_host(host)

      expect(reported_logins).to be_empty
    end
  end

  [{ 'name' => 'Missing slug' }, { 'name' => 'Blank slug', 'slug' => '' }, { 'name' => nil, 'slug' => 'wrong' }, nil].each do |entry|
    it "ignores a derived malformed entry #{entry.inspect} while retaining the native author" do
      valid = JSON.parse(captures.fetch('pretty_root').fetch('body')).first
      allow(mod).to receive(:send_request_cgi).and_return(derived_response([entry, valid]))

      mod.run_host(host)

      expect(mod).to have_received(:create_credential).once.with(hash_including(username: 'module_author'))
    end
  end

  def response(name)
    capture = captures.fetch(name)
    Rex::Proto::Http::Response.new(capture.fetch('code')).tap do |result|
      result.headers['Content-Type'] = capture.fetch('content_type')
      result.body = capture.fetch('body')
    end
  end

  def absent_response
    response('plain_pretty_missing')
  end

  def derived_response(document, code: 200)
    Rex::Proto::Http::Response.new(code).tap do |result|
      result.headers['Content-Type'] = 'application/json'
      result.body = JSON.generate(document)
    end
  end
end
