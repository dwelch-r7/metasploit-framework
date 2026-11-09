require 'rspec'
require 'json'

RSpec.describe 'CouchDB user creation acknowledgement' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/couchdb/couchdb_enum')
  end

  # Native original CouchDB 1.6.1 response, captured November 9, 2026:
  # couchdb@sha256:03f65e23bd3155bca91fc51e04b9b231e54ea5505e8820bb3928dc38d08077d3
  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/couchdb/create_user_response.json'))) }
  let(:username) { 'native_creation_capture' }
  let(:password) { 'fixture-create-password' }
  let(:response) { captured_response(capture) }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['HttpUsername'] = username
    mod.datastore['HttpPassword'] = password
    mod.datastore['ROLES'] = '_admin'
    allow(mod).to receive(:send_request_cgi).and_return(response)
    allow(mod).to receive(:create_credential_and_login)
    allow(mod).to receive(:myworkspace_id).and_return(nil)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:elog)
  end

  it 'accepts the native HTTP 201 acknowledgement without claiming failure' do
    mod.create_user

    expect(mod).to have_received(:print_good).with(a_string_including("User #{username} created"))
    expect(mod).not_to have_received(:print_error)
  end

  it 'records creation proof without claiming an authenticated login' do
    mod.create_user

    expect(mod).to have_received(:create_credential_and_login).with(hash_including(
      address: '192.0.2.1', port: 5984, protocol: 'tcp', service_name: 'couchdb',
      origin_type: :service, module_fullname: mod.fullname, username: username,
      private_type: :password, private_data: password,
      status: Metasploit::Model::Login::Status::UNTRIED, proof: response.body
    ))
  end

  it 'uses the registered HTTP timeout instead of an unregistered nil override' do
    mod.create_user

    expect(mod).to have_received(:send_request_cgi).with(hash_including('method' => 'PUT'))
  end

  context 'with HTTP 200 compatibility status' do
    # Synthetic status variant of the actual acknowledgement.
    let(:response) { captured_response(capture.merge('code' => 200)) }

    it 'accepts the same successful document acknowledgement' do
      mod.create_user

      expect(mod).to have_received(:print_good).with(a_string_including("User #{username} created"))
    end
  end

  [
    ['an unsuccessful operation', { 'ok' => false, 'id' => 'org.couchdb.user:native_creation_capture' }],
    ['a missing operation acknowledgement', {}],
    ['another document', { 'ok' => true, 'id' => 'org.couchdb.user:another-user' }],
    ['an array', []],
    ['null', nil]
  ].each do |description, document|
    context "with #{description}" do
      # Synthetic error/parser boundaries, not additional native captures.
      let(:response) { captured_response(capture.merge('code' => 200, 'body' => JSON.generate(document))) }

      it 'does not report or record successful account creation' do
        mod.create_user
        expect(mod).not_to have_received(:print_good)
        expect(mod).not_to have_received(:create_credential_and_login)
      end
    end
  end

  context 'with malformed JSON' do
    let(:response) { captured_response(capture.merge('code' => 201, 'body' => '{invalid')) }

    it 'rejects the response without recording credentials' do
      mod.create_user
      expect(mod).not_to have_received(:create_credential_and_login)
    end
  end

  [202, 401, 403, 409, 500].each do |code|
    context "with HTTP #{code}" do
      let(:response) { captured_response(capture.merge('code' => code)) }

      it 'does not claim completed account creation' do
        mod.create_user
        expect(mod).not_to have_received(:create_credential_and_login)
      end
    end
  end

  context 'without a response' do
    let(:response) { nil }

    it 'identifies the failed operation without reporting success' do
      mod.create_user
      expect(mod).to have_received(:print_error).with(a_string_including('create CouchDB user'))
    end
  end

  context 'with a failed connection' do
    before { allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionRefused) }

    it 'retains developer context without reporting success' do
      mod.create_user
      expect(mod).to have_received(:elog).with('CouchDB user creation request failed', error: an_instance_of(Rex::ConnectionRefused))
    end
  end

  context 'with punctuation in operator-provided values' do
    let(:username) { 'native user"name' }
    let(:password) { "quoted-\"password\\value\n" }
    let(:response) { nil }

    it 'encodes each string while preserving the duplicate-role vulnerability request' do
      mod.create_user

      expect(mod).to have_received(:send_request_cgi) do |request, _timeout|
        body = request.fetch('data')
        expect(JSON.parse(body).slice('name', 'password', 'roles')).to eq('name' => username, 'password' => password, 'roles' => [])
        expect(body.scan(/"roles"\s*:/).length).to eq(2)
        expect(body).to include('"roles":["_admin"]')
        expect(request.fetch('uri')).to eq('/_users/org.couchdb.user:native%20user%22name')
      end
    end
  end

  def captured_response(capture)
    result = Rex::Proto::Http::Response.new(capture.fetch('code'))
    result.headers['Content-Type'] = 'application/json'
    result.body = capture.fetch('body')
    result
  end
end
