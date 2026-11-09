require 'rspec'
require 'json'

RSpec.describe 'CouchDB Login Utility' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/couchdb/couchdb_login')
  end

  # Native HTTP captures from the public Docker lab, CouchDB 3.3.1
  # (sha256:04d9b3ef9406112a9903484fbbaf1497e1b5fce892bd214e1135565ab97aa48b)
  # and real Apache 2.4.62 with FallbackResource, November 9, 2026.
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/couchdb/login_responses.json'))) }
  let(:username) { 'labadmin' }
  let(:password) { 'labpassword' }
  let(:session_capture) { 'administrator_session' }
  let(:users_capture) { 'administrator_users' }
  let(:session_response) { captured_response(captures.fetch(session_capture)) }
  let(:users_response) { captured_response(captures.fetch(users_capture)) }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['TARGETURI'] = '/'
    allow(mod).to receive(:send_request_cgi) do |request|
      request.fetch('uri').end_with?('/_session') ? session_response : users_response
    end
    allow(mod).to receive(:report_cred)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:elog)
  end

  describe '#do_login' do
    it 'accepts the native administrator identity' do
      expect(mod.do_login(username, password)).to eq(:next_user)
    end

    it 'records the actual authenticated identity response as proof' do
      mod.do_login(username, password)

      expect(mod).to have_received(:report_cred).with(hash_including(user: username, password: password, proof: session_response.body))
    end

    it 'requests the identity resource under the configured application path' do
      mod.datastore['TARGETURI'] = '/couch/'
      mod.do_login(username, password)

      expect(mod).to have_received(:send_request_cgi).with(hash_including(
        'method' => 'GET', 'uri' => '/couch/_session', 'authorization' => mod.basic_auth(username, password)
      ))
    end

    context 'with a native non-administrator account' do
      let(:username) { 'labreader' }
      let(:password) { 'readerpassword' }
      let(:session_capture) { 'reader_session' }
      let(:users_capture) { 'reader_users' }

      it 'accepts authentication independently of administrator-only database access' do
        expect(mod.do_login(username, password)).to eq(:next_user)
      end
    end

    context 'with a native wrong-password response' do
      let(:session_capture) { 'wrong_session' }
      let(:users_capture) { 'wrong_users' }

      it 'does not report a credential' do
        expect(mod.do_login(username, 'wrong-password')).to eq(:skip_pass)
        expect(mod).not_to have_received(:report_cred)
      end
    end

    context 'with unrelated native HTTP 200 HTML' do
      let(:session_capture) { 'unrelated_session' }
      let(:users_capture) { 'unrelated_session' }

      it 'does not treat success status as authentication' do
        expect(mod.do_login(username, password)).to eq(:skip_pass)
        expect(mod).not_to have_received(:report_cred)
      end
    end

    context 'with the native anonymous user context' do
      let(:session_capture) { 'anonymous_session' }
      let(:users_capture) { 'anonymous_session' }

      it 'does not validate an ignored or unknown identity' do
        expect(mod.do_login(username, password)).to eq(:skip_pass)
      end
    end

    # Synthetic parser/identity boundaries derived from the native response;
    # these variants do not claim additional native server captures.
    [
      ['another identity', { 'ok' => true, 'userCtx' => { 'name' => 'another-user', 'roles' => [] } }],
      ['missing user context', { 'ok' => true }],
      ['invalid user context type', { 'ok' => true, 'userCtx' => 'labadmin' }],
      ['unsuccessful operation', { 'ok' => false, 'userCtx' => { 'name' => 'labadmin' } }],
      ['an array', []],
      ['null', nil]
    ].each do |description, document|
      context "with #{description}" do
        let(:session_response) { captured_response(captures.fetch('administrator_session').merge('body' => JSON.generate(document))) }
        let(:users_response) { session_response }

        it 'does not validate the credential' do
          expect(mod.do_login(username, password)).to eq(:skip_pass)
          expect(mod).not_to have_received(:report_cred)
        end
      end
    end

    [301, 302, 500].each do |code|
      context "with HTTP #{code}" do
        let(:session_response) { captured_response(captures.fetch('administrator_session').merge('code' => code)) }
        let(:users_response) { session_response }

        it 'requires a completed identity response' do
          expect(mod.do_login(username, password)).to eq(:skip_pass)
        end
      end
    end

    context 'when no response arrives' do
      let(:session_response) { nil }
      let(:users_response) { nil }

      it 'aborts this host rather than consuming a nil response' do
        expect(mod.do_login(username, password)).to eq(:abort)
      end
    end

    context 'when the connection fails' do
      before { allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionRefused) }

      it 'aborts the host with developer error context' do
        expect(mod.do_login(username, password)).to eq(:abort)
        expect(mod).to have_received(:elog).with('CouchDB authentication request failed', error: an_instance_of(Rex::ConnectionRefused))
      end
    end
  end

  describe '#run_host' do
    it 'uses the same identity validation for legacy explicit HTTP credentials' do
      mod.datastore['HttpUsername'] = 'labreader'
      mod.datastore['HttpPassword'] = 'readerpassword'
      allow(mod).to receive(:do_login).and_return(:next_user)

      expect(mod.run_host('192.0.2.1')).to be_nil
      expect(mod).to have_received(:do_login).with('labreader', 'readerpassword')
    end

    it 'preserves credential iteration through AuthBrute' do
      allow(mod).to receive(:each_user_pass).and_yield(username, password)
      allow(mod).to receive(:do_login).and_return(:next_user)

      expect(mod.run_host('192.0.2.1')).to be_nil
      expect(mod).to have_received(:do_login).with(username, password)
    end
  end

  describe '#report_cred' do
    it 'marks validated credentials successful and preserves identity proof' do
      allow(mod).to receive(:report_cred).and_call_original
      allow(mod).to receive(:myworkspace_id).and_return(nil)
      core = double('credential core')
      allow(mod).to receive(:create_credential).and_return(core)
      allow(mod).to receive(:create_credential_login)

      mod.report_cred(ip: '192.0.2.1', port: 5984, service_name: 'couchdb', user: username, password: password, proof: session_response.body)

      expect(mod).to have_received(:create_credential_login).with(hash_including(core: core, status: Metasploit::Model::Login::Status::SUCCESSFUL, proof: session_response.body))
    end
  end

  def captured_response(capture)
    response = Rex::Proto::Http::Response.new(capture.fetch('code'))
    capture.fetch('headers').each { |name, value| response.headers[name] = value }
    response.body = capture.fetch('body')
    response
  end
end
