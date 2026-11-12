require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Strapi reset request and reporting contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/http/strapi_3_password_reset.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:api) { JSON.parse(File.binread(File.expand_path('../../../../file_fixtures/modules/strapi/api_responses.json', __dir__))) }
  let(:password) { 'ModulePendingPassword0!' }
  let(:requests) { [] }
  let(:credentials) { [] }
  let(:good_messages) { [] }
  let(:init_response) { captured_response(api.fetch('affected_init')) }
  let(:reset_response) { captured_response(api.fetch('reset_success')) }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['RPORT'] = 1337
    mod.datastore['NEW_PASSWORD'] = password
    allow(mod).to receive_messages(myworkspace_id: 1, print_status: nil, print_error: nil, elog: nil)
    allow(mod).to receive(:print_good) { |message| good_messages << message }
    allow(mod).to receive(:create_credential) { |data| credentials << data }
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      options.fetch('uri').end_with?('/admin/init') ? init_response : reset_response
    end
  end

  # Genuine native/API projections and exact public complex password are in the
  # fixture with provenance. Owner init, JSON parsing/generation, Rex requests,
  # scanner capability/check wrapper and version objects remain real. HTTP and
  # credential persistence/UI are doubles; no Framework, database or target.

  def captured_response(record)
    response(record.fetch('status'), record.fetch('body').to_json)
  end

  def response(status, body)
    Rex::Proto::Http::Response.new(status).tap { |result| result.body = body }
  end

  def init_with_version(version)
    body = api.fetch('affected_init').fetch('body')
    body.fetch('data')['strapiVersion'] = version
    response(200, body.to_json)
  end

  def serialized_reset
    options = requests.find { |request| request['method'] == 'POST' }
    wire = Rex::Proto::Http::ClientRequest.new(options.merge('vhost' => '192.0.2.1')).to_s.b
    headers, body = wire.split("\r\n\r\n".b, 2)
    length = headers[/^Content-Length:\s*(\d+)/i, 1].to_i
    if (directory = ENV['STRAPI_UNIT_EVIDENCE'])
      record = {
        declared_length: length, body_bytesize: body.bytesize, data_length: options.fetch('data').length,
        data_encoding: options.fetch('data').encoding.name, wire_hex: wire.unpack1('H*'), body_hex: body.unpack1('H*')
      }
      File.write(File.join(directory, RSpec.current_example.metadata.fetch(:scoped_id).tr(':', '_') + '.json'), JSON.pretty_generate(record))
    end
    { declared_length: length, body: body }
  end

  describe 'passive scanner check capability' do
    it 'exposes the intended check through the scanner capability API' do
      expect(mod.has_check?).to be(true)
    end

    it 'returns Appears for the native-proven affected version' do
      expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Appears.code)
    end

    context 'with the native fixed response' do
      let(:init_response) { captured_response(api.fetch('fixed_init')) }

      it 'returns Safe for beta17.5' do
        expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Safe.code)
      end
    end

    context 'with an earlier unqualified beta' do
      let(:init_response) { init_with_version('3.0.0-beta.17.3') }

      it 'returns Detected without inventing a native-qualified minimum' do
        expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Detected.code)
      end
    end

    context 'without a reported version' do
      let(:init_response) { response(200, '{"data":{}}') }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end

    context 'with invalid JSON' do
      let(:init_response) { response(200, 'not JSON') }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end

    context 'without a response' do
      let(:init_response) { nil }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end

    context 'with an HTTP error' do
      let(:init_response) { response(403, '<html>Forbidden</html>') }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end

    context 'with a malformed version' do
      let(:init_response) { init_with_version('not-a-version') }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end

    context 'with an unexpected data type' do
      let(:init_response) { response(200, '{"data":"unexpected"}') }

      it('returns Unknown') { expect(mod.check.code).to eq(Msf::Exploit::CheckCode::Unknown.code) }
    end
  end

  describe 'reset and credential boundaries' do
    it 'supplies the service protocol required by the real credential API' do
      mod.run

      expect(credentials.first.fetch(:protocol)).to eq('tcp')
    end

    context 'with the exact public Unicode password as binary UTF8 input' do
      let(:password) { api.fetch('complex_password').b }

      it 'declares the number of octets emitted by the real Rex serializer' do
        mod.run
        wire = serialized_reset

        expect(wire.fetch(:declared_length)).to eq(wire.fetch(:body).bytesize)
      end

      it 'preserves both password fields when the server honors Content-Length' do
        mod.run
        wire = serialized_reset
        body = JSON.parse(wire.fetch(:body).byteslice(0, wire.fetch(:declared_length)))

        expect(body.values_at('password', 'passwordConfirmation')).to eq([api.fetch('complex_password')] * 2)
      end

      it 'keeps datastore bytes and encoding unchanged' do
        original = mod.datastore['NEW_PASSWORD']
        before = [original.object_id, original.encoding, original.bytes]
        mod.run

        expect([mod.datastore['NEW_PASSWORD'].object_id, original.encoding, original.bytes]).to eq(before)
      end
    end

    context 'without a reset response' do
      let(:reset_response) { nil }

      it 'does not report credentials' do
        mod.run

        expect(credentials).to eq([])
      end
    end

    context 'with the genuine token-refused response' do
      let(:reset_response) { captured_response(api.fetch('reset_refused')) }

      it 'does not report credentials' do
        mod.run

        expect(credentials).to eq([])
      end
    end

    context 'with invalid reset JSON' do
      let(:reset_response) { response(200, 'not JSON') }

      it 'does not report credentials' do
        mod.run

        expect(credentials).to eq([])
      end
    end

    context 'without a valid user in a successful response' do
      let(:reset_response) { response(200, '{"user":null}') }

      it 'does not raise or claim success' do
        expect { mod.run }.not_to raise_error

        expect([credentials, good_messages]).to eq([[], []])
      end
    end

    context 'with invalid UTF8 input' do
      let(:password) { "invalid\xff".b }

      it 'refuses the input without an encoder exception or request' do
        expect { mod.run }.not_to raise_error

        expect(requests).to eq([])
      end
    end
  end
end
