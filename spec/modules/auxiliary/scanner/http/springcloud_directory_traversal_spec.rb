require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Spring Cloud Config resource collection contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/http/springcloud_directory_traversal.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:captures) { JSON.parse(File.binread(File.expand_path('../../../../file_fixtures/modules/springcloud/resource_responses.json', __dir__))) }
  let(:record) { captures.fetch('native_files').fetch('secret.properties') }
  let(:filename) { '/lab/proof/secret.properties' }
  let(:expected_target) { '/foo/default/master/%252Flab/proof/secret.properties' }
  let(:requests) { [] }
  let(:loot) { [] }
  let(:messages) { [] }
  let(:resource_response) { captured_response(record) }
  let(:wrong_route_response) { response(400, '', 'application/json') }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['FILEPATH'] = filename
    allow(mod).to receive_messages(print_error: nil, vprint_status: nil)
    allow(mod).to receive(:print_good) { |message| messages << message }
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/loot/captured-file'
    end
    allow(mod).to receive(:send_request_cgi) { |options| deliver(options, cgi: true) }
    allow(mod).to receive(:send_request_raw) { |options| deliver(options, cgi: false) }
  end

  # Response bytes/statuses and the original false-positive JSON are genuine
  # captures with provenance. HTTP delivery and loot persistence are doubled;
  # owner initialization, URI helpers and Rex request serialization are real.
  # Main captures lack response headers; their Content-Type is projected from
  # the separately captured binary route header recorded in the fixture.

  def response(status, body, content_type)
    Rex::Proto::Http::Response.new(status).tap do |result|
      result.body = body
      result.headers['Content-Type'] = content_type if content_type
    end
  end

  def captured_response(capture)
    response(capture.fetch('status'), [capture.fetch('body_hex')].pack('H*'), captures.fetch('binary_content_type'))
  end

  def deliver(options, cgi:)
    wire = Rex::Proto::Http::ClientRequest.new(options.merge('vhost' => '192.0.2.1', 'cgi' => cgi)).to_s.b
    target = wire.lines.first.split(' ')[1]
    requests << { options: options, wire: wire, target: target }
    if (directory = ENV['SPRINGCLOUD_UNIT_EVIDENCE'])
      name = RSpec.current_example.metadata.fetch(:scoped_id).tr(':', '_')
      File.write(File.join(directory, name + '.json'), JSON.pretty_generate(target: target, wire_hex: wire.unpack1('H*')))
    end
    return wrong_route_response unless target == expected_target && wire.include?("Accept: application/octet-stream\r\n")

    resource_response
  end

  describe 'captured file bytes' do
    it 'collects the exact properties file through the resource endpoint' do
      mod.run_host('192.0.2.1')

      expect(loot.first&.fetch(3)).to eq([record.fetch('body_hex')].pack('H*'))
    end

    context 'with the native root-level file' do
      let(:record) { captures.fetch('root_file') }
      let(:filename) { '/springcloud-proof.txt' }
      let(:expected_target) { '/foo/default/master/%252Fspringcloud-proof.txt' }

      it 'collects exact bytes through the unambiguous explicit-label route' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq([record.fetch('body_hex')].pack('H*'))
      end
    end

    context 'with plain text' do
      let(:record) { captures.fetch('native_files').fetch('plain.txt') }
      let(:filename) { '/lab/proof/plain.txt' }
      let(:expected_target) { '/foo/default/master/%252Flab/proof/plain.txt' }

      it 'collects every captured byte' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq([record.fetch('body_hex')].pack('H*'))
      end
    end

    context 'with a space and UTF-8 filename' do
      let(:record) { captures.fetch('native_files').fetch('sp%20ace-%CE%A9.txt') }
      let(:filename) { '/lab/proof/sp ace-Ω.txt' }
      let(:expected_target) { '/foo/default/master/%252Flab/proof/sp%20ace-%ce%a9.txt' }

      it 'emits the encoded target through the real Rex request serializer' do
        mod.run_host('192.0.2.1')

        expect(requests.first.fetch(:target)).to eq(expected_target)
      end

      it 'preserves the captured UTF-8 file bytes' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq([record.fetch('body_hex')].pack('H*'))
      end
    end

    context 'with a binary file' do
      let(:record) { captures.fetch('native_files').fetch('binary.bin') }
      let(:filename) { '/lab/proof/binary.bin' }
      let(:expected_target) { '/foo/default/master/%252Flab/proof/binary.bin' }

      it 'preserves the genuine all-256-octet response' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq([record.fetch('body_hex')].pack('H*'))
      end

      it 'records the loot as binary data' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(1)).to eq('application/octet-stream')
      end
    end

    context 'with an empty file' do
      let(:record) { captures.fetch('native_files').fetch('empty.txt') }
      let(:filename) { '/lab/proof/empty.txt' }
      let(:expected_target) { '/foo/default/master/%252Flab/proof/empty.txt' }

      it 'stores the successful zero-byte resource' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq(''.b)
      end
    end
  end

  describe 'request compatibility' do
    it 'preserves a context prefix' do
      mod.datastore['TARGETURI'] = '/config/'
      mod.run_host('192.0.2.1')

      expect(requests.first.fetch(:target)).to eq('/config/foo/default/master/%252Flab/proof/secret.properties')
    end

    it 'uses explicit application and profile selectors' do
      mod.datastore['APPLICATION'] = 'billing'
      mod.datastore['PROFILE'] = 'production'
      mod.run_host('192.0.2.1')

      expect(requests.first.fetch(:target)).to eq('/billing/production/master/%252Flab/proof/secret.properties')
    end

    it 'uses the operator repository label' do
      mod.datastore['LABEL'] = 'main'
      mod.run_host('192.0.2.1')

      expect(requests.first.fetch(:target)).to eq('/foo/default/main/%252Flab/proof/secret.properties')
    end

    it 'URI-encodes a literal quote in the filepath' do
      mod.datastore['FILEPATH'] = '/lab/proof/quote"name.txt'
      mod.run_host('192.0.2.1')

      expect(requests.first.fetch(:target)).to eq('/foo/default/master/%252Flab/proof/quote%22name.txt')
    end

    it 'retains DEPTH without adding a rejected parent-directory prefix' do
      mod.datastore['DEPTH'] = 37
      mod.run_host('192.0.2.1')

      expect(requests.first.fetch(:target)).to eq(expected_target)
    end

    it 'keeps the operator filepath and depth unchanged' do
      mod.run_host('192.0.2.1')

      expect([mod.datastore['FILEPATH'], mod.datastore['DEPTH'], mod.datastore['RPORT']]).to eq([filename, 11, 8888])
    end

    it 'does not request a relative filepath' do
      mod.datastore['FILEPATH'] = 'lab/proof/secret.properties'
      mod.run_host('192.0.2.1')

      expect(requests).to be_empty
    end

    it 'does not allow a selector to change the resource route structure' do
      mod.datastore['APPLICATION'] = 'wrong/route'
      mod.run_host('192.0.2.1')

      expect(requests).to be_empty
    end
  end

  describe 'response boundaries' do
    context 'with a genuinely absent file' do
      let(:record) { captures.fetch('native_files').fetch('missing.txt') }
      let(:filename) { '/lab/proof/missing.txt' }
      let(:expected_target) { '/foo/default/master/%252Flab/proof/missing.txt' }

      it 'does not create loot' do
        mod.run_host('192.0.2.1')

        expect(loot).to be_empty
      end

      context 'when the old environment route returns genuine ordinary config JSON' do
        let(:wrong_route_response) do
          capture = captures.fetch('old_environment_route')
          response(capture.fetch('status'), capture.fetch('body'), capture.fetch('headers').fetch('Content-Type'))
        end

        it 'does not mistake that HTTP200 for file collection' do
          mod.run_host('192.0.2.1')

          expect(loot).to be_empty
        end
      end
    end

    context 'without a response' do
      let(:resource_response) { nil }

      it 'does not create loot' do
        mod.run_host('192.0.2.1')

        expect(loot).to be_empty
      end
    end

    context 'with an authorization error' do
      let(:resource_response) { response(403, 'Forbidden', 'text/html') }

      it 'does not create loot' do
        mod.run_host('192.0.2.1')

        expect(loot).to be_empty
      end
    end

    context 'with an internal server error' do
      let(:resource_response) { response(500, 'Failure', 'application/octet-stream') }

      it 'does not create loot' do
        mod.run_host('192.0.2.1')

        expect(loot).to be_empty
      end
    end

    context 'with a nullable successful body' do
      let(:resource_response) { response(200, nil, 'application/octet-stream') }

      it 'does not raise or claim a download' do
        mod.run_host('192.0.2.1')

        expect(messages).to be_empty
      end
    end

    context 'with an ordinary JSON response at the requested URI' do
      let(:resource_response) { response(200, captures.fetch('old_environment_route').fetch('body'), 'application/json') }

      it 'does not create loot' do
        mod.run_host('192.0.2.1')

        expect(loot).to be_empty
      end
    end

    context 'with legitimate JSON file bytes' do
      let(:resource_response) { response(200, captures.fetch('old_environment_route').fetch('body'), 'application/octet-stream') }

      it 'does not reject file bytes because they happen to contain JSON' do
        mod.run_host('192.0.2.1')

        expect(loot.first&.fetch(3)).to eq(captures.fetch('old_environment_route').fetch('body').b)
      end
    end
  end
end
