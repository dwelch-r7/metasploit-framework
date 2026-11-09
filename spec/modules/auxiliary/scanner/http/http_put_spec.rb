require 'rspec'
require 'json'

RSpec.describe 'HTTP PUT and DELETE verification' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/http_put') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/http_put/responses.json'))).fetch('responses') }
  let(:data) { captures.fetch('literal_get').fetch('body') }
  let(:readback) { captured_response('literal_get') }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['RPORT'] = 80
    mod.datastore['PATH'] = '/dav/'
    mod.datastore['FILENAME'] = 'proof.txt'
    mod.datastore['FILEDATA'] = data
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_error)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:report_vuln)
  end

  describe '#file_exists' do
    before { allow(mod).to receive(:send_request_cgi).and_return(readback) }

    it 'finds the literal native file content containing regular-expression characters' do
      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1')).to be(true)
    end

    it 'finds the actual multiline file content including its backslash' do
      reply = captured_response('multiline_get')
      allow(mod).to receive(:send_request_cgi).and_return(reply)

      expect(mod.file_exists('/dav/proof.txt', reply.body, '192.0.2.1')).to be(true)
    end

    it 'treats an unmatched bracket as ordinary file text' do
      expect(mod.file_exists('/dav/proof.txt', '[', '192.0.2.1')).to be(true)
    end

    it 'rejects different actual file content' do
      expect(mod.file_exists('/dav/proof.txt', 'different-content', '192.0.2.1')).to be(false)
    end

    it 'does not use the native Server header as file content' do
      reply = captured_response('literal_get')
      allow(mod).to receive(:send_request_cgi).and_return(reply)

      expect(mod.file_exists('/dav/proof.txt', reply.headers['Server'].split.first, '192.0.2.1')).to be(false)
    end

    it 'does not accept the actual 404 error-page body as an uploaded file' do
      allow(mod).to receive(:send_request_cgi).and_return(captured_response('missing_get'))

      expect(mod.file_exists('/plain/missing.txt', 'Not Found', '192.0.2.1')).to be(false)
    end

    it 'returns unknown when the server does not respond' do
      allow(mod).to receive(:send_request_cgi).and_return(nil)

      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1')).to be_nil
    end

    it 'returns unknown for the native unauthorized response' do
      allow(mod).to receive(:send_request_cgi).and_return(captured_response('unauthorized_get'))

      expect(mod.file_exists('/auth/existing.txt', data, '192.0.2.1')).to be_nil
    end

    it 'accepts an actual empty successful body when empty content was requested' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, ''))

      expect(mod.file_exists('/dav/empty.txt', '', '192.0.2.1')).to be(true)
    end

    it 'does not treat nonempty content as the requested empty file' do
      expect(mod.file_exists('/dav/empty.txt', '', '192.0.2.1')).to be(false)
    end

    it 'handles nil requested content as an empty upload' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, ''))

      expect(mod.file_exists('/dav/empty.txt', nil, '192.0.2.1')).to be(true)
    end

    it 'handles a nil successful response body without matching nonempty data' do
      reply = response(200, '')
      allow(reply).to receive(:body).and_return(nil)
      allow(mod).to receive(:send_request_cgi).and_return(reply)

      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1')).to be(false)
    end

    it 'compares identical UTF-8 bytes despite different encoding labels' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, "\xc3\xa9".b))

      expect(mod.file_exists('/dav/proof.txt', "\xc3\xa9", '192.0.2.1')).to be(true)
    end

    it 'compares arbitrary uploaded bytes without interpreting their encoding' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, "\x00\xff".b))

      expect(mod.file_exists('/dav/proof.txt', "\x00\xff", '192.0.2.1')).to be(true)
    end

    it 'detects a remaining successful file independently of its changed contents' do
      allow(mod).to receive(:send_request_cgi).and_return(response(200, 'changed-content'))

      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1', verify_contents: false)).to be(true)
    end

    it 'accepts an explicit Gone response as absence' do
      allow(mod).to receive(:send_request_cgi).and_return(response(410, 'Gone'))

      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1', verify_contents: false)).to be(false)
    end

    it 'keeps a connection failure unknown' do
      allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionRefused)

      expect(mod.file_exists('/dav/proof.txt', data, '192.0.2.1')).to be_nil
    end
  end

  describe '#run_host' do
    let(:data) { captures.fetch('existing_get').fetch('body') }
    let(:action_name) { 'PUT' }
    let(:mutation_response) { captured_response('put_created') }
    let(:readbacks) { [captured_response('existing_get')] }
    let(:requests) { [] }

    before do
      allow(mod).to receive(:action).and_return(double(name: action_name))
      allow(mod).to receive(:send_request_cgi) do |request, *_arguments|
        requests << request
        request.fetch('method') == 'GET' ? readbacks.shift : mutation_response
      end
    end

    it 'reports successful creation backed by real content' do
      mod.run_host('192.0.2.1')

      expect(mod).to have_received(:print_good).with('File uploaded: http://192.0.2.1:80/dav/proof.txt')
    end

    it 'does not report a denied write even when a matching file already exists' do
      allow(mod).to receive(:send_request_cgi).and_return(captured_response('forbidden_put'), captured_response('existing_get'))
      mod.datastore['FILEDATA'] = captures.fetch('existing_get').fetch('body')

      mod.run_host('192.0.2.1')

      expect(mod).not_to have_received(:report_vuln)
    end

    it 'uses an explicit extensionless filename for both upload and verification' do
      mod.datastore['FILENAME'] = 'module-target-extensionless'

      mod.run_host('192.0.2.1')

      expect(requests.map { |request| request.fetch('uri') }).to eq(['/dav/module-target-extensionless', '/dav/module-target-extensionless'])
    end

    it 'retains generated text filenames when none was supplied' do
      mod.datastore['FILENAME'] = ''
      allow(Rex::Text).to receive(:rand_text_alpha).with(5).and_return('proof')

      mod.run_host('192.0.2.1')

      expect(requests.map { |request| request.fetch('uri') }).to eq(['/dav/proof.txt', '/dav/proof.txt'])
    end

    context 'with an empty upload and no verification response' do
      let(:data) { '' }
      let(:readbacks) { [nil] }

      it 'does not claim a successful empty upload' do
        mod.run_host('192.0.2.1')

        expect(mod).not_to have_received(:report_vuln)
      end
    end

    context 'when deleting' do
      let(:action_name) { 'DELETE' }
      let(:mutation_response) { captured_response('delete_success') }
      let(:readbacks) { [captured_response('existing_get'), captured_response('missing_get')] }

      it 'deletes an explicit extensionless filename after verifying its content' do
        mod.datastore['FILENAME'] = 'module-target-extensionless'

        mod.run_host('192.0.2.1')

        expect(mod).to have_received(:print_good).with('File deleted: http://192.0.2.1:80/dav/module-target-extensionless')
      end

      it 'does not delete without a filename' do
        mod.datastore['FILENAME'] = ''

        mod.run_host('192.0.2.1')

        expect(requests).to be_empty
      end

      context 'when initial verification is unknown' do
        let(:readbacks) { [nil] }

        it 'does not send DELETE' do
          mod.run_host('192.0.2.1')

          expect(requests.map { |request| request.fetch('method') }).to eq(['GET'])
        end
      end

      context 'when the initial content differs' do
        let(:readbacks) { [response(200, 'different-content')] }

        it 'preserves the expected-content guard' do
          mod.run_host('192.0.2.1')

          expect(requests.map { |request| request.fetch('method') }).to eq(['GET'])
        end
      end

      context 'when the file is already missing' do
        let(:readbacks) { [captured_response('missing_get')] }

        it 'does not send DELETE' do
          mod.run_host('192.0.2.1')

          expect(requests.map { |request| request.fetch('method') }).to eq(['GET'])
        end
      end

      context 'when final verification does not respond' do
        let(:readbacks) { [captured_response('existing_get'), nil] }

        it 'does not report successful deletion' do
          mod.run_host('192.0.2.1')

          expect(mod).not_to have_received(:report_vuln)
        end
      end

      context 'when final verification returns different content' do
        let(:readbacks) { [captured_response('existing_get'), response(200, 'changed-content')] }

        it 'does not report successful deletion of a remaining file' do
          mod.run_host('192.0.2.1')

          expect(mod).not_to have_received(:report_vuln)
        end
      end

      context 'when final verification is unauthorized' do
        let(:readbacks) { [captured_response('existing_get'), captured_response('unauthorized_get')] }

        it 'does not report successful deletion from an unreadable response' do
          mod.run_host('192.0.2.1')

          expect(mod).not_to have_received(:report_vuln)
        end
      end

      context 'when DELETE is denied' do
        let(:mutation_response) { captured_response('forbidden_put') }

        it 'does not report successful deletion even if a later GET is missing' do
          mod.run_host('192.0.2.1')

          expect(mod).not_to have_received(:report_vuln)
        end
      end
    end
  end

  def captured_response(name)
    capture = captures.fetch(name)
    reply = response(capture.fetch('status'), capture.fetch('body'))
    capture.fetch('headers').each { |key, value| reply.headers[key] = value.join(', ') }
    reply
  end

  def response(code, body)
    Rex::Proto::Http::Response.new(code).tap { |reply| reply.body = body }
  end
end
