require 'rspec'
require 'json'

RSpec.describe 'Elasticsearch memory response contracts' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/elasticsearch_memory_disclosure') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/elasticsearch_memory_disclosure/responses.json'))).fetch('captures') }

  before do
    mod.datastore['RHOSTS'] = '192.0.2.45'
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
  end

  describe 'version detection' do
    it 'recognizes the genuine affected version' do
      allow(mod).to receive(:send_request_cgi).and_return(response('affected-readiness'))

      expect(mod.check_host('192.0.2.45').code).to eq('appears')
    end

    it 'recognizes the genuine fixed version' do
      allow(mod).to receive(:send_request_cgi).and_return(response('fixed-readiness'))

      expect(mod.check_host('192.0.2.45').code).to eq('safe')
    end

    it 'returns Unknown for the genuine nonexistent-path HTTP 404 response' do
      allow(mod).to receive(:send_request_cgi).and_return(response('wrong-path'))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'returns Unknown for the genuine unauthenticated HTTP 401 challenge' do
      allow(mod).to receive(:send_request_cgi).and_return(response('unauthenticated-root'))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'returns Unknown for the genuine limited-account HTTP 403 refusal' do
      allow(mod).to receive(:send_request_cgi).and_return(response('limited-root-forbidden'))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'retains a reason-bearing Unknown result when there is no response' do
      allow(mod).to receive(:send_request_cgi).and_return(nil)

      expect(mod.check_host('192.0.2.45').message).to include('Could not connect')
    end

    it 'does not raise when the native JSON document has no version' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', {}))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'does not dereference a JSON list as a product document' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', ['unrelated']))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'does not dereference a malformed version object' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', 'version' => 'unexpected'))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'does not pass a non-string version to the version parser' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', 'version' => { 'number' => [] }))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    it 'returns Unknown for a malformed version string' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', 'version' => { 'number' => 'invalid-version' }))

      expect(mod.check_host('192.0.2.45').code).to eq('unknown')
    end

    {
      '7.9.9' => 'safe',
      '7.10.0' => 'appears',
      '7.13.3' => 'appears'
    }.each do |number, result|
      it "classifies the explicit version boundary #{number} as #{result}" do
        capture = JSON.parse(captures.fetch('affected-readiness').fetch('body'))
        capture.fetch('version')['number'] = number
        allow(mod).to receive(:send_request_cgi).and_return(derived('affected-readiness', capture))

        expect(mod.check_host('192.0.2.45').code).to eq(result)
      end
    end
  end

  describe 'native backing-buffer responses' do
    it 'retains the genuine prior-response disclosure from the pooled target' do
      allow(mod).to receive(:send_request_cgi).and_return(response('affected-malformed-0'))

      expect(mod.bleed).to include('HTTP/1.1 200 OK', 'module_target_memory')
    end

    it 'retains the genuine HTTP framing from the unpooled target' do
      allow(mod).to receive(:send_request_cgi).and_return(response('unpooled-malformed-0'))

      expect(mod.bleed).to include('POST /_bulk HTTP/1.1', 'Content-Type: application/json')
    end

    it 'does not dereference an absent byte-array frame on the fixed target' do
      allow(mod).to receive(:send_request_cgi).and_return(response('fixed-malformed-0'))

      expect(mod.bleed).to be_nil
    end

    it 'identifies an unreachable bulk operation' do
      allow(mod).to receive(:send_request_cgi).and_return(nil)

      expect { mod.bleed }.to raise_error(Msf::Auxiliary::Failed, /Could not connect.*no response/)
    end

    it 'does not dereference a list in place of an error object' do
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-malformed-0', 'error' => []))

      expect(mod.bleed).to be_nil
    end

    it 'does not dereference a string in place of the root-cause list' do
      capture = JSON.parse(captures.fetch('affected-malformed-0').fetch('body'))
      capture.fetch('error')['root_cause'] = 'unexpected'
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-malformed-0', capture))

      expect(mod.bleed).to be_nil
    end

    it 'does not invent a combined disclosure when one reason is missing' do
      capture = JSON.parse(captures.fetch('affected-malformed-0').fetch('body'))
      capture.fetch('error').delete('reason')
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-malformed-0', capture))

      expect(mod.bleed).to be_nil
    end

    it 'does not mistake a truncated source description for a complete disclosure' do
      capture = JSON.parse(captures.fetch('affected-malformed-0').fetch('body'))
      capture.fetch('error')['reason'] = 'Unexpected character at [Source: (byte[])"incomplete'
      allow(mod).to receive(:send_request_cgi).and_return(derived('affected-malformed-0', capture))

      expect(mod.bleed).to be_nil
    end
  end

  describe 'scanner execution' do
    it 'executes the configured requests for each host through the public scanner entrypoint' do
      seen = []
      mod.datastore['RHOSTS'] = '192.0.2.45 192.0.2.46'
      mod.datastore['LEAK_COUNT'] = 2
      allow(mod).to receive(:send_request_cgi) do
        seen << mod.rhost
        response('affected-malformed-0')
      end
      allow(mod).to receive(:replicant).and_wrap_original do |original, *arguments|
        original.call(*arguments).tap do |replica|
          allow(replica).to receive(:send_request_cgi) do
            seen << replica.rhost
            response('affected-malformed-0')
          end
        end
      end

      mod.run

      expect(seen).to eq(%w[192.0.2.45 192.0.2.45 192.0.2.46 192.0.2.46])
    end

    it 'does not report or store loot when both replies have no backing-buffer frame' do
      mod.datastore['ACTION'] = 'DUMP'
      mod.datastore['LEAK_COUNT'] = 2
      allow(mod).to receive(:send_request_cgi).and_return(response('fixed-malformed-0'))
      expect(mod).not_to receive(:report_vuln)
      expect(mod).not_to receive(:store_loot)

      mod.run_host('192.0.2.45')
    end

    it 'retains a valid later disclosure after an earlier reply has no backing-buffer frame' do
      saved = []
      mod.datastore['ACTION'] = 'DUMP'
      mod.datastore['LEAK_COUNT'] = 2
      allow(mod).to receive(:send_request_cgi).and_return(response('fixed-malformed-0'), response('affected-malformed-0'))
      allow(mod).to receive(:store_loot) do |*arguments|
        saved << arguments.fetch(3)
        '/tmp/module-target-memory.bin'
      end

      mod.run_host('192.0.2.45')

      expect(saved).to contain_exactly(include('HTTP/1.1 200 OK', 'module_target_memory'))
    end
  end

  def response(name)
    capture = captures.fetch(name)
    Rex::Proto::Http::Response.new(capture.fetch('status')).tap do |result|
      result.headers['Content-Type'] = 'application/json'
      result.body = capture.fetch('body')
    end
  end

  def derived(name, body)
    response(name).tap { |result| result.body = JSON.generate(body) }
  end
end
