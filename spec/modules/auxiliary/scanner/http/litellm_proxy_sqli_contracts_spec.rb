require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'LiteLLM SQL injection probe contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('LITELLM_CONTRACT_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/litellm_proxy_sqli.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:clock) { [Time.at(1_700_000_000)] }
  let(:requests) { [] }
  let(:proofs) { [] }
  let(:model) { 'gpt-3.5-turbo'.freeze }
  let(:health_reply) { response(401) }
  let(:probe_replies) { [response(401), response(401)] }
  let(:probe_seconds) { [1.03, 0.02] }

  before do
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 4000, 'MODEL' => model, 'SqliDelay' => 1.0)
    allow(mod).to receive(:framework).and_return(instance_double(Msf::Framework, datastore: Msf::DataStore.new))
    allow(mod).to receive(:user_output).and_return(Rex::Ui::Text::Output::Buffer.new)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:report_vuln)
    allow(Time).to receive(:now) { clock.first }
    allow(Rex::Text).to receive(:rand_text_alphanumeric).with(8).and_return('ProbeOne', 'ProbeTwo')
    # HTTP and elapsed time are controlled; the PostgreSQL SQLi object,
    # true/false predicates, timing comparison and Rex serialization are real.
    allow(mod).to receive(:send_request_cgi) do |request, timeout = nil|
      requests << request
      if request.fetch('method') == 'GET'
        health_reply
      else
        clock[0] += probe_seconds.shift
        proofs << wire_proof(request).merge(timeout: timeout)
        probe_replies.shift
      end
    end
  end

  after do |example|
    if (path = ENV['LITELLM_CONTRACT_UNIT_EVIDENCE'])
      File.open(path, 'a') do |file|
        file.puts(JSON.generate(example: example.full_description, proofs: proofs, requests: requests.map { |request| request.slice('method', 'uri') }))
      end
    end
  end

  def response(code)
    Rex::Proto::Http::Response.new(code)
  end

  def wire_proof(request)
    wire = Rex::Proto::Http::ClientRequest.new(request.merge('vhost' => '192.0.2.10', 'cgi' => true)).to_s
    headers, body = wire.split("\r\n\r\n", 2)
    {
      declared_bytes: headers[/Content-Length: (\d+)/i, 1].to_i,
      actual_bytes: body.bytesize,
      body_base64: Base64.strict_encode64(body),
      model: JSON.parse(body).fetch('model'),
      authorization: request.fetch('headers').fetch('Authorization')
    }
  end

  def checked
    mod.check_host('192.0.2.10').tap { |code| proofs << { code: code.code, reason: code.reason } }
  end

  describe 'request bytes' do
    it 'frames the ASCII model without changing its JSON document or timeout' do
      checked

      expect(proofs.first.slice(:declared_bytes, :actual_bytes, :model, :timeout)).to eq(declared_bytes: 83, actual_bytes: 83, model: model, timeout: 24)
    end

    context 'with the native Unicode model' do
      # Immutable genuine replay: litellm-original-contract-failures-20261114,
      # litellm/litellm-owner-calls.jsonl: UTF-8 body90characters/93bytes.
      # Independent native HTTP401 still exhibited the true/false time signal.
      let(:model) { 'module-native-café-雪'.freeze }

      it 'declares all93body bytes while preserving the exact model and JSON' do
        checked

        expect(proofs.first.slice(:declared_bytes, :actual_bytes, :model)).to eq(declared_bytes: 93, actual_bytes: 93, model: model)
        expect(JSON.parse(Base64.strict_decode64(proofs.first.fetch(:body_base64)))).to eq(
          'model' => model, 'messages' => [{ 'role' => 'user', 'content' => 'x' }], 'max_tokens' => 1
        )
        expect(mod.datastore['MODEL']).to equal(model)
        expect(model.encoding).to eq(Encoding::UTF_8)
      end
    end

    it 'keeps distinct cache-busting bearer comments for the real true and false probes' do
      checked

      expect(proofs.first(2).map { |proof| proof.fetch(:authorization) }).to eq([
        "Bearer ' OR 1=(case when 1=1 then (select 1 from pg_sleep(1.0)) else 1 end)-- ProbeOne",
        "Bearer ' OR 1=(case when 1=2 then (select 1 from pg_sleep(1.0)) else 1 end)-- ProbeTwo"
      ])
    end
  end

  describe 'completed true and false probes' do
    it 'confirms the native slow-true fast-false HTTP401 signal' do
      expect(checked).to eq(Msf::Exploit::CheckCode::Vulnerable)
    end

    context 'when both replies are fast' do
      let(:probe_seconds) { [0.02, 0.02] }

      it 'reports no observed signal' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Safe)
      end
    end

    context 'when both replies are slow' do
      let(:probe_seconds) { [1.03, 1.03] }

      it 'does not confuse uniform slowness with SQL injection' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Safe)
      end
    end

    context 'when only the false reply is slow' do
      let(:probe_seconds) { [0.02, 1.03] }

      it 'rejects the reversed time signal' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Safe)
      end
    end

    context 'without a fingerprint response' do
      let(:health_reply) { nil }

      it 'retains best-effort fingerprinting when both SQLi probes complete' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Vulnerable)
      end
    end

    context 'with a mixed-case native version header' do
      let(:health_reply) { response(401).tap { |res| res.headers['X-LiteLLM-Version'] = '1.83.3' } }

      it 'includes the optional fingerprint in the confirmed reason' do
        expect(checked.reason).to include('LiteLLM 1.83.3')
      end
    end
  end

  describe 'incomplete probes' do
    context 'when all requests receive no response' do
      let(:health_reply) { nil }
      let(:probe_replies) { [nil, nil] }
      let(:probe_seconds) { [0.02, 0.02] }

      it 'returns a reason-bearing Unknown rather than Safe' do
        code = checked

        expect(code).to eq(Msf::Exploit::CheckCode::Unknown)
        expect(code.reason).to include('No response to the SQL injection probe')
      end
    end

    context 'when the true probe receives no response after a fingerprint reply' do
      let(:probe_replies) { [nil, response(401)] }

      it 'does not count a timed-out true probe as a positive signal' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Unknown)
      end
    end

    context 'when the false probe receives no response after a slow true reply' do
      let(:probe_replies) { [response(401), nil] }

      it 'does not claim a vulnerability without the negative-control response' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Unknown)
      end
    end

    context 'when the false probe receives no response after a fast true reply' do
      let(:probe_replies) { [response(401), nil] }
      let(:probe_seconds) { [0.02, 0.02] }

      it 'does not claim Safe from an incomplete comparison' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Unknown)
      end
    end

    it 'returns Unknown for an expected connection exception during fingerprinting' do
      allow(mod).to receive(:send_request_cgi).and_raise(Rex::ConnectionRefused.new)

      expect(checked).to eq(Msf::Exploit::CheckCode::Unknown)
    end

    it 'returns Unknown with context for an expected SQLi connection exception' do
      error = Rex::ConnectionTimeout.new
      allow(mod).to receive(:send_request_cgi).with(hash_including('method' => 'POST'), 24).and_raise(error)

      code = checked

      expect(code).to eq(Msf::Exploit::CheckCode::Unknown)
      expect(code.reason).to include('SQL injection')
      expect(mod).to have_received(:elog).with('Failed to complete the LiteLLM SQL injection check', error: error)
    end

    it 'does not hide unrelated programming errors' do
      allow(mod).to receive(:send_request_cgi).and_raise(ArgumentError, 'Controlled programming error')

      expect { checked }.to raise_error(ArgumentError, 'Controlled programming error')
    end
  end

  describe 'the real HttpClient transport contract' do
    # Only connect is doubled here. Real send_request_cgi/send_request_raw
    # handle their documented connection/timeout/broken-pipe failures as nil.
    before do
      allow(mod).to receive(:send_request_cgi).and_call_original
      allow(mod).to receive(:connect).and_raise(transport_error)
    end

    shared_examples 'an inconclusive transport failure' do
      it 'converts the actual HttpClient failure sentinel to Unknown' do
        expect(checked).to eq(Msf::Exploit::CheckCode::Unknown)
      end
    end

    context 'connection refused' do
      let(:transport_error) { Rex::ConnectionRefused.new }

      include_examples 'an inconclusive transport failure'
    end

    context 'read timeout' do
      let(:transport_error) { Timeout::Error.new }

      include_examples 'an inconclusive transport failure'
    end

    context 'broken pipe' do
      let(:transport_error) { Errno::EPIPE.new }

      include_examples 'an inconclusive transport failure'
    end
  end

  describe '#run_host reporting' do
    it 'keeps explicit reporting for a confirmed time signal' do
      mod.run_host('192.0.2.10')

      expect(mod).to have_received(:report_vuln).with(hash_including(host: '192.0.2.10', port: 4000))
    end

    context 'when the completed probes are uniformly fast' do
      let(:probe_seconds) { [0.02, 0.02] }

      it 'does not report an unconfirmed vulnerability' do
        mod.run_host('192.0.2.10')

        expect(mod).not_to have_received(:report_vuln)
      end
    end
  end
end
