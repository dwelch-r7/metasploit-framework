require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Next.js middleware bypass response classification' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('NEXTJS_MIDDLEWARE_UNIT_MODULE', File.expand_path('../../../../../modules/auxiliary/scanner/http/nextjs_middleware_auth_bypass.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:requests) { [] }
  let(:reports) { [] }
  let(:good_messages) { [] }
  let(:denied) { projected_response(401) }
  let(:login_redirect) { projected_response(307, 'Location' => '/login') }
  let(:missing_route) { projected_response(404) }

  before do
    mod.datastore['RHOSTS'] = '192.0.2.1'
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['TARGETURI'] = '/api/protected'
    mod.datastore['SUBREQUEST_PAYLOAD'] = 'm' * 20_000
    allow(mod).to receive_messages(print_error: nil, print_status: nil, vprint_status: nil)
    allow(mod).to receive(:print_good) { |text| good_messages << text }
    allow(mod).to receive(:report_vuln) { |data| reports << data }
  end

  # Actual status/Location projections from native protocol-before.json in run
  # 20261112T043120-8ef721: Next.js401->431, Apache401->400, and affected
  # Next.js307(/login)->404. Bodies and other headers are deliberately omitted.
  # HTTP delivery and report persistence are explicit doubles; initialization,
  # URI building, Rex responses and check/run-host classification remain real.
  [400, 431].each do |status|
    context "native HTTP #{status} protocol rejection" do
      it 'does not return a bypassing payload' do
        supply_responses(projected_response(status))

        expect(mod.bypassing_payload(denied)).to be_nil
      end

      it 'returns a reason-bearing safe check instead of a confirmed bypass' do
        supply_responses(denied, projected_response(status))

        result = mod.check_host('192.0.2.1')

        expect([result, result.reason]).to eq([Msf::Exploit::CheckCode::Safe, '/api/protected gated (HTTP 401); not bypassed'])
      end

      it 'does not print confirmation or submit a vulnerability from run_host' do
        supply_responses(denied, projected_response(status))
        mod.run_host('192.0.2.1')

        expect([reports, good_messages]).to eq([[], []])
      end
    end
  end

  context 'native missing downstream route after a legitimate bypass' do
    before do
      mod.datastore['TARGETURI'] = '/dashboard/module-target-missing'
      mod.datastore['SUBREQUEST_PAYLOAD'] = 'middleware:middleware:middleware:middleware:middleware'
    end

    it 'retains the observed 307 to 404 payload result' do
      supply_responses(missing_route)

      expect(mod.bypassing_payload(login_redirect)).to eq(payload: mod.datastore['SUBREQUEST_PAYLOAD'], response: missing_route)
    end

    it 'retains the real vulnerable CheckCode for the missing downstream route' do
      supply_responses(login_redirect, missing_route)

      result = mod.check_host('192.0.2.1')

      expect([result, result.reason.include?('HTTP 307 -> /login -> HTTP 404')]).to eq([Msf::Exploit::CheckCode::Vulnerable, true])
    end

    it 'still submits the vulnerability for the observed downstream response' do
      supply_responses(login_redirect, missing_route)
      mod.run_host('192.0.2.1')

      expect(reports).to contain_exactly(include(host: '192.0.2.1', port: 3000, name: mod.name, info: include('HTTP 307 -> /login -> HTTP 404')))
    end
  end

  {
    '401 to 403' => [401, {}, 403, {}],
    '403 to 401' => [403, {}, 401, {}],
    '401 with a changed Location' => [401, { 'Location' => '/login' }, 401, { 'Location' => '/different-login' }],
    '403 with a changed Location' => [403, { 'Location' => '/login' }, 403, { 'Location' => '/different-login' }]
  }.each do |label, (baseline_status, baseline_headers, status, headers)|
    it "rejects the synthetic continuing denial #{label}" do
      baseline = projected_response(baseline_status, baseline_headers)
      supply_responses(projected_response(status, headers))

      expect(mod.bypassing_payload(baseline)).to be_nil
    end
  end

  [429, 500, 503].each do |status|
    it "does not infer a bypass from the synthetic HTTP #{status} error" do
      supply_responses(projected_response(status))

      expect(mod.bypassing_payload(denied)).to be_nil
    end
  end

  [200, 204].each do |status|
    it "preserves the synthetic successful HTTP #{status} differential" do
      accepted = projected_response(status)
      supply_responses(accepted)

      expect(mod.bypassing_payload(denied)).to eq(payload: mod.datastore['SUBREQUEST_PAYLOAD'], response: accepted)
    end
  end

  it 'preserves a synthetic same-status redirect with a changed destination' do
    redirected = projected_response(307, 'Location' => '/dashboard/')
    supply_responses(redirected)

    expect(mod.bypassing_payload(login_redirect)).to eq(payload: mod.datastore['SUBREQUEST_PAYLOAD'], response: redirected)
  end

  it 'does not report an unchanged synthetic login redirect' do
    supply_responses(projected_response(307, 'Location' => '/login'))

    expect(mod.bypassing_payload(login_redirect)).to be_nil
  end

  it 'preserves a synthetic changed redirect status' do
    redirected = projected_response(308, 'Location' => '/dashboard/')
    supply_responses(redirected)

    expect(mod.bypassing_payload(login_redirect)).to eq(payload: mod.datastore['SUBREQUEST_PAYLOAD'], response: redirected)
  end

  it 'continues without a bypass when a response is nil' do
    supply_responses(nil)

    expect(mod.bypassing_payload(denied)).to be_nil
  end

  it 'continues to a later payload after a synthetic rejected attempt' do
    mod.datastore['SUBREQUEST_PAYLOAD'] = ''
    accepted = projected_response(200)
    supply_responses(projected_response(431), accepted)

    expect(mod.bypassing_payload(denied)).to eq(payload: owner_class::PAYLOADS.fetch(1), response: accepted)
  end

  def projected_response(status, headers = {})
    response = Rex::Proto::Http::Response.new
    response.code = status
    response.body = nil
    headers.each { |name, value| response.headers[name] = value }
    response
  end

  def supply_responses(*responses)
    allow(mod).to receive(:send_request_cgi) do |data|
      requests << data
      responses.shift
    end
  end
end
