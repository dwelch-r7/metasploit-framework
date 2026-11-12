require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/nextjs_middleware/acceptance'

profile = ENV.fetch('NEXTJS_PROFILE', 'vulnerable_root')

RSpec.describe 'Genuine Next.js middleware authorization bypass', acceptance: true do
  include_context 'module target'
  include Acceptance::NextjsMiddleware

  before(:all) do
    @app = profile != 'unrelated'
    @vulnerable = profile.start_with?('vulnerable_')
    @layout = profile.end_with?('_src') ? 'src/middleware' : 'middleware'
    @payload = ([@layout] * 5).join(':')
    @native = nx_native('before')
    expect(nx_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    proof = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"NX_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"NX_REFUSED=true\"; end'")
    expect(proof).to include('NX_REFUSED=true')
    @accepted_cookie = File.join(target_runtime.fetch('artifacts'), 'accepted-cookie.headers')
    @rejected_cookie = File.join(target_runtime.fetch('artifacts'), 'rejected-cookie.headers')
    File.write(@accepted_cookie, "Cookie: session=module-target-next-session\r\n")
    File.write(@rejected_cookie, "Cookie: session=module-target-rejected-session\r\n")
  end

  after(:all) do
    if @native
      current = nx_native('after')
      keys = @app ? %w[files identity command_base64 versions build_id middleware_manifest ordinary_sha256] : %w[files identity command_base64 ordinary_sha256]
      keys.each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
    end
  end

  before do |example|
    @workspace = "nx_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(nx_reports.values).to all(eq([]))
  end

  after { nx_reports if @workspace }

  if profile != 'unrelated'
    it 'checks twice and retains one real vulnerability and service identity' do
      first = nx_protected('check')
      expect(nx_protected('check')).to eq(first)
    end

    it 'runs twice with real HTTP trace and stable persisted reporting' do
      first = nx_protected('run')
      expect(nx_protected('run', { 'HttpTrace' => true })).to eq(first)
    end

    it 'checks and runs the API route gated with HTTP 401' do
      nx_protected('check', { 'TARGETURI' => '/api/protected' })
      nx_protected('run', { 'TARGETURI' => '/api/protected' })
    end

    it 'checks and runs a resource gated with HTTP 403' do
      nx_protected('check', { 'TARGETURI' => '/forbidden' })
      nx_protected('run', { 'TARGETURI' => '/forbidden' })
    end

    it 'checks and runs a resource using an HTTP 302 login redirect' do
      nx_protected('check', { 'TARGETURI' => '/redirect302' })
      nx_protected('run', { 'TARGETURI' => '/redirect302' })
    end

    it 'honors a single forced correct-layout recursion payload' do
      nx_protected('run', { 'SUBREQUEST_PAYLOAD' => @payload })
    end

    it 'does not claim a bypass with the other middleware layout forced' do
      other = @layout == 'middleware' ? 'src/middleware' : 'middleware'
      options = { 'SUBREQUEST_PAYLOAD' => ([other] * 5).join(':') }
      nx_protected('check', options, vulnerable: false)
      nx_protected('run', options, vulnerable: false)
    end

    it 'does not bypass modern recursion protection with a single module name' do
      nx_protected('check', { 'SUBREQUEST_PAYLOAD' => @layout }, vulnerable: false)
    end

    it 'handles accepted and rejected cookies without leaking headers into later calls' do
      accepted = { 'HttpRawHeaders' => @accepted_cookie }
      nx_ungated(accepted)
      nx_protected('run', { 'HttpRawHeaders' => @rejected_cookie })
      nx_protected('check')
    end

    it 'retains a genuine middleware bypass ending at a missing downstream route' do
      options = { 'TARGETURI' => Acceptance::NextjsMiddleware::PROTOCOL_REJECTION.fetch('downstream_path') }
      nx_protected('check', options)
      nx_protected('run', options)
    end

    it 'does not mistake ordinary trailing-slash normalization for a bypass' do
      options = { 'TARGETURI' => '/dashboard/' }
      nx_protected('check', options, vulnerable: false)
      nx_protected('run', options, vulnerable: false)
    end
  else
    it 'does not bypass a genuine unrelated Apache Basic authentication gate' do
      nx_protected('check', { 'TARGETURI' => '/protected/' }, vulnerable: false)
      nx_protected('run', { 'TARGETURI' => '/protected/' }, vulnerable: false)
    end
  end

  it 'does not report an ordinary public resource as vulnerable' do
    nx_ungated({ 'TARGETURI' => '/' })
  end

  it 'handles a missing resource without false vulnerability reporting' do
    nx_ungated({ 'TARGETURI' => '/module-target-missing' })
  end

  it 'does not confirm a bypass when the check request is rejected by the HTTP parser' do
    nx_protected('check', nx_rejection_options, vulnerable: false)
  end

  it 'does not report a vulnerability when the run request is rejected by the HTTP parser' do
    nx_protected('run', nx_rejection_options, vulnerable: false)
  end

  it 'handles the independently proved refused port without false reporting' do
    options = { 'RPORT' => 1 }
    expect(nx_call('check', options)).to include('Cannot reliably check exploitability.', 'No response to the baseline request')
    expect(nx_call('run', options)).to include('No response to the baseline request')
    nx_assert_reports(vulnerable: false)
  end
end
