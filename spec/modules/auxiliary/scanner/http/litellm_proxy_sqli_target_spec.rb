require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/litellm/acceptance'

RSpec.describe 'Native LiteLLM pre-authentication SQLi scanner', acceptance: true, order: :defined do
  include_context 'module target'
  include LiteLLMAcceptance

  before(:all) do
    @native = native('before')
    @positive = @native.fetch('version') == '1.83.3' && @native.fetch('configuration') == 'affected'
    @expected = @positive ? 'vulnerable' : 'safe'
    select_endpoint
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    code = 'load "test/module_targets/litellm/input_audit.rb";puts "LITELLM_AUDIT="+LiteLLMTargetInputs.install(framework)'
    expect(console_command("irb -e #{code.inspect}")).to include('LITELLM_AUDIT=auxiliary/scanner/http/litellm_proxy_sqli')
  end

  before do |example|
    @workspace = 'litellm_' + example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(reports).to eq([])
    idle
  end

  after(:all) do
    native('after') if @native
  end

  it 'records the native-proven empty-key-table detection limit twice' do
    expect(@native.fetch('empty')).to include('virtual_keys' => 0, 'delayed' => false)
    invoke(expected: 'safe')
    invoke(action: 'run', expected: 'safe', reuse: true)
    expect(reports).to eq([])
  end

  it 'checks a genuine API-generated and independently validated virtual key twice' do
    expect(native('seed', 1).fetch('virtual_keys')).to eq(1)
    expect(native('calibrate').fetch('delayed')).to eq(@positive)
    invoke(expected: @expected)
    invoke(expected: @expected, reuse: true)
    # Scanner#check records a genuine confirmed vulnerability automatically.
    expect(reports.length).to eq(@positive ? 1 : 0)
    expect(reports.fetch(0).fetch('info')).to include('Vulnerability confirmed by check') if @positive
  end

  it 'runs the scanner twice and verifies actual PostgreSQL vulnerability reporting' do
    invoke(action: 'run', expected: @expected)
    invoke(action: 'run', expected: @expected, reuse: true)
    if @positive
      expect(reports.length).to eq(1)
      row = reports.fetch(0)
      expect(row).to include('name' => 'BerriAI LiteLLM Proxy Pre-Auth SQL Injection Scanner', 'host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => 4000, 'proto' => 'tcp')
      expect(row.fetch('refs')).to include('CVE-2026-42208', 'GHSA-r75f-5x8p-qvmc')
      expect(row.fetch('info')).to include('Time-based blind SQLi via Authorization header (pg_sleep)')
    else
      expect(reports).to eq([])
    end
  end

  it 'sends valid UTF-8 model JSON through the same native authentication path twice' do
    options = { 'MODEL' => 'module-native-café-雪' }
    invoke(expected: @expected, options: options)
    invoke(action: 'run', expected: @expected, options: options, reuse: true)
  end

  it 'returns a reason-bearing inconclusive check for a native-proven refused connection twice' do
    invoke(expected: 'unknown', options: { 'RPORT' => 1 }, statuses: [nil])
    invoke(expected: 'unknown', options: { 'RPORT' => 1 }, statuses: [nil], reuse: true)
    expect(reports).to eq([])
  end

  it 'does not report an injection on the native missing route twice' do
    2.times do |iteration|
      result = invoke(options: { 'TARGETURI' => '/module-native-absent' }, statuses: [404], reuse: iteration.positive?)
      expect(result.fetch('code')).not_to eq('vulnerable')
    end
    expect(reports).to eq([])
  end

  it 'checks five independently provisioned virtual keys twice without per-row sleeps' do
    expect(native('seed', 5).fetch('virtual_keys')).to eq(5)
    calibration = native('calibrate')
    expect(calibration).to include('virtual_keys' => 5, 'delayed' => @positive)
    invoke(expected: @expected)
    invoke(expected: @expected, reuse: true)
  end

  it 'preserves checks across delay and model transitions with unique uncached bearer probes' do
    invoke(expected: @expected, options: { 'SqliDelay' => 0.5, 'MODEL' => 'module-native-alternate-model' })
    invoke(expected: @expected, options: { 'SqliDelay' => 1.0 }, reuse: true)
    headers = owner_rows.select { |row| row['kind'] == 'http' && row['method'] == 'POST' }.map { |row| row.fetch('authorization') }
    expect(headers.uniq).to eq(headers)
  end
end
