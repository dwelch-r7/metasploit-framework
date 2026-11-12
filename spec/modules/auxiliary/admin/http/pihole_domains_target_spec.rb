require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/pihole_domains/acceptance'

profile = ENV.fetch('PH_PROFILE', 'vulnerable')

RSpec.describe 'Genuine Pi-hole Top Domains command execution', acceptance: true do
  include_context 'module target'
  include Acceptance::PiholeDomains

  before(:all) do
    @profile = profile
    @app = profile != 'unrelated'
    @vulnerable = %w[vulnerable noauth].include?(profile)
    @native = ph_native('before')
    expect(ph_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    proof = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"PH_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"PH_REFUSED=true\"; end'")
    expect(proof).to include('PH_REFUSED=true')
  end

  after(:all) do
    if @native
      current = ph_native('after')
      keys = @app ? %w[files identity database config_base64] : %w[identity ordinary_sha256]
      keys.each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
    end
  end

  before do |example|
    @workspace = "ph_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(ph_reports.values).to all(eq([]))
    expect(ph_config).to eq(Base64.strict_decode64(@native.fetch('config_base64'))) if @app
  end

  after { ph_reports if @workspace }

  if profile != 'unrelated'
    it 'checks the genuine web version twice without duplicate reporting' do
      original = nil
      2.times do
        rows = ph_positive_check
        expect(rows).to eq(original) if original
        original = rows
      end
    end

    it 'runs id then pwd without resetting target configuration between commands' do
      begin
        ph_execute({}, cleanup: false)
        retained = ph_config
        ph_execute({ 'COMMAND' => 'pwd' })
        expect(Base64.strict_decode64(@last_call.fetch(:config_before))).to eq(retained)
      ensure
        ph_restore(@native.fetch('config_base64'))
      end
      ph_expect_reports
    end

    it 'executes pwd using the independently captured native working directory' do
      ph_execute({ 'COMMAND' => 'pwd' })
      ph_expect_reports
    end

    it 'checks and runs with actual HTTP trace while preserving the prior check record' do
      prior = ph_positive_check
      ph_execute({ 'HttpTrace' => true })
      expect(ph_reports).to eq(prior)
    end

    it 'handles an incorrect password according to actual target authentication requirements' do
      options = { 'PASSWORD' => 'module-target-rejected-password' }
      if profile == 'noauth'
        ph_execute(options)
      else
        expect(ph_call('run', options)).to include(@vulnerable ? 'Incorrect Password' : 'Target is not vulnerable')
        expect(@last_call.values_at(:config_before, :config_after).uniq.length).to eq(1)
      end
      ph_expect_reports
    end
  else
    it 'returns unknown for the unrelated product and refuses execution' do
      expect(ph_call('check')).to include('Cannot reliably check exploitability.')
      expect(ph_call('run')).to include('Target is not vulnerable')
      ph_expect_reports
    end
  end

  it 'rejects an invalid command before changing the target' do
    expect(ph_call('run', { 'COMMAND' => 'id;uname' })).to include('COMMAND invalid')
    expect(@last_call.values_at(:config_before, :config_after).uniq.length).to eq(1)
    ph_expect_reports
  end

  it 'handles a missing application path without false reporting' do
    options = { 'TARGETURI' => '/module-target-missing' }
    expect(ph_call('check', options)).to include('Cannot reliably check exploitability.')
    expect(ph_call('run', options)).to include('Target is not vulnerable')
    ph_expect_reports
  end

  it 'handles the native-proven refused port without false reporting' do
    options = { 'RPORT' => 1 }
    expect(ph_call('check', options)).to include('Cannot reliably check exploitability.')
    expect(ph_call('run', options)).to include('Target is not vulnerable')
    ph_expect_reports
  end
end
