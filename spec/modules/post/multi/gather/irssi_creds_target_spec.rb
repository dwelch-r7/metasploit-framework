require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/irssi_creds/native'

RSpec.describe 'Irssi collection through genuine shell sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include IrssiCredentialTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], session_reads: [], calls: [], reports: [], cleanup: [], case_states: [] }
    @baseline = rc_native('before')
    rc_resources('before')
    expect(rc_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(rc_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets')
    expect(rc_json('begin;load "test/module_targets/druid_sessions/session_control.rb";DruidSessionControl.install(framework);end').fetch('installed')).to be(true)
    rc_callback
    @rc[:preflight] = 'passed'
    rc_save
  end

  after(:all) do
    if @rc&.key?(:preflight)
      current = rc_native('after')
      expect(current.fetch('files')).to eq(@baseline.fetch('files'))
      expect(current.fetch('fixtures')).to eq(@baseline.fetch('fixtures'))
      expect(current.fetch('server_pid')).to eq(@baseline.fetch('server_pid'))
      rc_resources('after')
      @rc[:final_framework] = rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')
      expect(@rc.fetch(:final_framework)).to eq('sessions' => [], 'jobs' => [])
    end
  ensure
    rc_save
  end

  after do |example|
    errors = []
    begin
      rc_cleanup
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    begin
      ic_restore
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    unless errors.empty?
      (@rc[:cleanup_errors] ||= []).concat(errors.map { |error| { error: error.class.name, message: error.message } })
      rc_save
      raise errors.first if example.exception.nil?
    end
  end

  it 'collects a native-working server password on repeated executions' do
    ic_install('plain.config')
    rc_session('plain', 'root')
    first = ic_call('plain')
    second = ic_call('repeat')
    expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
    [first, second].each { |call| ic_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
    expect(second.fetch(:loot).first.fetch('base64')).to eq(first.fetch(:loot).first.fetch('base64'))
  end

  %w[tabs compact].each do |fixture|
    it "collects the actual password from a native-working #{fixture} assignment" do
      ic_install(fixture + '.config')
      rc_session(fixture, 'root')
      ic_verify(ic_call(fixture))
    end
  end

  it 'retains commented password text as raw evidence without claiming authentication' do
    ic_install('commented.config')
    expect(@irssi_case.fetch(:native).fetch('native_client').fetch('authenticated')).to be(false)
    rc_session('commented', 'root')
    ic_verify(ic_call('commented'))
  end

  it 'collects an ordinary user home configuration through its genuine shell' do
    ic_install('plain.config', 'labuser', location: 'labuser')
    rc_session('ordinary', 'labuser')
    ic_verify(ic_call('ordinary'))
  end

  it 'handles a present configuration unreadable to its ordinary shell' do
    ic_install('plain.config', 'labuser', location: 'labuser', unreadable: true)
    expect(@irssi_case.fetch(:native).values_at('authenticated_mode', 'mode', 'file_exists', 'readable')).to eq(['0o600', '0o0', true, false])
    rc_session('unreadable', 'labuser')
    expect(@rc.fetch(:session_reads).last.fetch(:data).fetch('bytes')).to be_nil
    ic_verify(ic_call('unreadable'))
  end

  it 'does not collect a configuration without password tokens' do
    ic_install('missing-password.config')
    rc_session('passwordfree', 'root')
    ic_verify(ic_call('passwordfree'))
  end
end
