require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/fetchmailrc_creds/native'

RSpec.describe 'Fetchmail collection through genuine shell sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include FetchmailCredentialTarget

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
      expect(current.fetch('message_hashes_after')).to eq(@baseline.fetch('message_hashes_before'))
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
      fc_restore
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    unless errors.empty?
      (@rc[:cleanup_errors] ||= []).concat(errors.map { |error| { error: error.class.name, message: error.message } })
      rc_save
      raise errors.first if example.exception.nil?
    end
  end

  it 'collects a native-working plain file on repeated executions' do
    fc_install('plain.fetchmailrc')
    rc_session('plain', 'root')
    first = fc_call('plain')
    second = fc_call('repeat')
    expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
    [first, second].each { |call| fc_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
    expect(second.fetch(:loot).first.fetch('bytes_base64')).to eq(first.fetch(:loot).first.fetch('bytes_base64'))
  end

  it 'collects the complete native-working quoted password containing spaces' do
    fc_install('quoted-password.fetchmailrc')
    rc_session('quoted', 'root')
    fc_verify(fc_call('quoted'))
  end

  %w[imap comments blanks multiline defaults multiple-users].each do |fixture|
    it "collects the complete native-working #{fixture} file" do
      label = fixture.delete('-')
      fc_install(fixture + '.fetchmailrc')
      rc_session(label, 'root')
      fc_verify(fc_call(label))
    end
  end

  it 'does not create loot from a root file unreadable to an ordinary shell' do
    fc_install('plain.fetchmailrc', 'labuser')
    rc_session('unreadable', 'labuser')
    call = fc_call('unreadable')
    expect(call.fetch(:loot)).to eq([])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('No creds collected', 'Post module execution completed')
  end

  it 'collects an ordinary user home file through its genuine ordinary shell' do
    fc_install('plain.fetchmailrc', 'labuser', location: 'labuser')
    rc_session('ordinary', 'labuser')
    fc_verify(fc_call('ordinary'))
  end
end
