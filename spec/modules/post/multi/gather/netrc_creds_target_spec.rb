require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/netrc_creds/native'

RSpec.describe '.netrc collection through genuine shell sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include NetrcCredentialTarget

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
      nc_restore
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    unless errors.empty?
      (@rc[:cleanup_errors] ||= []).concat(errors.map { |error| { error: error.class.name, message: error.message } })
      rc_save
      raise errors.first if example.exception.nil?
    end
  end

  it 'collects a native-working multiline file on repeated executions' do
    nc_install('multiline.netrc', 'root')
    rc_session('multiline', 'root')
    first = nc_call('multiline')
    second = nc_call('repeat')
    expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
    [first, second].each { |call| nc_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
    expect(second.fetch(:loot).first.fetch('bytes_base64')).to eq(first.fetch(:loot).first.fetch('bytes_base64'))
  end

  it 'collects the same credentials from native-working tab-separated fields' do
    nc_install('tabs.netrc', 'root')
    rc_session('tabs', 'root')
    nc_verify(nc_call('tabs'))
  end

  it 'keeps commented example tokens out of the native-working credential list' do
    nc_install('comments.netrc', 'root')
    rc_session('comments', 'root')
    nc_verify(nc_call('comments'))
  end

  it 'does not create loot from a root file unreadable to an ordinary shell' do
    nc_install('multiline.netrc', 'labuser')
    rc_session('unreadable', 'labuser')
    call = nc_call('unreadable')
    expect(call.fetch(:loot)).to eq([])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('No creds collected', 'Post module execution completed')
  end

  it 'collects the native-working single-line form' do
    nc_install('inline.netrc', 'root')
    rc_session('inline', 'root')
    nc_verify(nc_call('inline'))
  end

  it 'retains both native-working machine entries' do
    nc_install('multiple.netrc', 'root')
    rc_session('multiple', 'root')
    nc_verify(nc_call('multiple'), hosts: ['netrc-auth', 'netrc-alias'])
  end

  it 'collects fields separated by multiple spaces' do
    nc_install('spaces.netrc', 'root')
    rc_session('spaces', 'root')
    nc_verify(nc_call('spaces'))
  end

  it 'collects an ordinary user own readable home file' do
    nc_install('inline.netrc', 'labuser', location: 'own')
    rc_session('own', 'labuser')
    nc_verify(nc_call('own'))
  end
end
