require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/irssi_nickserv/native'

RSpec.describe 'NickServ collection through genuine Irssi and shell sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include IrssiNickservTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], session_reads: [], calls: [], reports: [], cleanup: [], case_states: [] }
    expect(nc_action('bootstrap').fetch('account_created_through_native_service')).to be(true)
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
      %w[files fixtures services].each { |key| expect(current.fetch(key)).to eq(@baseline.fetch(key)) }
      rc_resources('after')
      @rc[:final_framework] = rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')
      expect(@rc.fetch(:final_framework)).to eq('sessions' => [], 'jobs' => [])
    end
  ensure
    if @rc&.fetch(:bootstrap, nil)&.fetch('account_created_through_native_service')
      expect(nc_action('drop').fetch('account_removed_and_absent')).to be(true)
    end
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

  it 'collects the exact file-derived lower-case password on repeated execution' do
    ic_install('autosend-lower.config')
    rc_session('lower', 'root')
    first = ic_call('lower')
    second = ic_call('repeat')
    expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
    [first, second].each { |call| nc_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
  end

  %w[caret capital account].each do |fixture|
    it "collects the exact native-working #{fixture} NickServ secret" do
      ic_install('autosend-' + fixture + '.config')
      rc_session(fixture, 'root')
      nc_verify(ic_call(fixture))
    end
  end

  {
    'commandcase' => 'autosend-command-case.config',
    'wrong' => 'autosend-wrong.config',
    'commented' => 'commented-autosend.config',
    'passwordfree' => 'password-free.config'
  }.each do |label, fixture|
    it "preserves exact raw evidence and native authentication verdict for #{label}" do
      ic_install(fixture)
      expected = label == 'commandcase'
      expect(@irssi_case.fetch(:native).fetch('native_client').fetch('identified')).to eq(expected)
      rc_session(label, 'root')
      nc_verify(ic_call(label))
    end
  end

  it 'collects an ordinary user home configuration through its genuine shell' do
    ic_install('autosend-lower.config', 'labuser', location: 'labuser')
    rc_session('ordinary', 'labuser')
    nc_verify(ic_call('ordinary'))
  end
end
