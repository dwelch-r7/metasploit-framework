require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/generic_env/native'

RSpec.describe 'Environment collection through genuine Linux sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include GenericEnvironmentTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], sources: [], cases: [], calls: [], reports: [], cleanup: [] }
    @baseline = ge_native('before')
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
      expect(ge_native('after')).to eq(@baseline)
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
      ge_cleanup
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    begin
      ge_restore
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    unless errors.empty?
      (@rc[:cleanup_errors] ||= []).concat(errors.map { |error| { error: error.class.name, message: error.message } })
      rc_save
      raise errors.first if example.exception.nil?
    end
  end

  it 'collects exact controlled values through a root shell on repeated execution' do
    ge_install
    ge_session('shell', 'standard')
    first = ge_call('plain')
    second = ge_call('repeat')
    expect(first.fetch(:module_id)).to eq(second.fetch(:module_id))
    [first, second].each { |call| ge_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
  end

  it 'collects exact controlled values through root Meterpreter on repeated execution' do
    ge_install
    ge_session('meterpreter', 'standard')
    first = ge_call('plain')
    second = ge_call('repeat')
    expect(first.fetch(:module_id)).to eq(second.fetch(:module_id))
    [first, second].each { |call| ge_verify(call) }
    expect(second.fetch(:loot).first.fetch('id')).not_to eq(first.fetch(:loot).first.fetch('id'))
  end

  [
    ['shell', 'labuser', 'standard'],
    ['meterpreter', 'labuser', 'standard'],
    ['shell', 'root', 'large'],
    ['meterpreter', 'root', 'large']
  ].each do |kind, actor, variant|
    it "collects exact #{variant} values through #{actor} #{kind}" do
      ge_install(variant)
      ge_session(kind, variant, actor)
      ge_verify(ge_call(variant))
    end
  end
end
