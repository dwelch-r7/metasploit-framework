require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/pgpass_creds/native'

RSpec.describe 'PostgreSQL password-file collection through genuine sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include_context 'wait_for_expect'
  include_context 'native Linux session'
  include PgpassCredentialTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], reads: [], cases: [], calls: [], reports: [], cleanup: [] }
    @baseline = pg_native('before')
    rc_resources('before')
    expect(rc_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    expect(rc_sql('SELECT usesuper FROM pg_user WHERE usename=current_user').strip).to eq('f')
    endpoint = target_runtime.fetch('module_endpoints').fetch('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets')
    expect(rc_json('begin;load "test/module_targets/druid_sessions/session_control.rb";DruidSessionControl.install(framework);end').fetch('installed')).to be(true)
    @realm_key = rc_json('Metasploit::Model::Realm::Key::POSTGRESQL_DATABASE')
    @rc[:preflight] = 'passed'
    rc_save
  end

  after(:all) do
    if @rc&.key?(:preflight)
      current = pg_native('after')
      expect(current.fetch('files')).to eq(@baseline.fetch('files'))
      expect(current.fetch('fixtures')).to eq(@baseline.fetch('fixtures'))
      expect(current.fetch('server')).to eq(@baseline.fetch('server'))
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
      pg_cleanup
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    begin
      pg_restore
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      errors << e
    end
    unless errors.empty?
      (@rc[:cleanup_errors] ||= []).concat(errors.map { |error| { error: error.class.name, message: error.message } })
      rc_save
      raise errors.first if example.exception.nil?
    end
  end

  %w[shell meterpreter].each do |kind|
    context kind do
      it 'collects the native-working plain file and preserves reporting on a repeat' do
        pg_install('plain.pgpass')
        pg_session(kind, 'plain')
        first = pg_call('plain')
        second = pg_call('repeat')
        expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
        [first, second].each { |call| pg_verify(call) }
        expect(second.fetch(:report).fetch(:cores)).to eq(first.fetch(:report).fetch(:cores))
        expect(second.fetch(:new_loot).first.fetch('id')).not_to eq(first.fetch(:new_loot).first.fetch('id'))
      end

      it 'continues across native-accepted blank lines' do
        pg_install('blanks.pgpass')
        pg_session(kind, 'blanks')
        pg_verify(pg_call('blanks'))
      end

      it 'collects the decoded native-working escaped database field' do
        pg_install('escaped-db.pgpass')
        pg_session(kind, 'escaped')
        pg_verify(pg_call('escaped'))
      end

      %w[comments wildcard escaped-user escaped-password incomplete].each do |fixture|
        it "collects the exact native-working #{fixture} file" do
          label = fixture.tr('-', '_')
          pg_install(fixture + '.pgpass')
          pg_session(kind, label)
          pg_verify(pg_call(label))
        end
      end
    end
  end
end
