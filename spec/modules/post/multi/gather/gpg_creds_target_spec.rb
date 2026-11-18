require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/gpg_creds/native'

RSpec.describe 'GnuPG raw collection through genuine sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include GpgCredentialTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], sources: [], cases: [], gpg_cases: [], calls: [], reports: [], cleanup: [] }
    @baseline = gp_native('before')
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
      expect(gp_native('after')).to eq(@baseline)
      rc_resources('after')
      @rc[:final_framework] = rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')
      expect(@rc.fetch(:final_framework)).to eq('sessions' => [], 'jobs' => [])
    end
  ensure
    rc_save
  end

  after do |example|
    errors = []
    %i[ge_cleanup gp_restore ge_restore].each do |operation|
      send(operation)
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
    it "collects actual root keyring bytes through #{kind} on repeat" do
      ge_install
      gp_install('root', 'plain', empty: true)
      ge_session(kind, 'root')
      first = gp_call('plain')
      second = gp_call('repeat')
      expect(first.fetch(:module_id)).to eq(second.fetch(:module_id))
      [first, second].each { |call| gp_verify(call) }
      expect(second.fetch(:loot).map { |row| row.fetch('id') } & first.fetch(:loot).map { |row| row.fetch('id') }).to eq([])
    end

    it "collects a native-valid protected keyring in a space-containing home through #{kind}" do
      ge_install
      gp_install('labuser', 'protected')
      ge_session(kind, 'space')
      gp_verify(gp_call('space'))
    end

    it "collects the ordinary user's native-valid protected keyring through #{kind}" do
      ge_install
      gp_install('labuser', 'protected', 'labuser')
      ge_session(kind, 'ordinary', 'labuser')
      gp_verify(gp_call('ordinary'))
    end

    it "skips the ordinary user's natively unreadable private key through #{kind}" do
      ge_install
      gp_install('labuser', 'protected', 'labuser', unreadable: true)
      files = @gpg_case.fetch(:native).fetch('files').values
      expect(files.count { |row| row.fetch('expected_collect') }).to eq(3)
      expect(files.count { |row| !row.fetch('readable') }).to eq(1)
      ge_session(kind, 'unreadable', 'labuser')
      gp_verify(gp_call('unreadable'))
    end

    it "reports genuinely absent keyrings without loot through #{kind}" do
      ge_install
      gp_missing
      ge_session(kind, 'missing')
      call = gp_call('missing')
      gp_verify(call)
      expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('No users found with a GnuPG directory')
    end
  end
end
