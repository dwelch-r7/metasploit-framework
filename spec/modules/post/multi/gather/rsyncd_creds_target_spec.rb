require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/rsync_creds/native'

RSpec.describe 'Rsync credentials through genuine shell sessions', acceptance: true, order: :defined do
  include_context 'module target'
  include RsyncCredentialTarget

  before(:all) do
    @rc = { commands: [], native: [], sessions: [], session_reads: [], calls: [], reports: [], cleanup: [] }
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
      after = rc_native('after')
      expect(after.fetch('files')).to eq(@baseline.fetch('files'))
      expect(after.fetch('daemon')).to eq(@baseline.fetch('daemon'))
      rc_resources('after')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    end
  ensure
    rc_save
  end

  after do |example|
    rc_cleanup
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    (@rc[:cleanup_errors] ||= []) << { error: e.class.name, message: e.message }
    rc_save
    raise if example.exception.nil?
  end

  it 'reads target-only global configuration and records its credentials on repeated runs' do
    rc_session('global', 'root')
    first = rc_call('global', { 'USER_CONFIG' => '' })
    second = rc_call('repeat', { 'USER_CONFIG' => '' })
    expect(second.fetch(:module_id)).to eq(first.fetch(:module_id))
    [first, second].each { |call| verify_credentials(call) }
    expect(second.fetch(:credentials)).to eq(first.fetch(:credentials))
  end

  it 'handles default home configuration enumeration and missing user files' do
    rc_session('homes', 'root')
    call = rc_call('homes', {})
    verify_credentials(call)
    output = Base64.strict_decode64(call.fetch(:output_base64))
    expect(output).to include('RSYNC credentials from /root/rsyncd.conf')
  end

  it 'does not fabricate credentials when an ordinary shell cannot read the secrets' do
    rc_session('unreadable', 'labuser')
    call = rc_call('unreadable', { 'USER_CONFIG' => '' })
    expect(call.fetch(:credentials)).to eq([])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed')
  end

  it 'skips a missing selected daemon configuration with user enumeration disabled' do
    rc_session('missing', 'root')
    @rc[:missing_configuration] = rc_json('active_module.read_file("/etc/module-target-rsync-missing.conf")')
    expect(@rc[:missing_configuration]).to be_nil
    call = rc_call('missing', { 'RSYNCD_CONFIG' => '/etc/module-target-rsync-missing.conf', 'USER_CONFIG' => '' })
    expect(call.fetch(:credentials)).to eq([])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed')
  end

  it 'uses a custom home configuration when the selected daemon configuration is missing' do
    rc_session('custom', 'root')
    call = rc_call('custom', { 'RSYNCD_CONFIG' => '/etc/module-target-rsync-missing.conf', 'USER_CONFIG' => 'rsync-user.conf' })
    verify_credentials(call)
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('RSYNC credentials from /root/rsync-user.conf')
  end

  def verify_credentials(call)
    rows = call.fetch(:credentials)
    expect(rows.length).to eq(1)
    row = rows.first
    expect(row.values_at('username', 'private_data', 'private_type')).to eq(['labuser', 'labpassword', 'Metasploit::Credential::Password'])
    expect(row.values_at('origin_type', 'session_id', 'post_reference_name')).to eq(['Metasploit::Credential::Origin::Session', call.fetch(:session).fetch('db_id'), 'multi/gather/rsyncd_creds'])
    expect(row.values_at('address', 'port', 'proto', 'service', 'status', 'access_level', 'last_attempted_at')).to eq([call.fetch(:session).fetch('host'), 873, 'tcp', 'rsync', 'Untried', 'User', nil])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('labuser', 'labpassword', 'locked', 'Post module execution completed')
  end
end
