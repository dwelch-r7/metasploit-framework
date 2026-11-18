require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/suitecrm/acceptance'

RSpec.describe 'Native SuiteCRM usernames and collector roles', acceptance: true, order: :defined do
  include_context 'module target'
  include SuiteCrmTarget

  def sc_native_variant
    'names'
  end

  before(:all) do
    @rc = { commands: [], native: [], calls: [], reports: [] }
    @baseline = sc_native('before')
    expect(SuiteCrmTarget::NAMES.fetch('username')).to include(',', "'")
    expect(SuiteCrmTarget::NAMES.fetch('username').ascii_only?).to be(false)
    rc_resources('before')
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    observation = rc_json('begin;load "test/module_targets/suitecrm/observe.rb";SuiteCrmObservation.install(framework);end')
    expect(observation).to include('installed' => true, 'owner_sha256' => Digest::SHA256.file('modules/auxiliary/gather/suite_crm_export_sqli.rb').hexdigest, 'config' => ENV.fetch('MSF_CFGROOT_CONFIG'))
    socket = TCPServer.new('127.0.0.1', 0)
    @unused_port = socket.local_address.ip_port
    socket.close
  end

  before do |example|
    label = example.metadata.fetch(:scoped_id).tr('0123456789', 'abcdefghij').delete(':')
    @workspace = 'sc_' + Process.pid.to_s + '_' + label
    console_command('workspace -a ' + @workspace)
    expect(sc_reports).to eq([])
  end

  after do
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end

  after(:all) do
    if @baseline
      expect(sc_native('after')).to eq(@baseline)
      rc_resources('after')
      @rc[:owner_events] = rc_json('begin;framework.instance_variable_get(:@suitecrm_trace)&.disable;framework.instance_variable_get(:@suitecrm_events);end')
    end
  ensure
    rc_save
  end

  it 'checks both native collector identities with passive evidence' do
    [{}, { 'USERNAME' => SuiteCrmTarget::NAMES.fetch('username'), 'PASSWORD' => SuiteCrmTarget::NAMES.fetch('password') }].each_with_index do |options, index|
      _output, record = sc_call('role-check-' + index.to_s, options, action: 'check')
      expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'result' => include('code' => 'appears', 'reason' => include('7.12.5'))))
      expect(record.fetch(:credentials)).to eq([])
    end
  end

  it 'preserves native byte inference and lengths beyond the previous fixed ceiling' do
    native, = rc_command('native-encoded-length', 'db', 'mariadb', '--user=root', '--password=module-suite-db-root', '--batch', '--skip-column-names', 'suitecrm', '--execute=SELECT LENGTH(HEX(SPACE(800))); SELECT HEX(user_name) FROM users WHERE is_admin=0')
    expect(native.lines.map(&:strip)).to eq(['1600', '61C3A92C6F276E65696C'])
    endpoint = target_endpoint('app')
    console_command('use ' + SuiteCrmTarget::OWNER)
    values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'USERNAME' => 'labadmin', 'PASSWORD' => 'Module-suite-admin42!', 'VERBOSE' => true, 'HttpClientTimeout' => 10 }
    code = "begin;mod=active_module;mod.datastore.merge!(#{values.inspect});raise 'Native administrator authentication failed' unless mod.authenticate;sqli=mod.init_sqli;{length:sqli.send(:blind_detect_length,'select hex(space(800))',false),bytes_base64:Base64.strict_encode64(sqli.run_sql('select user_name from users where is_admin=0').b)};end"
    @rc[:encoded_length] = rc_json(code)
    rc_save
    expect(@rc.fetch(:encoded_length)).to eq('length' => 1600, 'bytes_base64' => 'YcOpLG8nbmVpbA==')
    expect(sc_reports).to eq([])
  end

  it 'preserves names and exact hashes while changing the configured count from one to all' do
    _output, first = sc_call('admin-count-one', { 'COUNT' => 1 })
    sc_success(first, count: 1)
    _output, repeated = sc_call('admin-count-all', { 'COUNT' => 0, 'AutoCheck' => false }, reuse: true)
    sc_success(repeated, count: @baseline.fetch('users').length)
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  end

  it 'collects through the nonadministrator identity twice with both AutoCheck modes' do
    options = { 'USERNAME' => SuiteCrmTarget::NAMES.fetch('username'), 'PASSWORD' => SuiteCrmTarget::NAMES.fetch('password'), 'COUNT' => 1 }
    _output, first = sc_call('nonadmin-first', options)
    sc_success(first, count: 1)
    _output, repeated = sc_call('nonadmin-repeat', options.merge('AutoCheck' => false), reuse: true)
    sc_success(repeated, count: 1)
    expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
  end

  it 'refuses the native special username with a wrong password through AutoCheck' do
    _output, record = sc_call('nonadmin-wrong-check', { 'USERNAME' => SuiteCrmTarget::NAMES.fetch('username'), 'PASSWORD' => 'Module-wrong-password42!' }, expected_method: 'check', allow_failure: true, timeout: 60)
    expect(record.fetch(:credentials)).to eq([])
    expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'result' => include('code' => 'unknown')))
    expect(record.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'run'))
  end

  it 'refuses the native special username with a wrong password and AutoCheck disabled' do
    output, record = sc_call('nonadmin-wrong-run', { 'USERNAME' => SuiteCrmTarget::NAMES.fetch('username'), 'PASSWORD' => 'Module-wrong-password42!', 'AutoCheck' => false }, allow_failure: true, timeout: 60)
    expect(output).to match(/no-access|authenticate/i)
    expect(record.fetch(:credentials)).to eq([])
    expect(record.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'get_user_names'))
  end
end
