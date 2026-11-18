require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/suitecrm/acceptance'

RSpec.describe 'Native SuiteCRM export credential collection', acceptance: true, order: :defined do
  include_context 'module target'
  include SuiteCrmTarget

  before(:all) do
    @rc = { commands: [], native: [], calls: [], reports: [] }
    @baseline = sc_native('before')
    @affected = @baseline.fetch('version') == '7.12.5'
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

  it 'reports reason-bearing passive detection or a fixed release twice' do
    2.times do |index|
      _output, record = sc_call('check-' + index.to_s, {}, action: 'check', reuse: index.positive?)
      expected = @affected ? 'appears' : 'safe'
      results = record.fetch(:events).select { |event| event.values_at('event', 'method') == %w[return check] }
      expect(results.last.fetch('result')).to include('code' => expected, 'reason' => include(@baseline.fetch('version')))
      expect(record.fetch(:credentials)).to eq([])
    end
  end

  it 'honors COUNT=1 twice with both AutoCheck modes or refuses the patched target' do
    if @affected
      _output, first = sc_call('count-one-first', { 'COUNT' => 1 })
      sc_success(first, count: 1)
      _output, repeated = sc_call('count-one-repeat', { 'COUNT' => 1, 'AutoCheck' => false }, reuse: true)
      sc_success(repeated, count: 1)
      expect(repeated.fetch(:identity)).to eq(first.fetch(:identity))
    else
      sc_refusal('count-one-patched', { 'COUNT' => 1 })
      sc_refusal('count-one-patched-repeat', { 'COUNT' => 1 }, reuse: true)
    end
  end

  it 'collects all native hashes with COUNT=0 or refuses the patched target' do
    if @affected
      _output, record = sc_call('count-all', { 'COUNT' => 0, 'AutoCheck' => false })
      sc_success(record, count: @baseline.fetch('users').length)
    else
      sc_refusal('count-all-patched', { 'COUNT' => 0 })
    end
  end

  it 'collects the default bounded set or refuses the patched target' do
    if @affected
      _output, record = sc_call('default-count')
      sc_success(record, count: 3)
    else
      sc_refusal('default-count-patched')
    end
  end

  it 'refuses bad credentials through AutoCheck without collecting credentials' do
    _output, record = sc_call('wrong-password-check', { 'PASSWORD' => 'Module-wrong-password42!' }, expected_method: 'check', allow_failure: true, timeout: 60)
    expect(record.fetch(:credentials)).to eq([])
    expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'result' => include('code' => 'unknown')))
    expect(record.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'run'))
  end

  it 'refuses bad credentials with AutoCheck disabled' do
    output, record = sc_call('wrong-password-run', { 'PASSWORD' => 'Module-wrong-password42!', 'AutoCheck' => false }, allow_failure: true, timeout: 60)
    expect(output).to match(/no-access|authenticate/i)
    expect(record.fetch(:credentials)).to eq([])
    expect(record.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'get_user_names'))
  end

  it 'rejects a negative COUNT or refuses the patched target' do
    if @affected
      output, record = sc_call('negative-count', { 'COUNT' => -1, 'AutoCheck' => false }, allow_failure: true, timeout: 60)
      expect(output).to match(/bad-config.*COUNT/i)
      expect(record.fetch(:credentials)).to eq([])
    else
      sc_refusal('negative-count-patched', { 'COUNT' => -1 })
    end
  end

  it 'returns an unknown check for a refused connection' do
    _output, record = sc_call('closed-port', { 'RPORT' => @unused_port }, action: 'check', allow_failure: true, timeout: 60)
    expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'result' => include('code' => 'unknown')))
    expect(record.fetch(:credentials)).to eq([])
  end
end
