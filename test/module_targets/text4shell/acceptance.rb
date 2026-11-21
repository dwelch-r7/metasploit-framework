# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Real script-engine/interpolator/HTTP prerequisites precede original owner calls.
module Text4shellTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/apache_commons_text4shell'
  SOURCE = 'modules/exploits/multi/http/apache_commons_text4shell.rb'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'text4shell-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def tc_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/text4shell/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def tc_preserved
    expect(tc_native('snapshot')).to eq(@rc.fetch(:readiness).fetch('baseline'))
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end

  def tc_ready
    @rc[:readiness] = tc_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => ENV.fetch('TEXT4SHELL_VERSION'), 'method' => ENV.fetch('TEXT4SHELL_METHOD'), 'module_invoked' => false)
    @rc[:stopwatch_before_selection] = rc_json('defined?(Rex::Stopwatch)')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/text4shell/observe.rb';Text4shellObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    rc_resources('before')
    tc_preserved
  end

  def tc_events(call, method, event = 'call')
    call.fetch(:events).select { |row| row.values_at('method', 'event') == [method, event] && File.realpath(row.fetch('source')) == File.realpath(SOURCE) }
  end

  def tc_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@text4shell_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    settings = { 'SSL' => false, 'TARGETURI' => '/text4shell/attack', 'PARAM' => 'search', 'METHOD' => ENV.fetch('TEXT4SHELL_METHOD') }.merge(options)
    run_target_module(OWNER, 'target', settings, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 40) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@text4shell_events).drop(#{offset})")
      call[:selection] = rc_json('{object:active_module.object_id,target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],autocheck:active_module.class.ancestors.include?(Msf::Exploit::Remote::AutoCheck),stopwatch:defined?(Rex::Stopwatch)}')
      rc_save
    end
    expect(call.fetch(:output)).not_to include('Error while running command')
    tc_preserved
    call
  end

  def tc_checks
    expected = ENV.fetch('TEXT4SHELL_VERSION') == '1.8' ? { 'code' => 'vulnerable', 'reason' => 'Successfully tested command injection.' } : { 'code' => 'safe', 'reason' => 'Command injection test failed.' }
    calls = 2.times.map { |index| tc_call('check-' + index.to_s, reuse: index.positive?) }
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    calls.each do |call|
      expect(tc_events(call, 'check', 'return').map { |row| row['check'] }).to eq([expected])
      expect(tc_events(call, 'exploit')).to eq([])
      requests = call.fetch(:events).filter_map { |row| row['request'] }
      expect(requests.length).to eq(2)
      expect(requests).to all(include('method' => ENV.fetch('TEXT4SHELL_METHOD'), 'uri' => '/text4shell/attack'))
    end
  end

  def tc_commands
    @rc.fetch(:readiness).fetch('controls').each_with_index do |control, index|
      path = control.fetch('path')
      expect(tc_native('file', path)).to eq('exists' => false)
      if index.zero?
        console_command('back')
        console_command('use ' + OWNER)
        console_command('set TARGET 3')
        console_command('set PAYLOAD cmd/unix/generic')
      end
      # Preserve quotes, Unicode and physical CR/LF across the console parser.
      expect(rc_json("begin;active_module.datastore['CMD']=#{control.fetch('command').inspect};true;end")).to be(true)
      call = tc_call(control.fetch('label'), { 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, action: 'run -z', reuse: true)
      @rc[:command_selection] ||= call.fetch(:selection).fetch('object')
      expect(call.fetch(:selection)).to include('object' => @rc.fetch(:command_selection), 'target' => 3, 'payload' => 'cmd/unix/generic', 'autocheck' => false)
      expect(tc_events(call, 'exploit').length).to eq(1)
      expect(tc_events(call, 'check')).to eq([])
      expect(tc_events(call, 'execute_command').map { |row| row['command'] }).to eq([control.fetch('command')])
      requests = call.fetch(:events).filter_map { |row| row['request'] }
      expect(requests.length).to eq(1)
      values = requests.first.fetch(ENV.fetch('TEXT4SHELL_METHOD') == 'GET' ? 'query' : 'form')
      expect(values.fetch('search')).to include(Base64.strict_encode64(control.fetch('command').b))
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Exploit aborted')
      physical = if ENV.fetch('TEXT4SHELL_VERSION') == '1.8'
                   rc_poll(5) do
                     value = tc_native('file', path)
                     value if value.fetch('exists')
                   end
                 else
                   tc_native('file', path)
                 end
      call[:physical] = physical
      rc_save
      expect(physical).to eq(ENV.fetch('TEXT4SHELL_VERSION') == '1.8' ? { 'exists' => true, 'uid' => 1000, 'base64' => control.fetch('marker_base64') } : { 'exists' => false })
    ensure
      expect(tc_native('file', path, 'remove')).to eq('exists' => false) if path
      rc_save
    end
  end

  def tc_wrong_parameter
    call = tc_call('wrong-parameter', { 'PARAM' => 'unconsumed_parameter' })
    expect(tc_events(call, 'check', 'return').map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Command injection test failed.' }])
    if ENV.fetch('TEXT4SHELL_METHOD') == 'GET'
      call = tc_call('unsupported-post', { 'METHOD' => 'POST' })
      expect(tc_events(call, 'check', 'return').map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Command injection test failed.' }])
      expect(call.fetch(:events).filter_map { |row| row['response'] }.map { |row| row.fetch('code') }).to eq([405, 405])
    end
  end

  def tc_refused
    socket = TCPServer.new('127.0.0.1', 0)
    port = socket.local_address.ip_port
    socket.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = tc_call('refused-check', { 'RPORT' => port, 'HttpClientTimeout' => 2 })
    expect(tc_events(call, 'check', 'return').map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'No response received from target.' }])
    call = tc_call('refused-exploit', { 'RPORT' => port, 'HttpClientTimeout' => 2, 'TARGET' => 3, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }, action: 'run -z', reuse: true)
    expect(tc_events(call, 'execute_command').length).to eq(1)
    expect(call.fetch(:events).filter_map { |row| row['error'] }).to include(include('type' => 'Msf::Exploit::Failed', 'reason' => 'unreachable', 'message' => 'No response received from the target'))
  ensure
    socket&.close unless socket&.closed?
  end

  def tc_cleanup
    return unless @rc && @rc[:calibrated]

    tc_preserved
    rc_resources('after')
    rc_save
  end
end
