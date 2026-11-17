# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Uses the existing real Linux session context with a capped network console.
module PgpassCredentialTarget
  include RsyncCredentialTarget

  def rc_owner
    'post/multi/gather/pgpass_creds'
  end

  def rc_resource_roles
    %w[linux reporting_db framework]
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'pgpass-credentials.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def pg_native(phase)
    output, = rc_command(phase + '-native', 'linux', 'python3', '/opt/pgpass-native.py')
    data = JSON.parse(output)
    @rc.fetch(:native) << { phase: phase, data: data }
    rc_save
    expect(data.values_at('native_passed', 'hostname', 'uid')).to eq([true, 'module-target-pgpass', 0])
    data
  end

  def pg_install(fixture)
    @pg_case = { fixture: fixture }
    @rc.fetch(:cases) << @pg_case
    rc_save
    output, = rc_command('install-' + fixture, 'linux', 'python3', '/opt/pgpass-case-state.py', 'install', fixture)
    @pg_case[:native] = JSON.parse(output)
    expect(@pg_case.fetch(:native).fetch('native_passed')).to be(true)
    rc_save
  end

  def pg_restore
    return unless @pg_case

    output, = rc_command('restore-pgpass', 'linux', 'python3', '/opt/pgpass-case-state.py', 'restore', @pg_case.fetch(:fixture))
    @pg_case[:recovery] = JSON.parse(output)
    rc_save
    expect(@pg_case.fetch(:recovery).fetch('absent')).to be(true)
    expect(@pg_case.fetch(:recovery).fetch('was_present')).to be(true) if @pg_case.key?(:native)
    @pg_case = nil
  end

  def pg_session(kind, label)
    @workspace = "pg_#{Process.pid}_#{kind}_#{label}"
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    expect(rc_json('framework.sessions.keys')).to eq([])
    @delivery = { payload: "linux/x64/#{kind == 'shell' ? 'shell' : 'meterpreter'}_reverse_tcp", format: 'elf', file: kind + '-session.elf' }
    log_path = File.join(target_runtime.fetch('artifacts'), 'native-commands.jsonl')
    previous_lines = File.exist?(log_path) ? File.readlines(log_path).length : 0
    identifier = open_native_session(kind, @delivery).to_i
    @payload_sha = Digest::SHA256.file(File.join(target_runtime.fetch('artifacts'), @delivery.fetch(:file))).hexdigest
    records = File.readlines(log_path).drop(previous_lines).map { |line| JSON.parse(line) }
    launch = records.find { |row| row.fetch('service') == 'linux' && row.fetch('argv').first(2) == ['python3', '/opt/launch_session.py'] }
    expect(launch).not_to be_nil
    @launch = JSON.parse(launch.fetch('output'))
    @session = rc_poll(60) do
      value = rc_json("begin;s=framework.sessions.fetch(#{identifier});{id:#{identifier},type:s.type,platform:s.platform,host:s.session_host,db_id:s.db_record&.id};end")
      value if value['db_id']
    end
    expect(@session.values_at('type', 'platform', 'host')).to eq([kind, 'linux', target_runtime.fetch('module_endpoints').fetch('linux').fetch('host')])
    @session_row = { label: label, kind: kind, session: @session, launch: @launch, payload_sha256: @payload_sha }
    @rc.fetch(:sessions) << @session_row
    rc_save
    if kind == 'meterpreter'
      # open_native_session already waits for this native touch and verifies UID.
      @proof_path = '/tmp/module-target-session-proof'
      proof = rc_json("begin;s=framework.sessions.fetch(#{identifier});{id:#{identifier},type:s.type,pid:s.sys.process.getpid,identity:s.sys.config.getuid,expected:''};end")
    else
      @proof_path = "/tmp/module-target-druid-session-#{Process.pid}_#{identifier}-#{identifier}"
      proof = rc_json("DruidSessionControl.proof(framework,#{identifier},#{@proof_path.inspect})")
    end
    @proof_sha = Digest::SHA256.hexdigest(proof.fetch('expected'))
    @session_row[:proof] = proof
    rc_save
    output, = rc_command('session-identity', 'linux', 'python3', '/opt/pgpass-process-state.py', 'identity', proof.fetch('pid').to_s)
    @identity = JSON.parse(output)
    @session_row[:native_identity] = @identity
    rc_save
    expect(@identity.values_at('alive', 'uid')).to eq([true, 0])
    expect(@identity.fetch('state')).not_to eq('Z')
    uid, = rc_command('marker-uid', 'linux', 'stat', '-c', '%u', @proof_path)
    expect(uid.strip).to eq('0')
    console_command('back')
    console_command('use ' + rc_owner)
    console_command("set SESSION #{identifier}")
    code = 'begin;require "base64";source="modules/post/multi/gather/pgpass_creds.rb";{sha256:Digest::SHA256.file(source).hexdigest,source:active_module.method(:run).source_location,source_matches:File.realpath(active_module.method(:run).source_location.first)==File.realpath(source),data:Base64.strict_encode64(active_module.read_file("/root/.pgpass"))};end'
    observed = rc_json(code)
    @rc.fetch(:reads) << observed
    rc_save
    expect(observed.fetch('source_matches')).to be(true)
    expect(observed.fetch('sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/pgpass_creds.rb').hexdigest)
    expect(Digest::SHA256.hexdigest(Base64.strict_decode64(observed.fetch('data')))).to eq(@pg_case.fetch(:native).fetch('sha256'))
  end

  def pg_reports
    expect(@workspace).to match(/\Apg_\d+_[a-z_]+\z/)
    cores = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,
          realm.key AS realm_key,realm.value AS realm_value,c.origin_type,os.session_id,os.post_reference_name,
          l.id AS login_id,l.status,l.access_level,l.last_attempted_at,s.port,s.proto,s.name AS service,host(h.address::inet) AS address
        FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
        LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
        LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
        LEFT JOIN metasploit_credential_realms realm ON realm.id=c.realm_id
        LEFT JOIN metasploit_credential_origin_sessions os ON os.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Session'
        LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
        LEFT JOIN services s ON s.id=l.service_id LEFT JOIN hosts h ON h.id=s.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    loot = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT l.id,l.ltype,l.content_type,l.path,l.info,host(h.address::inet) AS address
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    loot.each do |row|
      path = File.realpath(row.fetch('path'))
      expect(path).to start_with(File.realpath(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/loot/')
      raw = File.binread(path)
      row['base64'] = Base64.strict_encode64(raw)
      row['sha256'] = Digest::SHA256.hexdigest(raw)
    end
    report = { workspace: @workspace, cores: cores, loot: loot }
    @rc.fetch(:reports) << report
    rc_save
    report
  end

  def pg_call(label)
    prior = pg_reports.fetch(:loot).map { |row| row.fetch('id') }
    call = { label: label, workspace: @workspace, session: @session, fixture: @pg_case.fetch(:native), started: true }
    @rc.fetch(:calls) << call
    run_target_module(rc_owner, 'linux', { 'SESSION' => @session.fetch('id') }, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:report] = pg_reports
      call[:new_loot] = call.fetch(:report).fetch(:loot).reject { |row| prior.include?(row.fetch('id')) }
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def pg_verify(call)
    expected = call.fetch(:fixture).fetch('expected')
    expect(call.fetch(:new_loot).length).to eq(1)
    loot = call.fetch(:new_loot).first
    expect(loot.values_at('ltype', 'content_type', 'info', 'address')).to eq(['postgres.pgpass', 'text/plain', 'pgpass /root/.pgpass file', call.fetch(:session).fetch('host')])
    expect(loot.fetch('base64')).to eq(call.fetch(:fixture).fetch('base64'))
    rows = call.fetch(:report).fetch(:cores)
    expect(rows.length).to eq(1)
    row = rows.first
    expect(row.values_at('username', 'private_data', 'private_type', 'realm_key', 'realm_value')).to eq([expected.fetch('user'), expected.fetch('password'), 'Metasploit::Credential::Password', @realm_key, expected.fetch('database')])
    expect(row.values_at('origin_type', 'session_id', 'post_reference_name')).to eq(['Metasploit::Credential::Origin::Session', call.fetch(:session).fetch('db_id'), 'multi/gather/pgpass_creds'])
    expect(row.values_at('address', 'port', 'proto', 'service', 'status', 'access_level', 'last_attempted_at')).to eq([call.fetch(:session).fetch('host'), 5432, 'tcp', 'postgres', 'Untried', 'User', nil])
    expect(Base64.strict_decode64(call.fetch(:output_base64))).to include('Post module execution completed')
  end

  def pg_cleanup
    if @session
      @rc.fetch(:cleanup) << { session: @session }
      row = @rc.fetch(:cleanup).last
      row[:request] = rc_json("DruidSessionControl.exit_remote(framework,#{@session.fetch('id')})")
      output, = rc_command('session-stop', 'linux', 'python3', '/opt/pgpass-process-state.py', 'stop', JSON.generate(@identity))
      row[:process] = JSON.parse(output)
      expect(row.fetch(:process).fetch('absent')).to be(true)
      console_command("sessions -k #{@session.fetch('id')}") if rc_json('framework.sessions.keys').include?(@session.fetch('id'))
      rc_poll { !rc_json('framework.sessions.keys').include?(@session.fetch('id')) }
      rc_poll { rc_sql("SELECT closed_at IS NOT NULL FROM sessions WHERE id=#{@session.fetch('db_id')}").strip == 't' }
      console_command('jobs -K')
      output, = rc_command('remove-session-artifacts', 'linux', 'python3', '/opt/pgpass-process-state.py', 'artifacts', @delivery.fetch(:file), @payload_sha, @proof_path, @proof_sha)
      row[:artifacts] = JSON.parse(output)
      row[:database_session_closed] = true
      rc_save
    end
  ensure
    rc_save
    @session = @session_row = @launch = @identity = @delivery = @payload_sha = @proof_path = @proof_sha = nil
  end
end
