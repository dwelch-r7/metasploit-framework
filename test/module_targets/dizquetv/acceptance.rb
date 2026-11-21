# frozen_string_literal: true

require 'shellwords'
require_relative '../rsync_creds/native'

# Independent API, database and exact-command controls precede owning verdicts.
module DizquetvTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/dizquetv_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'dizquetv-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def dq_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/dizquetv/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def dq_registry
    expect(dq_native('snapshot')).to eq(@rc.fetch(:readiness).fetch('baseline'))
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end

  def dq_ready
    @rc[:readiness] = dq_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => self.class.metadata.fetch(:dizquetv_version), 'module_invoked' => false)
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/dizquetv/observe.rb';DizquetvObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    dq_registry
  end

  def dq_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@dizquetv_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    run_target_module(OWNER, 'target', { 'SSL' => false }.merge(options), action: action, reuse_module: reuse, allow_errors: true, command_timeout: 60) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@dizquetv_events).drop(#{offset})")
      call[:selection] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def dq_check
    version = self.class.metadata.fetch(:dizquetv_version)
    call = dq_call('check')
    expected = version == '1.5.3' ? { 'code' => 'appears', 'reason' => 'dizqueTV 1.5.3 is vulnerable' } : { 'code' => 'safe', 'reason' => 'dizqueTV 1.5.5 is patched' }
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([expected])
    expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
    dq_registry
  end

  def dq_closed_port
    socket = TCPServer.new('127.0.0.1', 0)
    port = socket.local_address.ip_port
    socket.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = dq_call('closed-port', { 'RPORT' => port, 'HttpClientTimeout' => 2 })
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'No response from target' }])
    expect(call.fetch(:events).select { |row| row['response'] }).to eq([])
    dq_registry
  ensure
    socket&.close unless socket&.closed?
  end

  def dq_select_command(command, fallback, reuse:)
    unless reuse
      console_command('back')
      expect(console_command('use ' + OWNER)).not_to match(/Failed to load|Unknown command|No results/)
      console_command('set TARGET 0')
      console_command('set AllowNoCleanup true')
      expect(console_command('set PAYLOAD cmd/unix/generic')).not_to match(/Failed|Invalid|not found/)
    end
    # Direct assignment preserves physical CR/LF across the console line parser.
    expect(rc_json("begin;active_module.datastore['COMMAND']=#{command.inspect};active_module.datastore['CMD']=#{fallback.inspect};true;end")).to be(true)
  end

  def dq_commands(label, marker, via_payload: false)
    2.times do |iteration|
      path = "/tmp/module-target-dizquetv-owner-#{Process.pid}-#{label}-#{iteration}"
      sentinel = path + '-payload'
      expected = marker + iteration.to_s + "\n"
      command = 'printf %s ' + Shellwords.escape(expected) + ' | tee ' + path
      expect(dq_native('file', path)).to eq('exists' => false)
      expect(dq_native('file', sentinel)).to eq('exists' => false)
      control = dq_native('command-control', Base64.strict_encode64(command.b), path, Base64.strict_encode64(expected.b))
      expect(control).to include('passed' => true, 'vulnerable' => true, 'command_base64' => Base64.strict_encode64(command.b))
      expect(dq_native('file', path)).to eq('exists' => false)
      dq_select_command(via_payload ? '' : command, via_payload ? command : 'printf payload-must-not-run > ' + sentinel, reuse: iteration.positive?)
      call = dq_call(label + '-' + iteration.to_s,
                     { 'AutoCheck' => iteration.zero?, 'ForceExploit' => false, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: true)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:selection)) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      events = call.fetch(:events)
      expect(events.count { |row| row['owner_exploit_body'] }).to eq(1)
      expect(events.filter_map { |row| row['command_base64'] }).to eq([Base64.strict_encode64(command.b)])
      expect(events.filter_map { |row| row['output_base64'] }).to eq([Base64.strict_encode64(expected.b)])
      expect(events.filter_map { |row| row['original_settings_cleared'] }).to eq([true])
      expect(events.select { |row| row['event'] == 'call' && row['method'] == 'upload_script' }).to eq([])
      expect(call.fetch(:output)).not_to include('Exploit failed', 'Exploit aborted')
      expect(call.fetch(:output)).to include('Command output (')
      expect(dq_native('file', path)).to eq('exists' => true, 'uid' => 0, 'base64' => Base64.strict_encode64(expected.b))
      expect(dq_native('file', sentinel)).to eq('exists' => false)
      dq_registry
    ensure
      dq_native('remove', path) if path
      dq_native('remove', sentinel) if sentinel
      rc_save
    end
  end

  def dq_bad_config
    path = "/tmp/module-target-dizquetv-guard-#{Process.pid}"
    dq_select_command('printf guard-must-not-run > ' + path, 'printf generic-unused', reuse: false)
    [{ 'MAXWAIT' => 0, 'POLL_INTERVAL' => 1 }, { 'MAXWAIT' => 1, 'POLL_INTERVAL' => 0 }].each_with_index do |values, index|
      call = dq_call('bad-config-' + index.to_s, { 'AutoCheck' => false, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }.merge(values), action: 'run -z', reuse: true)
      expect(call.fetch(:events).filter_map { |row| row['error'] }.select { |row| row['type'] == 'Msf::Exploit::Failed' }).to include('type' => 'Msf::Exploit::Failed', 'message' => 'MAXWAIT and POLL_INTERVAL must be greater than zero', 'reason' => 'bad-config')
      expect(call.fetch(:events).select { |row| row['request'] }).to eq([])
      expect(dq_native('file', path)).to eq('exists' => false)
      dq_registry
    end
  ensure
    dq_native('remove', path) if path
  end

  def dq_refusal
    path = "/tmp/module-target-dizquetv-refused-#{Process.pid}"
    2.times do |iteration|
      dq_select_command('printf must-not-run > ' + path, 'printf generic-unused', reuse: iteration.positive?)
      call = dq_call('patched-refusal-' + iteration.to_s,
                     { 'AutoCheck' => true, 'ForceExploit' => false, 'AllowNoCleanup' => true, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                     action: 'run -z', reuse: true)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:selection)) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'dizqueTV 1.5.5 is patched' }])
      expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
      expect(call.fetch(:events).filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/api/version', 'data_base64' => nil }])
      expect(dq_native('file', path)).to eq('exists' => false)
      dq_registry
    end
  ensure
    dq_native('remove', path) if path
  end
end
