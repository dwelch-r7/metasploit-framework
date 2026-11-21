# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Independent installation, PHP execution and exact option recovery gate checks.
module ProjectsendTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/linux/http/projectsend_unauth_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'projectsend-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[target database]
  end

  def ps_native(action)
    argv = ['python3', '-B', 'test/module_targets/projectsend/native_probe.py', action]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def ps_ready
    @rc[:readiness] = ps_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => 'r1605', 'module_invoked' => false)
    rc_resources('before')
    @rc[:observer] = rc_json("begin;load 'test/module_targets/projectsend/observe.rb';ProjectsendObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    expect(ps_native('snapshot')).to eq(@rc.fetch(:readiness).fetch('baseline'))
  end

  def ps_call(label, options = {}, reuse: false)
    offset = rc_json('framework.instance_variable_get(:@projectsend_events).length')
    call = { label: label, options: options }
    @rc[:calls] << call
    run_target_module(OWNER, 'target', { 'SSL' => false }.merge(options), action: 'check', reuse_module: reuse, allow_errors: true, command_timeout: 45) do |output|
      call[:output] = output
      call[:selection] = rc_json('active_module.object_id')
      call[:events] = rc_json("framework.instance_variable_get(:@projectsend_events).drop(#{offset})")
      call[:actual_options] = ps_native('snapshot')
      rc_save
    end
    call
  end

  def ps_check
    2.times do |iteration|
      call = ps_call('check-' + iteration.to_s, reuse: iteration.positive?)
      expect(call.fetch(:selection)).to eq(@rc.fetch(:selection)) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'appears', 'reason' => 'The target appears to be vulnerable' }])
      expect(call.fetch(:events).select { |row| row['event'] == 'call' && row['method'] == 'exploit' }).to eq([])
      expect(call.fetch(:actual_options)).to eq(@rc.fetch(:readiness).fetch('baseline'))
      expect(call.fetch(:output)).not_to include('Error while running command', 'Exploit failed')
    ensure
      # Retain the actual owning diff before separate fixture restoration so a
      # broken check cannot contaminate later negative controls.
      ps_native('restore-baseline') if call && call[:actual_options] != @rc.fetch(:readiness).fetch('baseline')
      rc_save
    end
  end

  def ps_closed_port
    socket = TCPServer.new('127.0.0.1', 0)
    port = socket.local_address.ip_port
    socket.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = ps_call('closed-port', { 'RPORT' => port, 'HttpClientTimeout' => 2 })
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'Target is not reachable' }])
    expect(call.fetch(:events).filter_map { |row| row['request'] }).to eq([{ 'method' => 'GET', 'uri' => '/index.php', 'vars_get' => nil, 'vars_post' => nil }])
    expect(call.fetch(:actual_options)).to eq(@rc.fetch(:readiness).fetch('baseline'))
    expect(call.fetch(:output)).not_to include('Error while running command')
  ensure
    socket&.close unless socket&.closed?
  end
end
