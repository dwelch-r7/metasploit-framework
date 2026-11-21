# frozen_string_literal: true

require_relative '../rsync_creds/native'

# Genuine expression controls gate the original owner and fixed-release refusal.
module N8nExpressionTarget
  include RsyncCredentialTarget

  OWNER = 'exploit/multi/http/n8n_workflow_expression_rce'

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'n8n-expression-owner.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    ['target']
  end

  def n8n_native(action, *arguments)
    argv = ['python3', '-B', 'test/module_targets/n8n_expression/native_probe.py', action, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { action: action, argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def n8n_registry
    value = n8n_native('registry')
    expect(value).to eq('preserved' => true, 'flow_ids' => @rc.fetch(:readiness).fetch('foreign_ids'))
    expect(rc_json('{sessions:framework.sessions.keys,jobs:framework.jobs.keys}')).to eq('sessions' => [], 'jobs' => [])
  end

  def n8n_ready
    @rc[:readiness] = n8n_native('before')
    expect(@rc.fetch(:readiness)).to include('passed' => true, 'version' => ENV.fetch('N8N_TARGET_VERSION'))
    @rc[:observer] = rc_json("begin;load 'test/module_targets/n8n_expression/observe.rb';N8nExpressionObservation.install(framework,#{target_runtime.fetch('artifacts').inspect});end")
    @rc[:calibrated] = true
    rc_resources('before')
    n8n_registry
  end

  def n8n_call(label, options = {}, action: 'check', reuse: false)
    offset = rc_json('framework.instance_variable_get(:@n8n_expression_events).length')
    call = { label: label, options: options, action: action }
    @rc[:calls] << call
    settings = @rc.fetch(:readiness).fetch('credentials').merge('SSL' => false).merge(options)
    run_target_module(OWNER, 'target', settings, action: action, reuse_module: reuse, allow_errors: true, command_timeout: 60) do |output|
      call[:output] = output
      call[:events] = rc_json("framework.instance_variable_get(:@n8n_expression_events).drop(#{offset})")
      call[:selection] = rc_json('active_module.object_id')
      rc_save
    end
    call
  end

  def n8n_check
    call = n8n_call('check')
    fixed = ENV.fetch('N8N_TARGET_VERSION') == '1.120.4'
    expected = { 'code' => fixed ? 'safe' : 'appears', 'reason' => "Version #{ENV.fetch('N8N_TARGET_VERSION')} is #{fixed ? 'not vulnerable' : 'vulnerable'}" }
    results = call.fetch(:events).filter_map { |row| row['check'] }
    @rc[:fixed_safe] = results == [expected] if fixed
    expect(results).to eq([expected])
    expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
    n8n_registry
  end

  def n8n_bad_password
    call = n8n_call('bad-password', { 'PASSWORD' => 'ModuleTarget-wrong-123!' })
    expect(call.fetch(:events).filter_map { |row| row['response'] }.map { |row| row['code'] }).to eq([401])
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'Could not authenticate to n8n' }])
    expect(call.fetch(:events).select { |row| row['owner_exploit_body'] }).to eq([])
    n8n_registry
  end

  def n8n_closed_port
    server = TCPServer.new('127.0.0.1', 0)
    port = server.local_address.ip_port
    server.close
    expect { TCPSocket.new('127.0.0.1', port) }.to raise_error(Errno::ECONNREFUSED)
    call = n8n_call('closed-port', { 'RPORT' => port, 'HttpClientTimeout' => 2 })
    expect(call.fetch(:events).filter_map { |row| row['check'] }).to eq([{ 'code' => 'unknown', 'reason' => 'Could not authenticate to n8n' }])
    expect(call.fetch(:events).filter_map { |row| row['response'] }).to eq([])
    n8n_registry
  ensure
    server&.close unless server&.closed?
  end

  def n8n_commands
    2.times do |iteration|
      path = "/tmp/module-target-n8n-expression-owner-#{Process.pid}-#{iteration}"
      marker = "Owner #{iteration} 'quote' \\ Unicode雪\r\nEnd\n".encode(Encoding::UTF_8).b
      expect(n8n_native('file', path)).to eq('exists' => false)
      command = 'printf %s ' + Base64.strict_encode64(marker) + ' | base64 -d > ' + path
      # The payload contract excludes apostrophes; encode proof data rather
      # than claiming the original command transport accepts forbidden bytes.
      call = n8n_call('command-' + iteration.to_s,
                      { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'AutoCheck' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 },
                      action: 'run -z', reuse: iteration.positive?)
      expect(call.fetch(:selection)).to eq(@rc[:selection]) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      events = call.fetch(:events)
      expect(events.count { |row| row['owner_exploit_body'] }).to eq(1)
      expect(events.filter_map { |row| row['command_base64'] }).to eq([Base64.strict_encode64(command.b)])
      actual = rc_poll(8) do
        value = n8n_native('file', path)
        value if value.fetch('exists')
      end
      expect(actual).to eq('exists' => true, 'uid' => 1000, 'base64' => Base64.strict_encode64(marker))
      n8n_registry
    ensure
      n8n_native('remove', path) if path
    end
  end

  def n8n_withhold
    2.times do |iteration|
      options = { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'printf fixed_must_not_run', 'AutoCheck' => true, 'ForceExploit' => false, 'DisablePayloadHandler' => true, 'WfsDelay' => 0 }
      call = n8n_call('withhold-' + iteration.to_s, options, action: 'run -z', reuse: iteration.positive?)
      expect(call.fetch(:selection)).to eq(@rc[:selection]) if iteration.positive?
      @rc[:selection] = call.fetch(:selection)
      expect(call.fetch(:output)).to include('The target is not exploitable.')
      events = call.fetch(:events)
      expect(events.filter_map { |row| row['check'] }).to eq([{ 'code' => 'safe', 'reason' => 'Version 1.120.4 is not vulnerable' }])
      expect(events.select { |row| row['owner_exploit_body'] || row['command_base64'] || row['workflow_id'] }).to eq([])
      expect(events.filter_map { |row| row['request'] }.map { |row| row.values_at('method', 'uri') }).to eq([['POST', '/rest/login'], ['GET', '/rest/settings']])
      n8n_registry
    end
  end
end
