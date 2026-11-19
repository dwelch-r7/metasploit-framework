# frozen_string_literal: true

require_relative '../kafka_ui/sessions'
require_relative 'commands'

# Reuse the genuine handler/session/report/cleanup assertions with Kong delivery.
module KongGatewaySessions
  include KafkaUiSessionTarget
  include KongGatewayTarget

  FAMILIES = {
    'bash' => ['cmd/unix/reverse_bash', 'shell', nil],
    'netcat' => KafkaUiSessionTarget::FAMILIES.fetch('netcat')
  }.freeze

  def ks_families
    FAMILIES
  end

  def rc_resource_roles
    ENV.fetch('KONG_EXPECT_PLUGIN') == 'true' ? %w[app database reporting_db] : %w[app database]
  end

  def ks_native(script, operation, *)
    return kg_native(operation, *) if script == 'native.py'

    argv = ['python3', 'test/module_targets/kong_gateway/controls.py', ENV.fetch('MODULE_TARGET_RUNTIME'), script, operation, *]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    result = JSON.parse(output)
    expect(result.fetch('passed')).to be(true)
    result.fetch('data')
  end

  def ks_owner_fullname
    KongGatewayTarget::OWNER
  end

  def ks_owner_events
    kg_events
  end

  def ks_session(family, **)
    offset = @rc.fetch(:native).length
    super
    attempt = @rc.fetch(:sdk).last
    probe = @rc.fetch(:native).drop(offset).reverse.find { |row| row.fetch(:argv)[3, 2] == %w[state_probe.py connections] }
    expect(probe).not_to be_nil
    port = Integer(probe.fetch(:argv).last, 10)
    attempt[:handler_listener_cleanup] = ks_native('host_port', 'refused', port.to_s)
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    if attempt && attempt[:status] == 'passed'
      attempt[:status] = 'listener_cleanup_failed'
      @rc[:cleanup_errors] << { family: family, type: e.class.name, message: e.message }
    end
    raise
  ensure
    rc_save
  end

  def ks_start_owner(attempt, options, payload, reuse, offset)
    before_files, = rc_command('owner-tmp-baseline', 'app', 'sh', '-c', 'printf "%s\\n" /tmp/*')
    attempt[:tmp_baseline] = before_files.lines.map(&:strip)
    unless reuse
      console_command('back')
      expect(console_command('use ' + ks_owner_fullname)).not_to match(/Failed to load|Unknown command|No results/)
    end
    kg_proxy
    attempt[:output_base64] = Base64.strict_encode64(run_target_module(ks_owner_fullname, 'app', options.except('ExitOnSession', 'ListenerTimeout').merge('WfsDelay' => 30), action: 'run -z', reuse_module: true, command_timeout: 120).b)
    events = ks_owner_events.drop(offset)
    attempt[:owner_events] = events
    invoked = events.select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
    attempt[:owner_exploit_invoked] = invoked.length == 1
    expect(attempt[:owner_exploit_invoked]).to be(true)
    deliveries = events.select { |event| event['event'] == 'return' && event['method'] == 'create_plugin' }
    expect(deliveries.length).to eq(1)
    command = Base64.strict_decode64(deliveries.first.fetch('payload_base64'))
    attempt[:generated] = { 'owner' => ks_owner_fullname, 'payload' => payload, 'base64' => Base64.strict_encode64(command), 'sha256' => Digest::SHA256.hexdigest(command) }
    selection = rc_json('active_module.object_id')
    expect(selection).to eq(@rc.fetch(:previous_owner_selection)) if reuse
    @rc[:previous_owner_selection] = selection
    attempt[:selection] = selection
    checks = events.select { |event| event['event'] == 'return' && event['method'] == 'check' }
    expect(checks.map { |event| event.fetch('check').fetch('code') }).to eq(['appears'])
    expect(events).to include(include('event' => 'return', 'method' => 'delete_route'))
  end
end
