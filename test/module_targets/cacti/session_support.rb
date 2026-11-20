# frozen_string_literal: true

require_relative '../kafka_ui/sessions'

# Share real handler, persistence and cleanup checks at the application's UID.
module CactiSdkTarget
  include KafkaUiSessionTarget

  FAMILIES = {
    'bash' => ['cmd/unix/reverse_bash', 'shell', nil],
    'netcat' => KafkaUiSessionTarget::FAMILIES.fetch('netcat'),
    'fetch32' => KafkaUiSessionTarget::FAMILIES.fetch('fetch32'),
    'fetch64' => KafkaUiSessionTarget::FAMILIES.fetch('fetch64'),
    'staged32' => ['cmd/linux/http/x86/meterpreter/reverse_tcp', 'meterpreter', 1],
    'staged64' => KafkaUiSessionTarget::FAMILIES.fetch('staged64'),
    'php' => ['cmd/unix/php/meterpreter/reverse_tcp', 'meterpreter', nil]
  }.freeze

  def rc_save
    File.write(File.join(target_runtime.fetch('artifacts'), 'cacti-sdk.json'), JSON.pretty_generate(@rc)) if @rc
  end

  def rc_resource_roles
    %w[app db reporting_db]
  end

  def ca_native(operation, *arguments)
    argv = ['python3', 'test/module_targets/cacti/native.py', ENV.fetch('MODULE_TARGET_RUNTIME'), operation, *arguments]
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    JSON.parse(output.match(/^CACTI_NATIVE=(.+)$/)[1]).fetch('result')
  end

  def ks_native(script, operation, *arguments)
    return ca_native(operation, *arguments) if script == 'native.py'

    argv = ['python3', 'test/module_targets/cacti/controls.py', ENV.fetch('MODULE_TARGET_RUNTIME'), script, operation].concat(arguments)
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    result = JSON.parse(output)
    expect(result.fetch('passed')).to be(true)
    result.fetch('data')
  end

  def ks_expected_uid
    @rc.fetch(:identity).fetch('uid')
  end

  def ks_exec_user_options
    ['--user', ks_expected_uid.to_s]
  end

  def ks_families
    FAMILIES
  end

  def ks_owner_events
    rc_json('framework.instance_variable_get(:@cacti_events)')
  end

  def ks_session(family, **options)
    offset = @rc.fetch(:native).length
    super
    attempt = @rc.fetch(:sdk).last
    probe = @rc.fetch(:native).drop(offset).reverse.find { |row| row.fetch(:argv)[3, 2] == %w[state_probe.py connections] }
    expect(probe).not_to be_nil
    attempt[:listener_cleanup] = ks_native('host_port', 'refused', probe.fetch(:argv).last)
    workspace = attempt.fetch(:workspace)
    expect(workspace).to match(/\Aks_\d+_[a-z0-9_]+\z/)
    rows = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.closed_at FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{workspace}') row"))
    attempt[:workspace_reports] = rows
    expect(rows).to eq([attempt.fetch(:closed_report)])
  ensure
    rc_save
  end
end
