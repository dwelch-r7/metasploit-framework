# frozen_string_literal: true

require_relative '../kafka_ui/sessions'
require_relative 'commands'

# Reuse the real handler, SQL and physical cleanup proofs with APISIX delivery.
module ApisixSessions
  include KafkaUiSessionTarget
  include ApisixTarget

  FAMILIES = {
    'bash' => ['cmd/unix/reverse_bash', 'shell', nil],
    'netcat' => KafkaUiSessionTarget::FAMILIES.fetch('netcat')
  }.freeze

  def ks_expected_uid
    @rc.fetch(:identity).fetch('uid')
  end

  def ks_exec_user_options
    ['--user', ks_expected_uid.to_s]
  end

  def ks_families
    FAMILIES
  end

  def ks_native(script, operation, *arguments)
    return ap_native(operation, *arguments) if script == 'native.py'

    argv = ['python3', 'test/module_targets/apisix/controls.py', ENV.fetch('MODULE_TARGET_RUNTIME'), script, operation].concat(arguments)
    output, error, status = Open3.capture3(*argv)
    @rc[:native] << { argv: argv, exit: status.exitstatus, stdout: output, stderr: error }
    rc_save
    expect(status.success?).to be(true), output + error
    data = JSON.parse(output)
    expect(data.fetch('passed')).to be(true)
    data.fetch('data')
  end

  def ks_owner_fullname
    ApisixTarget::OWNER
  end

  def ks_owner_events
    rc_json('framework.instance_variable_get(:@apisix_events)')
  end

  def ap_owner_processes(label)
    output, = rc_command(label, 'app', 'ps', '-o', 'pid,ppid,user,args')
    output.lines.drop(1).filter_map do |line|
      pid, parent, user, command = line.strip.split(/\s+/, 4)
      { 'pid' => Integer(pid), 'parent' => Integer(parent), 'user' => user, 'command' => command } if user == 'nobody'
    end
  end

  def ks_start_owner(attempt, options, payload, reuse, offset)
    before_files, = rc_command('owner-tmp-baseline', 'app', 'sh', '-c', 'printf "%s\\n" /tmp/*')
    attempt[:tmp_baseline] = before_files.lines.map(&:strip)
    attempt[:process_baseline] = ap_owner_processes('owner-process-baseline')
    unless reuse
      console_command('back')
      expect(console_command('use ' + ApisixTarget::OWNER)).not_to match(/Failed to load|Unknown command|No results/)
    end
    expect(console_command('set DisablePayloadHandler false')).not_to include('[-]')
    output = run_target_module(ApisixTarget::OWNER, 'app', options.except('ExitOnSession', 'ListenerTimeout').merge('WfsDelay' => 5), action: 'run -z', reuse_module: true, allow_errors: true, command_timeout: 150)
    attempt[:output_base64] = Base64.strict_encode64(output.b)
    events = ks_owner_events.drop(offset)
    attempt[:owner_events] = events
    invoked = events.select { |event| event['event'] == 'call' && event['method'] == 'exploit' && event['source'].end_with?('/apache_apisix_api_default_token_rce.rb') }
    attempt[:owner_exploit_invoked] = invoked.length == 1
    expect(attempt[:owner_exploit_invoked]).to be(true)
    deliveries = events.select { |event| event['event'] == 'return' && %w[add_route filter_func_exec].include?(event['method']) }
    expect(deliveries.length).to eq(1)
    command = Base64.strict_decode64(deliveries.first.fetch('payload_base64'))
    attempt[:generated] = { 'owner' => ApisixTarget::OWNER, 'payload' => payload, 'base64' => Base64.strict_encode64(command), 'sha256' => Digest::SHA256.hexdigest(command) }
    selection = rc_json('active_module.object_id')
    expect(selection).to eq(@rc.fetch(:previous_owner_selection)) if reuse
    @rc[:previous_owner_selection] = selection
    attempt[:selection] = selection
    baseline_pids = attempt.fetch(:process_baseline).map { |row| row.fetch('pid') }
    attempt[:owned_processes] = rc_poll do
      rows = ap_owner_processes('owner-process-live').reject { |row| baseline_pids.include?(row.fetch('pid')) }
      rows unless rows.empty?
    end
    attempt[:live_api] = ap_native('api_ready')
    attempt[:cleanup_before_session_close] = ap_native('audit')
  end

  def ks_session(family, **options)
    offset = @rc.fetch(:native).length
    super
    attempt = @rc.fetch(:sdk).last
    workspace = attempt.fetch(:workspace)
    expect(workspace).to match(/\Aks_\d+_[a-z0-9_]+\z/)
    reports = JSON.parse(rc_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT s.id,s.closed_at FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{workspace}') row"))
    attempt[:workspace_reports] = reports
    expect(reports.length).to eq(1)
    expect(reports.first).to eq(attempt.fetch(:closed_report))
    probe = @rc.fetch(:native).drop(offset).reverse.find { |row| row.fetch(:argv)[3, 2] == %w[state_probe.py connections] }
    expect(probe).not_to be_nil
    attempt[:listener_cleanup] = ks_native('host_port', 'refused', probe.fetch(:argv).last)
    if attempt[:owner_path]
      attempt.fetch(:owned_processes).each { |row| rc_poll(20) { !ks_inspect('process', row.fetch('pid')).fetch('exists') } }
      attempt[:all_owned_processes_absent] = true
    end
  rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
    if attempt && attempt[:status] == 'passed'
      attempt[:status] = 'physical_cleanup_failed'
      @rc[:cleanup_errors] << { family: family, type: e.class.name, message: e.message }
    end
    raise
  ensure
    rc_save
  end
end
