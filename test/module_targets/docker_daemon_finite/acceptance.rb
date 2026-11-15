# frozen_string_literal: true

require_relative '../docker_daemon/acceptance'

# Finite payloads require explicit manual cleanup; do not imply a session exists.
module DockerDaemonFiniteAcceptance
  def finite_cleanup_guard
    offset = owner_rows.length
    settings = { 'TARGET' => 0, 'PAYLOAD' => 'linux/x64/exec', 'CMD' => '/usr/bin/true', 'DOCKERIMAGE' => 'module-target-native:base', 'AllowNoCleanup' => false, 'DisablePayloadHandler' => false, 'WfsDelay' => 0 }
    output = run_target_module(DockerDaemonAcceptance::OWNER, 'target', settings, action: 'run -z', allow_errors: true, command_timeout: 45)
    observed = owner_rows.drop(offset)
    record('docker-daemon-invocations.jsonl', action: 'run -z', settings: settings, output: output, rows: observed)
    expect(output).to include('cannot cleanup files created during exploit')
    expect(observed).to eq([])
    expect(host_file_names).to match_array(@before_files)
    expect(session_rows).to eq([])
    expect(rpc('{jobs:framework.jobs.keys,sessions:framework.sessions.keys}')).to eq('jobs' => [], 'sessions' => [])
  end

  def finite_proof(payload, target:)
    2.times do |iteration|
      path = "/tmp/module-target-docker-finite-#{@case}-#{iteration}"
      marker = "docker-finite-café-雪-#{@case}-#{iteration}"
      markers = [path, path + '.uid', path + '.pid']
      expect(native_file_state(markers)).to all(include('exists' => false))
      @owned_markers.concat(markers)
      command = "printf %s #{marker} > #{path}; id -u > #{path}.uid; echo $$ > #{path}.pid"
      settings = {
        'TARGET' => target, 'PAYLOAD' => payload, 'CMD' => command,
        'DOCKERIMAGE' => 'module-target-native:base', 'AllowNoCleanup' => true,
        'DisablePayloadHandler' => false, 'WfsDelay' => 0, 'HttpClientTimeout' => 10
      }
      offset = owner_rows.length
      output = run_target_module(DockerDaemonAcceptance::OWNER, 'target', settings, action: 'run -z', allow_errors: true, command_timeout: 45)
      observed = owner_rows.drop(offset)
      record('docker-daemon-invocations.jsonl', action: 'run -z', iteration: iteration, settings: settings, output: output, rows: observed)
      expect(output).not_to include('Exploit failed', 'Exploit aborted due to failure')
      effects = source_owned_effects(offset, @before_files)
      expect(effects.length).to eq(1)
      wait_for_expect(80, 1) do
        expect(native_file_state(markers)).to all(include('exists' => true, 'uid' => 0))
      end
      expect(target_exec('target', 'cat', path).b).to eq(marker.b)
      expect(target_exec('target', 'cat', path + '.uid').strip).to eq('0')
      identifier = Integer(target_exec('target', 'cat', path + '.pid').strip, 10)
      expect(identifier).to be > 1
      wait_for_expect(10, 0.2) { expect(process_identity(identifier)).to be_nil }
      expect(session_rows).to eq([])
      expect(rpc('{jobs:framework.jobs.keys,sessions:framework.sessions.keys}')).to eq('jobs' => [], 'sessions' => [])
      expect(inner('ps', '--all', '--quiet').strip).to eq('')
      states = native_file_state(effects.flat_map { |effect| effect.fetch('host_paths') })
      expect(states).to all(include('exists' => true, 'uid' => 0))
      record('docker-daemon-finite-proof.jsonl', payload: payload, iteration: iteration, marker_path: path, exact_marker_base64: Base64.strict_encode64(marker.b), uid: 0, finite_pid: identifier, finite_pid_gone: true, session_count: 0, explicit_allow_no_cleanup: true, effects: effects, source_residuals_before_operator_cleanup: states)
      # These residuals are permitted by the explicit operator opt-in. Preserve
      # their actual bytes first, then remove only proven source-owned paths.
      effects.each do |effect|
        effect.fetch('host_paths').each { |owned| target_exec('target', 'rm', '-f', '--', owned) }
      end
      cleaned = native_file_state(effects.flat_map { |effect| effect.fetch('host_paths') })
      record('docker-daemon-finite-proof.jsonl', phase: 'after-operator-cleanup', file_states: cleaned)
      expect(cleaned).to all(include('exists' => false))
      expect(core_processes).to eq(@baseline_core)
    end
  end
end
