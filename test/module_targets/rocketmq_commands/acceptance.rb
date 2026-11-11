# frozen_string_literal: true

require 'base64'
require 'English'
require 'securerandom'
require 'timeout'
require_relative '../rocketmq/acceptance'

module Acceptance
  # Distinguish independently observed command execution from operator recovery.
  module RocketmqCommands
    include Rocketmq

    def rmqc_record(record)
      File.open(File.join(target_runtime.fetch('artifacts'), 'command-executions.jsonl'), 'a') { |file| file.puts(JSON.generate(record)) }
    end

    def rmqc_json(expression)
      code = "puts 'RMQC_JSON=' + (#{expression}).to_json"
      output = console_command("irb -e #{code.inspect}")
      lines = output.lines.grep(/^RMQC_JSON=/)
      expect(lines.size).to eq(1), output
      JSON.parse(lines.first.delete_prefix('RMQC_JSON='))
    end

    def rmqc_marker(path, nonce)
      expect(target_exec('vulnerable', 'cat', path)).to eq(nonce)
      expect(target_exec('vulnerable', 'stat', '-c', '%u:%g', path).strip).to eq('3000:3000')
    end

    def rmqc_restore
      config = @native.fetch('config')
      output = target_exec('vulnerable', 'bash', '/lab/native.sh', 'restore', config.fetch('rocketmqHome'), config.fetch('filterServerNums'))
      result = JSON.parse(output.lines.grep(/^NATIVE_JSON=/).fetch(0).delete_prefix('NATIVE_JSON='))
      rmqc_record(kind: 'explicit_native_operator_recovery', result: result)
      expect(result.fetch('update').fetch('code')).to eq(0)
      expect(result.fetch('snapshot').fetch('config')).to eq(config)
      expect(result.fetch('snapshot').fetch('broker_pid')).to eq(@native.fetch('broker_pid'))
    end

    def rmqc_execute(disable_handler)
      token = SecureRandom.hex(8)
      marker = "/tmp/module-target-rocketmq-command-#{token}"
      nonce = "rocketmq-command-#{token}"
      command = "printf %s #{nonce} > #{marker}"
      record = { kind: 'owning_command', disable_handler: disable_handler, command: command, status: 'started' }
      begin
        before = rocketmq_native('vulnerable', "pre-command-#{token}")
        expect(before.fetch('config')).to eq(@native.fetch('config'))
        target_exec('vulnerable', 'test', '!', '-e', marker)
        output = run_target_module(EXPLOIT, 'vulnerable', { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => command, 'WfsDelay' => 0, 'DisablePayloadHandler' => disable_handler, 'ConnectTimeout' => 3 })
        record[:output] = output
        expect(output).not_to include('Unknown datastore option')
        expect(output).to include('on Broker port: 10921')
        expect(output).to include('No session callback was observed', 'filterServerNums to "0"')
        Timeout.timeout(45) do
          wait_for_expect(90, 0.5) do
            expect(target_exec('vulnerable', 'bash', '-c', 'if test -e "$1";then cat "$1";fi', 'bash', marker)).to eq(nonce)
          end
        end
        rmqc_marker(marker, nonce)
        after = rocketmq_native('vulnerable', "post-command-#{token}")
        record[:after] = after
        expect(after.fetch('broker_pid')).to eq(@native.fetch('broker_pid'))
        # No callback can prove a generic command ran. The module must leave it
        # scheduled, and disclose the saved original values for operator recovery.
        expect(after.fetch('config').fetch('filterServerNums')).to eq('1')
        expect(after.fetch('config').fetch('rocketmqHome')).to include(command)
        expect(rmqc_json('framework.sessions.keys')).to eq([])
        record[:status] = 'passed'
      ensure
        failure = $ERROR_INFO
        record[:failure] = "#{failure.class}: #{failure.message}" if failure
        record[:status] = 'failed' if failure
        errors = []
        [-> { rmqc_restore }, -> { target_exec('vulnerable', 'rm', '-f', marker) }].each do |cleanup|
          cleanup.call
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
          errors << "#{e.class}: #{e.message}"
        end
        record[:cleanup_errors] = errors
        rmqc_record(record)
        raise "Command recovery failed: #{errors.inspect}" if !failure && !errors.empty?
      end
    end
  end
end
