# frozen_string_literal: true

require_relative '../freeswitch/acceptance'
require_relative 'package_verify'

module Acceptance
  # Owner-specific calls share the calibrated native client and passive capture.
  module FreeSwitchExecution
    include FreeSwitch

    EXEC_OWNER = 'exploit/multi/misc/freeswitch_event_socket_cmd_exec'

    def fx_record(name, value)
      fs_journal(name, value)
    end

    def fx_native(phase)
      result = fs_native_phase(phase)
      unless @mode == 'unrelated'
        expect(target_exec('target', 'sha256sum', '-c', '/opt/module-target-tool-binaries.sha256').lines.length).to eq(3)
        manifest = target_exec('target', 'cat', '/opt/module-target-tool-packages.tsv')
        tools = JSON.parse(File.read('test/module_targets/freeswitch_execution/tools.json'))
        installed = manifest.lines.to_h do |line|
          name, version, architecture = line.strip.split("\t")
          [name.delete_suffix(':amd64'), [version, architecture]]
        end
        tools.fetch('packages').each do |name, entry|
          expect(installed.fetch(name)).to eq([entry.fetch('Version'), 'amd64'])
        end
        result['packages_sha256'] = Digest::SHA256.hexdigest(manifest)
        verification = target_exec('target', 'dpkg', '--verify', 'curl', 'wget', 'inetutils-telnet')
        configuration = target_exec('target', 'cat', '/etc/dpkg/dpkg.cfg.d/docker')
        excluded = FreeSwitchExecutionPackages.verify(verification, configuration)
        fx_record('native-package-verification.jsonl', phase: phase, verification: verification, configuration_sha256: Digest::SHA256.hexdigest(configuration), intentionally_excluded_missing_paths: excluded)
      end
      fx_record('execution-native-phases.jsonl', phase: phase, native: result)
      result
    end

    def fx_json(expression)
      output = console_command("irb -e #{("puts 'FS_EXEC_JSON=' + (#{expression}).to_json").inspect}")
      captured = output.lines.grep(/^FS_EXEC_JSON=/)
      expect(captured.length).to eq(1), output
      JSON.parse(captured.first.delete_prefix('FS_EXEC_JSON='))
    end

    def fx_call(options = {}, action: 'run -z')
      @call = (@call || 0) + 1
      stem = "#{@workspace}-#{@call}"
      port = options.fetch('RPORT', target_runtime.fetch('module_endpoints').fetch('target').fetch('port'))
      arguments = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/freeswitch/capture.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), port.to_s]
      values = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'printf module-target-unexpected-execution', 'DisablePayloadHandler' => true, 'ConnectTimeout' => 3, 'VERBOSE' => true, 'PASSWORD' => @password }.merge(options)
      values.delete('PASSWORD') if values.delete('OMIT_PASSWORD')
      output = nil
      raw = nil
      errors = nil
      status = nil
      begin
        Open3.popen3(*arguments) do |input, captured, stderr, wait|
          expect(IO.select([captured], nil, nil, 8)).not_to be_nil
          expect(captured.gets).to eq("FREESWITCH_CAPTURE_READY\n")
          output = run_target_module(EXEC_OWNER, 'target', values, action: action, allow_errors: true, command_timeout: 60)
        ensure
          begin
            input.puts('STOP')
          rescue Errno::EPIPE, IOError
            # Preserve actual capture termination and diagnostics below.
          end
          input.close
          unless wait.join(5)
            Process.kill('TERM', wait.pid)
            wait.join(3)
          end
          raw = captured.read
          errors = stderr.read
          status = wait.value.exitstatus
        end
      ensure
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.json'), raw.to_s)
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.stderr'), errors.to_s)
        fx_record('execution-owning-calls.jsonl', workspace: @workspace, owner: EXEC_OWNER, action: action, options: values, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), wrapper_returned: !output.nil?, capture_actual_exit: status)
      end
      expect(status).to eq(0), errors
      expect(errors).to eq('')
      streams = fs_streams(JSON.parse(raw).fetch('packets'))
      fx_record('execution-verified-wire.jsonl', workspace: @workspace, streams: streams)
      [output.dup.force_encoding(Encoding::UTF_8), streams]
    end

    def fx_check(reason, options = {})
      2.times do
        output, streams = fx_call(options, action: 'check')
        expect(output).to include(reason)
        expect(streams.select { |row| row.fetch(:direction) == 'request' }.map { |row| row.fetch(:text) }.join).to eq('')
      end
    end

    def fx_command(password: @password, omit_password: false, allowed: true, reason: nil)
      2.times do |iteration|
        path = "/tmp/module-target-fs-command-#{@workspace}-#{iteration}"
        marker = "freeswitch-command-#{@workspace}-#{iteration}"
        command = "printf %s #{marker} > #{path};printf %s #{marker}"
        begin
          options = { 'CMD' => command, 'PASSWORD' => password, 'OMIT_PASSWORD' => omit_password }
          output, streams = fx_call(options)
          requests = streams.select { |row| row.fetch(:direction) == 'request' }.map { |row| row.fetch(:text) }.join
          replies = streams.select { |row| row.fetch(:direction) == 'response' }.map { |row| row.fetch(:text) }.join
          expect(output).to include(reason) if reason
          if allowed
            expect(output).to include('Login success', marker)
            expect(requests).to include("auth #{omit_password ? 'ClueCon' : password}\n\n", "api system #{command}\n\n")
            expect(replies).to include('Reply-Text: +OK accepted', "\n\n#{marker}")
            expect(target_exec('target', 'cat', path)).to eq(marker)
            expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq(@uid)
          else
            expect(output).not_to include('Login success')
            expect(requests).not_to include('api system ', 'api bg_system ')
            expect(replies).not_to include('Reply-Text: +OK accepted')
            target_exec('target', 'test', '!', '-e', path)
          end
        ensure
          target_exec('target', 'rm', '-f', '--', path)
        end
      end
    end

    def fx_resources
      observations = %w[target framework reporting_db].to_h do |service|
        counters = %w[memory.events pids.events].to_h do |counter|
          values = target_exec(service, 'cat', "/sys/fs/cgroup/#{counter}").lines.to_h do |line|
            name, value = line.split
            [name, Integer(value, 10)]
          end
          [counter, values]
        end
        [service, counters]
      end
      File.write(File.join(target_runtime.fetch('artifacts'), 'execution-resource-counters.json'), JSON.pretty_generate(observations))
      observations.each do |service, counters|
        %w[oom oom_kill oom_group_kill].each { |name| expect(counters.fetch('memory.events').fetch(name, 0)).to eq(0), "#{service} #{name}" }
        expect(counters.fetch('pids.events').fetch('max')).to eq(0), "#{service} PID limit reached"
      end
    end
  end
end
