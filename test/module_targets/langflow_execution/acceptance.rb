# frozen_string_literal: true

require 'timeout'
require 'base64'

module Acceptance
  # Public Python execution, process and database lifecycle assertions.
  module LangflowExecution
    def record(name, data)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(data)) }
    end

    def native(tag, action: 'verify')
      arguments = ['python3', '-B', self.class.metadata.fetch(:native_probe), action, tag]
      output, error, status = Open3.capture3(*arguments)
      record('native-probe-status.jsonl', argv: arguments, actual_exit: status.exitstatus, stdout: output, stderr: error)
      expect(status.exitstatus).to eq(0), error
      JSON.parse(output)
    end

    def process_state
      state = JSON.parse(target_exec('target', 'python', '/opt/module-target-process-state.py'))
      state['processes'].reject! do |row|
        row.fetch('command').include?("urllib.request.urlopen('http://127.0.0.1:7860/api/v1/version'") ||
          row.values_at('uid', 'ppid', 'command') == ['0', 0, 'runc init']
      end
      state
    end

    def rpc(expression)
      output = console_command("irb -e #{("puts 'LANGFLOW_JSON=' + (#{expression}).to_json").inspect}", timeout: 40)
      captured = output[/^LANGFLOW_JSON=(.+)\r?$/, 1]
      expect(captured).not_to be_nil, output
      JSON.parse(captured)
    end

    def call_owner(options = {}, action: 'run -z', reuse: false)
      @call = (@call || 0) + 1
      command_payload = self.class.metadata.fetch(:command_payload, 'python/exec')
      settings = {
        'TARGET' => 0, 'PAYLOAD' => command_payload, 'CMD' => 'true', 'DisablePayloadHandler' => true,
        'USERNAME' => 'module-target-admin', 'PASSWORD' => 'module-target-native-password',
        'AutoCheck' => true, 'TARGETURI' => '/', 'LHOST' => listener_host, 'LPORT' => 4492,
        'WfsDelay' => 3, 'HttpClientTimeout' => 3
      }.merge(options)
      settings.delete('CMD') unless settings.fetch('PAYLOAD') == command_payload
      output = nil
      begin
        if reuse
          endpoint = target_runtime.fetch('module_endpoints').fetch('target')
          datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(settings)
          output = console_command(action + ' ' + format_datastore_options(datastore), timeout: 45)
          expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError/)
        else
          output = run_target_module(owner_fullname, 'target', settings, action: action, allow_errors: true, command_timeout: 45)
        end
      ensure
        captured = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        encoding = captured.valid_encoding? ? 'utf-8' : 'base64'
        record('owning-calls.jsonl', owner: owner_fullname, workspace: @workspace, call: @call, action: action,
                                     options: settings, same_selected_instance: reuse, wrapper_returned: !output.nil?,
                                     output_encoding: encoding, output: encoding == 'utf-8' ? captured : Base64.strict_encode64(captured))
      end
      expect(output).not_to include('Unknown datastore option')
      output
    end

    def poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(200, 0.1, &block) }
    end

    def session_rows
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Alangflow_exec_[0-9_]+\z/)

      query = "SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]'::json) FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}'"
      JSON.parse(target_exec('reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query))
    end

    def idle
      expect(rpc('framework.sessions.keys')).to eq([])
      expect(rpc('framework.jobs.keys')).to eq([])
      expect(session_rows).to all(include('closed_at' => be_a(String)))
      state = process_state
      expect(state.fetch('connections')).to eq([])
      record('idle-process-state.jsonl', state)
      expect(state.fetch('processes').map { |row| row.except('state') }).to eq(@baseline.fetch('processes').map { |row| row.except('state') })
    end

    def command_proof(options = {})
      2.times do |iteration|
        path = "/tmp/module-target-langflow-own-#{@case}-#{iteration}"
        marker = "langflow-command-#{@case}-#{iteration}"
        begin
          target_exec('target', 'test', '!', '-e', path)
          output = call_owner(options.merge('CMD' => "printf %s #{marker} >> #{path}"), reuse: iteration.positive?)
          expect(output).not_to include('Exploit aborted', 'Exploit failed')
          poll(10) { expect(target_exec('target', 'sh', '-c', 'if test -f "$1"; then cat "$1"; fi', 'native-proof', path)).to eq(marker) }
          expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('1000')
          record('command-proofs.jsonl', path: path, marker: marker, matched: true)
        ensure
          target_exec('target', 'rm', '-f', '--', path)
        end
        poll(10) { idle }
      end
    end

    def session_proof(payload, options = {})
      2.times do |iteration|
        path = "/tmp/module-target-langflow-own-#{@case}-#{iteration}"
        marker = "langflow-session-#{@case}-#{iteration}"
        identifier = nil
        begin
          output = call_owner({ 'PAYLOAD' => payload, 'DisablePayloadHandler' => false, 'WfsDelay' => 12 }.merge(options), reuse: iteration.positive?)
          identifier = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(identifier).not_to be_nil, output
          identifier = Integer(identifier, 10)
          poll(15) do
            events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line).fetch('id') }
            expect(events).to include(identifier)
          end
          proof = rpc("LangflowSessionControl.proof(framework, #{identifier}, #{path.inspect}, #{marker.inspect})")
          expect(target_exec('target', 'cat', path)).to eq(marker)
          expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('1000')
          expect(rpc("framework.sessions.fetch(#{identifier}).then { |session| [session.via_exploit, session.via_payload] }")).to eq([owner_fullname, 'payload/' + payload])
          expect(session_rows).to include(include('id' => proof.fetch('db_id'), 'via_exploit' => owner_fullname, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
          process = process_state.fetch('processes').find { |row| row.fetch('pid') == proof.fetch('pid') }
          expect(process).not_to be_nil
          expect(process.fetch('uid')).to eq('1000')
          expect(@baseline.fetch('processes').map { |row| row.fetch('pid') }).not_to include(proof.fetch('pid'))
          expect(native("live-#{@case}-#{iteration}", action: 'health')).to include('version' => self.class.metadata.fetch(:target_version), 'package' => 'Langflow')
          record('session-lifecycle.jsonl', phase: 'proof', payload: payload, proof: proof, process: process)
          yield(identifier, path, marker, proof, process) if block_given?
          record('session-lifecycle.jsonl', phase: 'shutdown', result: rpc("LangflowSessionControl.shutdown(framework, #{identifier})"))
          rpc("begin; framework.sessions[#{identifier}]&.kill; true; end")
          poll(15) { expect(process_state.fetch('processes').any? { |row| row.values_at('pid', 'birth') == process.values_at('pid', 'birth') }).to be(false) }
          poll(15) { idle }
          record('session-lifecycle.jsonl', phase: 'closed', id: identifier, payload: payload, database_rows: session_rows)
          expect(output).not_to include('Exploit aborted', 'Exploit failed')
        ensure
          console_command('sessions -K')
          console_command('jobs -K')
          target_exec('target', 'rm', '-f', '--', path)
        end
        poll(15) { idle }
      end
    end
  end
end
