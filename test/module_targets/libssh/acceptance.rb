# frozen_string_literal: true

require 'base64'
require 'json'

module Acceptance
  # Target controls and observations never replace the owning module's methods.
  module Libssh
    OWNER = 'auxiliary/scanner/ssh/libssh_auth_bypass'

    def ssh_journal(name, data)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(data)) }
    end

    def ssh_json(expression)
      output = console_command("irb -e #{("puts 'LIBSSH_JSON=' + (#{expression}).to_json").inspect}")
      rows = output.lines.grep(/^LIBSSH_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('LIBSSH_JSON='))
    end

    def ssh_sql(query)
      JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
    end

    def ssh_reports
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Alibssh_[0-9_]+\z/)

      rows = ssh_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT v.id,v.name,v.info,v.service_id,host(h.address) AS address,s.port,s.proto,s.name AS service_name FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{@workspace}' ORDER BY v.id) row")
      ssh_journal('vulnerability-snapshots.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def ssh_state
      JSON.parse(target_exec('target', 'python3', '/opt/libssh-lab/state.py'))
    end

    def ssh_idle
      wait_for_expect(30, 0.1) do
        state = ssh_state
        expect(state.fetch('connections')).to eq([])
        expect(state.fetch('processes')).to match_array(@idle.fetch('processes'))
      end
      expect(ssh_json('framework.sessions.keys')).to eq([])
      expect(ssh_json('framework.jobs.keys')).to eq([])
    end

    def ssh_native(phase)
      native = JSON.parse(target_exec('target', 'python3', '/opt/libssh-lab/native_probe.py', '127.0.0.1', phase))
      expect(native.fetch('native_status')).to eq('passed')
      expect(native.fetch('cases').length).to eq(47)
      ssh_journal('native-controls.jsonl', phase: phase, controls: native)
      native
    end

    def ssh_resources
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
      ssh_journal('resource-counters.jsonl', rows)
      rows.each_value do |counters|
        %w[oom oom_kill oom_group_kill].each { |name| expect(counters.fetch('memory.events').fetch(name, 0)).to eq(0) }
        expect(counters.fetch('pids.events').fetch('max')).to eq(0)
      end
    end

    def ssh_call(options = {})
      output = nil
      @calls = (@calls || 0) + 1
      options = { 'ACTION' => 'Execute', 'CMD' => 'printf unexpected-default-command', 'THREADS' => 1, 'SSH_TIMEOUT' => 3, 'CHECK_BANNER' => true, 'SPAWN_PTY' => false, 'CreateSession' => false }.merge(options)
      options.delete('CMD') if options['ACTION'] == 'Shell' && options['CMD'].nil?
      output = run_target_module(OWNER, 'target', options, allow_errors: true)
      expect(output).not_to match(/Auxiliary failed|Call stack:|Unknown datastore option/)
      output
    ensure
      ssh_journal('owning-calls.jsonl', workspace: @workspace, options: options, output_base64: Base64.strict_encode64(output || console.all_data), wrapper_returned: !output.nil?)
    end

    def ssh_execute(port, allowed:, check_banner: true, delayed: false, pty: false)
      2.times do |iteration|
        marker = "libssh-#{@case.tr('_', '-')}-#{iteration}"
        path = "/tmp/libssh-lab/owner-#{@case.tr('_', '-')}-#{iteration}"
        command = "#{'sleep 0.4;' if delayed}printf %s #{marker} > #{path};echo #{marker};printf TTY=;if test -t 0;then printf yes;else printf no;fi;echo"
        begin
          output = ssh_call('RPORT' => port, 'CMD' => command, 'CHECK_BANNER' => check_banner, 'SPAWN_PTY' => pty)
          if allowed
            wait_for_expect(30, 0.1) do
              observed = JSON.parse(target_exec('target', 'python3', '-c', 'from pathlib import Path;import json,sys;p=Path(sys.argv[1]);print(json.dumps(p.read_text() if p.is_file() else None))', path))
              expect(observed).to eq(marker)
            end
            expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('10001')
            expect(output).to match(/Executed: #{Regexp.escape(command)}\r?\n#{marker}\r?\nTTY=#{pty ? 'yes' : 'no'}(?:\r?\n|$)/)
          else
            target_exec('target', 'test', '!', '-e', path)
            expect(output).not_to include('Executed:')
          end
        ensure
          target_exec('target', 'rm', '-f', '--', path)
        end
        ssh_idle
      end
    end

    def ssh_session(port, pty:, alternative: false)
      2.times do |iteration|
        path = "/tmp/libssh-lab/owner-#{@case.tr('_', '-')}-#{iteration}"
        marker = "libssh-#{@case.tr('_', '-')}-#{iteration}"
        begin
          ssh_call('ACTION' => 'Shell', 'CMD' => alternative ? '/bin/sh' : nil, 'RPORT' => port, 'SPAWN_PTY' => pty, 'CreateSession' => true)
          identifier = nil
          wait_for_expect(30, 0.1) do
            sessions = ssh_json('framework.sessions.values.map { |s| {id:s.sid,type:s.type,owner:s.via_exploit} }')
            expect(sessions.length).to eq(1)
            expect(sessions.first).to include('type' => 'shell', 'owner' => OWNER)
            identifier = sessions.first.fetch('id')
            expect(File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line).fetch('id') }).to include(identifier)
          end
          proof = ssh_json("LibsshSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
          expect(proof).to include('type' => 'shell', 'owner' => OWNER, 'db_id' => be_a(Integer))
          expect(proof.fetch('output')).to match(/(?:^|\n)PID=\d+ UID=10001 TTY=#{pty ? 'yes' : 'no'}\r?(?:\n|$)/)
          expect(target_exec('target', 'cat', path)).to eq(marker)
          expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('10001')
          ssh_journal('session-proofs.jsonl', proof)
          ssh_json("DruidSessionControl.exit_remote(framework,#{identifier})")
          # Generic CommandShell does not mark itself dead on unconsumed EOF.
          # Observe remote closure first, then exercise its public close API.
          wait_for_expect(30, 0.1) do
            state = ssh_state
            expect(state.fetch('connections')).to eq([])
            expect(state.fetch('processes')).to match_array(@idle.fetch('processes'))
          end
          closure = ssh_json("LibsshSessionControl.close(framework,#{identifier})")
          ssh_journal('session-closures.jsonl', closure.merge('remote_processes_and_connections_closed_before_public_close' => true))
          wait_for_expect(30, 0.1) { expect(ssh_json('framework.sessions.keys')).to eq([]) }
          rows = ssh_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT id,closed_at FROM sessions WHERE id=#{proof.fetch('db_id')}) row")
          expect(rows).to contain_exactly(include('id' => proof.fetch('db_id'), 'closed_at' => be_a(String)))
        ensure
          target_exec('target', 'rm', '-f', '--', path)
        end
        ssh_idle
      end
    end

    def ssh_refuse_shell(port)
      2.times do
        output = ssh_call('ACTION' => 'Shell', 'CMD' => nil, 'RPORT' => port, 'CHECK_BANNER' => false, 'CreateSession' => true)
        expect(output).not_to match(/Command shell session \d+ opened/)
        expect(ssh_json('framework.sessions.keys')).to eq([])
        expect(ssh_reports).to eq([])
        ssh_idle
      end
    end
  end
end
