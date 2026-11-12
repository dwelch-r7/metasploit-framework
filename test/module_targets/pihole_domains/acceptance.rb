# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Keep native state, public command output and actual reporting separate.
  module PiholeDomains
    OWNER = 'auxiliary/admin/http/pihole_domains_api_exec'

    def ph_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/pihole_domains/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('PH_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 240, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def ph_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def ph_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Aph_[0-9_]+\z/)

      services = JSON.parse(ph_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.state,s.name
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      vulns = JSON.parse(ph_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(ph_sql("SELECT coalesce(json_agg(l.id),'[]'::json) FROM loots l JOIN workspaces w ON w.id=l.workspace_id WHERE w.name='#{@workspace}'"))
      rows = { 'services' => services, 'vulnerabilities' => vulns, 'loot' => loot }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') { |file| file.puts(JSON.generate(workspace: @workspace, reports: rows)) }
      rows
    end

    def ph_config
      target_exec('target', 'cat', '/etc/pihole/setupVars.conf')
    end

    def ph_restore(encoded)
      target_exec('target', 'php', '-r', "file_put_contents('/etc/pihole/setupVars.conf',base64_decode($argv[1]));", encoded)
      expect(ph_config).to eq(Base64.strict_decode64(encoded))
    end

    def ph_call(action, options = {}, cleanup: true)
      before = ph_config if @app
      output = nil
      cleaned = false
      begin
        password = @profile == 'noauth' ? '' : 'module-target-pihole-password'
        output = run_target_module(OWNER, 'target', { 'PASSWORD' => password, 'COMMAND' => 'id', 'HttpClientTimeout' => 15 }.merge(options), action: action, allow_errors: true, command_timeout: 120)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        current = ph_config if @app
        if @app && current != before && cleanup
          ph_restore(Base64.strict_encode64(before))
          cleaned = true
        end
        @last_call = {
          action: action, options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text,
          config_before: before && Base64.strict_encode64(before), config_after: current && Base64.strict_encode64(current), native_cleanup_requested: cleanup, native_cleanup_applied: cleaned
        }
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') { |file| file.puts(JSON.generate(@last_call)) }
      end
      expect(text).not_to include('Unknown datastore option')
      expect(Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }).to eq([])
      text
    end

    def ph_expect_reports(vulnerable: false)
      rows = ph_reports
      expect(rows.fetch('loot')).to eq([])
      unless vulnerable
        expect(rows.values).to all(eq([]))
        return rows
      end

      expect(rows.fetch('services').length).to eq(1)
      expect(rows.fetch('vulnerabilities').length).to eq(1)
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      service = rows.fetch('services').fetch(0)
      record = rows.fetch('vulnerabilities').fetch(0)
      expect(service.values_at('host', 'port', 'proto', 'state')).to eq([endpoint.fetch('host'), 80, 'tcp', 'open'])
      expect(record.values_at('host', 'service_id')).to eq([endpoint.fetch('host'), service.fetch('id')])
      expect(record.fetch('refs')).to include('CVE-2021-32706')
      rows
    end

    def ph_positive_check(options = {})
      output = ph_call('check', options)
      expect(output).to include(@vulnerable ? 'The target appears to be vulnerable.' : 'The target is not exploitable.')
      expect(@last_call.values_at(:config_before, :config_after).uniq.length).to eq(1)
      ph_expect_reports(vulnerable: @vulnerable)
    end

    def ph_execute(options = {}, cleanup: true)
      output = ph_call('run', options, cleanup: cleanup)
      if @vulnerable
        command = options.fetch('COMMAND', 'id')
        expected = @native.fetch('oracles').fetch(command).split.join("\n")
        expect(output).to include("[+] #{expected}")
        expect(output).not_to match(/^\[-\] Auxiliary (?:failed|aborted)/)
        expect(Base64.strict_decode64(@last_call.fetch(:config_after))).to include("API_EXCLUDE_DOMAINS=*;#{command}")
        protected_values = @last_call.values_at(:config_before, :config_after).map do |encoded|
          Base64.strict_decode64(encoded).lines.reject { |line| line.start_with?('API_EXCLUDE_DOMAINS=') }
        end
        expect(protected_values.first).to eq(protected_values.last)
        expect(@last_call.fetch(:native_cleanup_applied)).to eq(cleanup)
      else
        expect(output).to include('Target is not vulnerable')
        expect(@last_call.values_at(:config_before, :config_after).uniq.length).to eq(1)
      end
      output
    end
  end
end
