# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare public scanner entry points with real API and reporting state.
  module AudiobookshelfAuth
    OWNER = 'auxiliary/scanner/http/audiobookshelf_auth_bypass'

    def abs_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/audiobookshelf/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('ABS_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def abs_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def abs_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Aabs_[0-9_]+\z/)

      services = JSON.parse(abs_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.name,s.state,s.info
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      vulnerabilities = JSON.parse(abs_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(abs_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT l.id,l.path,l.ltype FROM loots l JOIN workspaces w ON w.id=l.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      rows = { 'services' => services, 'vulnerabilities' => vulnerabilities, 'loot' => loot }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') do |file|
        file.puts(JSON.generate(workspace: @workspace, reports: rows))
      end
      rows
    end

    def abs_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def abs_call(action, options = {})
      previous = abs_loot
      output = nil
      begin
        output = run_target_module(OWNER, 'target', { 'HttpClientTimeout' => 15 }.merge(options), action: action, allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(action: action, options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text, new_loot: abs_loot - previous))
        end
      end
      expect(text).not_to include('Unknown datastore option')
      expect(abs_loot - previous).to eq([])
      text
    end

    def abs_assert_reports(vulnerable:)
      rows = abs_reports
      expect(rows.fetch('loot')).to eq([])
      unless vulnerable
        expect(rows.fetch('services')).to eq([])
        expect(rows.fetch('vulnerabilities')).to eq([])
        return rows
      end

      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expect(rows.fetch('services').length).to eq(1)
      service = rows.fetch('services').fetch(0)
      expect(service.values_at('host', 'port', 'proto', 'state')).to eq([endpoint.fetch('host'), 80, 'tcp', 'open'])
      expect(rows.fetch('vulnerabilities').length).to eq(1)
      record = rows.fetch('vulnerabilities').fetch(0)
      expect(record.values_at('host', 'service_id')).to eq([endpoint.fetch('host'), service.fetch('id')])
      expect(record.fetch('refs')).to include('CVE-2025-25205')
      expect(record.fetch('name')).to match(/Audiobookshelf|audiobookshelf_auth_bypass/)
      rows
    end

    def abs_positive(action, options = {})
      output = abs_call(action, options)
      if action == 'check'
        expect(output).to include(@vulnerable ? 'The target is vulnerable.' : 'The target is not exploitable.')
      else
        expect(output).to include(@vulnerable ? 'unauthenticated API authentication bypass confirmed (CVE-2025-25205)' : 'not vulnerable (authentication enforced)')
      end
      expect(output).not_to match(/^\[-\] Auxiliary (?:failed|aborted)/)
      abs_assert_reports(vulnerable: @vulnerable)
    end
  end
end
