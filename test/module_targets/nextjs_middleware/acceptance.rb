# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Keep independent native requests and actual Framework reporting observable.
  module NextjsMiddleware
    OWNER = 'auxiliary/scanner/http/nextjs_middleware_auth_bypass'
    PROTOCOL_REJECTION = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).fetch('protocol_rejection').freeze
    REJECTION_PAYLOAD = (PROTOCOL_REJECTION.fetch('character') * PROTOCOL_REJECTION.fetch('length')).freeze

    def nx_rejection_options
      {
        'TARGETURI' => PROTOCOL_REJECTION.fetch(@app ? 'nextjs_path' : 'apache_path'),
        'SUBREQUEST_PAYLOAD' => REJECTION_PAYLOAD,
        'HttpTrace' => true
      }
    end

    def nx_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/nextjs_middleware/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('NEXTJS_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def nx_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def nx_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Anx_[0-9_]+\z/)

      services = JSON.parse(nx_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.state,s.name
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      vulnerabilities = JSON.parse(nx_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(nx_sql("SELECT coalesce(json_agg(l.id),'[]'::json) FROM loots l JOIN workspaces w ON w.id=l.workspace_id WHERE w.name='#{@workspace}'"))
      rows = { 'services' => services, 'vulnerabilities' => vulnerabilities, 'loot' => loot }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') { |file| file.puts(JSON.generate(workspace: @workspace, reports: rows)) }
      rows
    end

    def nx_call(action, options = {})
      output = nil
      begin
        output = run_target_module(OWNER, 'target', { 'HttpClientTimeout' => 10 }.merge(options), action: action, allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(action: action, options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text))
        end
      end
      expect(text).not_to include('Unknown datastore option')
      expect(Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }).to eq([])
      text
    end

    def nx_assert_reports(vulnerable:)
      rows = nx_reports
      expect(rows.fetch('loot')).to eq([])
      unless vulnerable
        expect(rows.values).to all(eq([]))
        return rows
      end

      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expect(rows.fetch('services').length).to eq(1)
      expect(rows.fetch('vulnerabilities').length).to eq(1)
      service = rows.fetch('services').fetch(0)
      record = rows.fetch('vulnerabilities').fetch(0)
      expect(service.values_at('host', 'port', 'proto', 'state')).to eq([endpoint.fetch('host'), 3000, 'tcp', 'open'])
      expect(record.values_at('host', 'service_id')).to eq([endpoint.fetch('host'), service.fetch('id')])
      expect(record.fetch('refs')).to include('CVE-2025-29927')
      rows
    end

    def nx_protected(action, options = {}, vulnerable: @vulnerable)
      output = nx_call(action, options)
      if action == 'check'
        expect(output).to include(vulnerable ? 'The target is vulnerable.' : 'The target is not exploitable.')
      else
        expect(output).to include(vulnerable ? 'middleware authorization bypass confirmed (CVE-2025-29927)' : 'not bypassed (patched or not Next.js middleware)')
      end
      expect(output).not_to match(/^\[-\] Auxiliary (?:failed|aborted)/)
      nx_assert_reports(vulnerable: vulnerable)
    end

    def nx_ungated(options = {})
      expect(nx_call('check', options)).to include('The service is running, but could not be validated.', 'is not middleware-gated')
      expect(nx_call('run', options)).to include('is not middleware-gated')
      nx_assert_reports(vulnerable: false)
    end
  end
end
