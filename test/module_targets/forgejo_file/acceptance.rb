# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare real renderer output, loot and native PostgreSQL records.
  module ForgejoFile
    OWNER = 'auxiliary/gather/forgejo_orgmode_fileread_cve_2026_59774'
    USERNAME = 'module-user'
    PASSWORD = 'module-target-forgejo-password'
    PUBLIC_REPO = USERNAME + '/public-test'
    PRIVATE_REPO = USERNAME + '/private-test'

    def forgejo_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/forgejo_file/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('FORGEJO_VERSION'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def forgejo_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def forgejo_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Aforgejo_[0-9_]+\z/)

      services = JSON.parse(forgejo_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT s.id, host(h.address::inet) AS host, s.port, s.proto, s.name, s.state, s.info
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      vulnerabilities = JSON.parse(forgejo_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT v.id, v.name, v.info, v.service_id, host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name), '[]'::json)
             FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      data = { 'services' => services, 'vulnerabilities' => vulnerabilities }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') do |file|
        file.puts(JSON.generate(workspace: @workspace, reports: data))
      end
      data
    end

    def forgejo_assert_reports(service:, vulnerable: false, path: nil)
      rows = forgejo_reports
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      if service
        expect(rows.fetch('services').size).to eq(1)
        record = rows.fetch('services').fetch(0)
        expect(record.values_at('host', 'port', 'proto', 'name', 'state')).to eq([endpoint.fetch('host'), 3000, 'tcp', 'http', 'open'])
      else
        expect(rows.fetch('services')).to eq([])
      end
      if vulnerable
        expect(rows.fetch('vulnerabilities').size).to eq(1)
        record = rows.fetch('vulnerabilities').fetch(0)
        expect(record.values_at('host', 'service_id', 'name')).to eq([endpoint.fetch('host'), rows.fetch('services').fetch(0).fetch('id'), 'Forgejo Arbitrary File Read via Org-mode Include'])
        expect(record.fetch('info')).to include(path)
        expect(record.fetch('refs')).to include('CVE-2026-59774')
      else
        expect(rows.fetch('vulnerabilities')).to eq([])
      end
      rows
    end

    def forgejo_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def forgejo_call(options = {}, action: 'run')
      data = { 'USERNAME' => USERNAME, 'PASSWORD' => PASSWORD, 'HttpClientTimeout' => 20 }.merge(options)
      before = forgejo_loot
      output = nil
      begin
        output = run_target_module(OWNER, 'target', data, action: action, allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(action: action, options: options, workspace: @workspace, output: text,
                                  wrapper_returned: !output.nil?, new_loot: forgejo_loot - before))
        end
      end
      expect(text.valid_encoding?).to be(true)
      expect(text).not_to include('Unknown datastore option')
      [text, forgejo_loot - before]
    end

    def forgejo_read(kind = 'default', options: {}, default_options: false)
      file = @native.fetch('files').fetch(kind)
      values = default_options ? options : { 'FILEPATH' => file.fetch('path') }.merge(options)
      output, paths = forgejo_call(values)
      if @vulnerable
        expected = file.fetch('rendered').fetch('text')
        expect(output).not_to include('[-]', 'Auxiliary aborted')
        marker = "Successfully read #{file.fetch('path')} (#{expected.bytesize} bytes)\n"
        start = output.index(marker)
        expect(start).not_to be_nil
        start += marker.length
        boundary = values.fetch('STORE_LOOT', true) ? "\n[+] File saved to: " : "\n[*] Auxiliary module execution completed"
        finish = output.index(boundary, start)
        expect(finish).not_to be_nil
        expect(output[start...finish].b).to eq(expected.b)
        if values.fetch('STORE_LOOT', true)
          expect(paths.size).to eq(1)
          expect(File.binread(paths.fetch(0))).to eq(expected.b)
        else
          expect(paths).to eq([])
        end
        forgejo_assert_reports(service: true, vulnerable: true, path: file.fetch('path'))
      else
        expect(output).to include('[-]')
        expect(output).not_to include('Successfully read ', 'File saved to: ')
        expect(paths).to eq([])
        forgejo_assert_reports(service: values.fetch('AutoCheck', true))
      end
      output
    end

    def forgejo_negative(options, service: false)
      output, paths = forgejo_call({ 'REPO' => PUBLIC_REPO, 'AutoCheck' => false }.merge(options))
      expect(output).to include('[-]')
      expect(output).not_to include('Successfully read ', 'File saved to: ')
      expect(paths).to eq([])
      forgejo_assert_reports(service: service)
      output
    end
  end
end
