# frozen_string_literal: true

require 'digest'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare the public collection entrypoint with the master's native key and SQL.
  module SaltstackZeromq
    OWNER = 'auxiliary/gather/saltstack_salt_root_key'

    def salt_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/saltstack_zeromq/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('SALT_VERSION'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 240, capture: output, quiet: true)
      expect(passed).to be(true), output
      result = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(result.fetch('status')).to eq('native_passed')
      result
    end

    def salt_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def salt_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Asalt_[0-9_]+\z/)

      credentials = JSON.parse(salt_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
            o.module_full_name,s.id AS service_id,s.port,s.proto,s.name AS service,host(h.address::inet) AS host,
            (SELECT json_agg(json_build_object('status',l.status,'last_attempted_at',l.last_attempted_at) ORDER BY l.id)
             FROM metasploit_credential_logins l WHERE l.core_id=c.id) AS logins
          FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
          LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
          LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
          LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
          LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      services = JSON.parse(salt_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.name,s.state FROM services s
          JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(salt_sql("SELECT coalesce(json_agg(l.id),'[]'::json) FROM loots l JOIN workspaces w ON w.id=l.workspace_id WHERE w.name='#{@workspace}'"))
      vulns = JSON.parse(salt_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      result = { 'credentials' => credentials, 'services' => services, 'loot' => loot, 'vulns' => vulns }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') { |file| file.puts(JSON.generate(workspace: @workspace, reports: result)) }
      result
    end

    def salt_call(options = {})
      output = nil
      begin
        output = run_target_module(OWNER, 'target', { 'ConnectTimeout' => 3 }.merge(options), allow_errors: true, command_timeout: 60)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text))
        end
      end
      expect(text).not_to include('Unknown datastore option')
      expect(Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }).to eq([])
      text
    end

    def salt_collection(options = {})
      output = salt_call(options)
      rows = salt_reports
      unless @vulnerable
        expect(output).to include('Did not receive serialized auth info')
        expect(output).not_to include('Root key:')
        expect(rows.values).to all(eq([]))
        return rows
      end

      expect(output).not_to match(/^\[-\] Auxiliary (?:failed|aborted)/)
      key = output.match(/Root key: (\S+)/)&.[](1)
      expect(key).not_to be_nil
      expect(Digest::SHA256.hexdigest(key)).to eq(@native.fetch('master').fetch('root_key_sha256'))
      expect(rows.fetch('credentials').length).to eq(1)
      expect(rows.fetch('services').length).to eq(1)
      credential = rows.fetch('credentials').fetch(0)
      service = rows.fetch('services').fetch(0)
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expect(credential.values_at('username', 'private_type', 'origin_type', 'module_full_name')).to eq(['root', 'Metasploit::Credential::Password', 'Metasploit::Credential::Origin::Service', OWNER])
      expect(credential.fetch('private_data')).to eq(key)
      expect(credential.values_at('host', 'port', 'proto', 'service', 'service_id')).to eq([endpoint.fetch('host'), 4506, 'tcp', 'salt/zeromq', service.fetch('id')])
      expect(credential.fetch('logins')).to eq([{ 'status' => 'Untried', 'last_attempted_at' => nil }])
      expect(service.values_at('host', 'port', 'proto', 'name', 'state')).to eq([endpoint.fetch('host'), 4506, 'tcp', 'salt/zeromq', 'open'])
      expect(rows.fetch('loot')).to eq([])
      expect(rows.fetch('vulns').length).to eq(1)
      vuln = rows.fetch('vulns').fetch(0)
      expect(vuln.values_at('host', 'service_id', 'name')).to eq([endpoint.fetch('host'), service.fetch('id'), 'SaltStack Salt Master Server Root Key Disclosure'])
      expect(vuln.fetch('info')).to eq("Vulnerability confirmed by check of #{OWNER}.")
      expect(vuln.fetch('refs')).to include('CVE-2020-11651')
      rows
    end
  end
end
