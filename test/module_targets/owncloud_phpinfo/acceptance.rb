# frozen_string_literal: true

require 'base64'
require 'open3'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare real phpinfo loot and reported secrets with independent native data.
  module OwncloudPhpinfo
    OWNER = 'auxiliary/gather/owncloud_phpinfo_reader'
    SUFFIXES = %w[css js svg gif png html ttf woff ico jpg jpeg json properties min.map js.map auto.map].freeze

    def owncloud_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/owncloud_phpinfo/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('OWNCLOUD_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 240, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def owncloud_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def owncloud_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Aowncloud_[0-9_]+\z/)

      credentials = JSON.parse(owncloud_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT c.id,p.username,secret.data AS private_data,secret.type AS private_type,c.origin_type,
            o.module_full_name,s.port,s.proto,s.name AS service,host(h.address::inet) AS host,
            (SELECT count(*) FROM metasploit_credential_logins l WHERE l.core_id=c.id) AS login_count,
            (SELECT json_agg(json_build_object('status',l.status,'last_attempted_at',l.last_attempted_at) ORDER BY l.id)
             FROM metasploit_credential_logins l WHERE l.core_id=c.id) AS logins
          FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
          LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
          LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
          LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
          LEFT JOIN services s ON s.id=o.service_id LEFT JOIN hosts h ON h.id=s.host_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(owncloud_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT l.id,l.path,l.ltype,l.content_type,l.name,host(h.address::inet) AS host
          FROM loots l JOIN workspaces w ON w.id=l.workspace_id LEFT JOIN hosts h ON h.id=l.host_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      data = { 'credentials' => credentials, 'loot' => loot }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') do |file|
        file.puts(JSON.generate(workspace: @workspace, reports: data))
      end
      data
    end

    def owncloud_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def owncloud_call(options = {})
      before = owncloud_loot
      output = nil
      begin
        output = run_target_module(OWNER, 'target', { 'VHOST' => 'localhost', 'HttpClientTimeout' => 15 }.merge(options), allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text, new_loot: owncloud_loot - before))
        end
      end
      expect(text.valid_encoding?).to be(true)
      expect(text).not_to include('Unknown datastore option')
      [text, owncloud_loot - before]
    end

    def owncloud_collection(options = {}, exposed: !@fixed)
      output, paths = owncloud_call(options)
      unless exposed
        expect(output).not_to include('Found phpinfo page', 'Loot stored to:', 'Credentials')
        expect(paths).to eq([])
        expect(owncloud_reports.values).to all(eq([]))
        return output
      end

      expect(output).not_to include('Auxiliary failed', 'Auxiliary aborted', '[-]')
      expect(output).to include('Found phpinfo page at:', 'Credentials')
      expect(paths.size).to eq(1)
      parsed, status = Open3.capture2('python3', 'test/module_targets/owncloud_phpinfo/phpinfo.py', paths.fetch(0))
      expect(status.success?).to be(true)
      actual = JSON.parse(parsed)
      expect(actual).to eq(@native.fetch('environment'))
      if options['HttpTrace']
        # Raw HTTP tracing is a public client option. Compare the complete actual
        # body for these requests; other native requests have volatile PHP fields.
        expect(output).to include(File.binread(paths.fetch(0)).force_encoding(Encoding::UTF_8))
      end
      environment = @native.fetch('environment')
      {
        'SMTP Password' => 'OWNCLOUD_MAIL_SMTP_PASSWORD',
        'ownCloud Password' => 'OWNCLOUD_ADMIN_PASSWORD',
        'DB Password' => 'OWNCLOUD_DB_PASSWORD',
        'Redis Password' => 'OWNCLOUD_REDIS_PASSWORD'
      }.each { |label, variable| expect(output).to include("#{label}: #{environment.fetch(variable)}") }
      expect(output).to include(environment.fetch('OWNCLOUD_OBJECTSTORE_KEY'), environment.fetch('OWNCLOUD_OBJECTSTORE_SECRET'))
      rows = owncloud_reports
      expect(rows.fetch('credentials').size).to eq(4)
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expected = {
        'smtp' => ['127.0.0.1', 2525, environment.fetch('OWNCLOUD_MAIL_SMTP_NAME'), environment.fetch('OWNCLOUD_MAIL_SMTP_PASSWORD')],
        'owncloud' => [endpoint.fetch('host'), 8080, environment.fetch('OWNCLOUD_ADMIN_USERNAME'), environment.fetch('OWNCLOUD_ADMIN_PASSWORD')],
        'pgsql' => [@native.fetch('addresses').fetch('reporting_db'), 5432, environment.fetch('OWNCLOUD_DB_USERNAME'), environment.fetch('OWNCLOUD_DB_PASSWORD')],
        'redis' => [@native.fetch('addresses').fetch('redis'), 6379, '', environment.fetch('OWNCLOUD_REDIS_PASSWORD')]
      }
      rows.fetch('credentials').each do |row|
        expect(row.values_at('host', 'port', 'username', 'private_data')).to eq(expected.fetch(row.fetch('service')))
        expect(row.values_at('proto', 'private_type', 'origin_type', 'module_full_name', 'login_count')).to eq(['tcp', 'Metasploit::Credential::Password', 'Metasploit::Credential::Origin::Service', OWNER, 1])
        expect(row.fetch('logins')).to eq([{ 'status' => 'Untried', 'last_attempted_at' => nil }])
      end
      expect(rows.fetch('loot').last.values_at('path', 'ltype', 'content_type', 'host')).to eq([paths.fetch(0), 'owncloud.phpinfo', 'text/html', endpoint.fetch('host')])
      output
    end
  end
end
