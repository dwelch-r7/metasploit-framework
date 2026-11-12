# frozen_string_literal: true

require 'base64'
require 'net/http'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Assert real account lifecycle, disclosed profiles, loot and reporting SQL.
  module FourgaBoards
    OWNER = 'auxiliary/gather/4gaboards_users_info_disclosure_cve_2026_53959'
    ADMIN = 'module_admin'
    PASSWORD = 'module-target-admin-password'
    PUBLIC_FIELDS = %w[id name username avatarUrl deletedAt].freeze

    def boards_native(phase)
      output = +''
      argv = ['python3', 'test/module_targets/4gaboards/native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME'), ENV.fetch('BOARDS_PROFILE'), phase]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      expect(passed).to be(true), output
      data = JSON.parse(File.read(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")))
      expect(data.fetch('status')).to eq('native_passed')
      data
    end

    def boards_sql(query, database: 'module_targets')
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', database, '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def boards_users
      JSON.parse(boards_sql(<<~SQL, database: 'module_app'))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT id::text,email,is_admin,phone,organization,sso_github_email,deleted_at,deleted_by_id::text
          FROM user_account
        ) row
      SQL
    end

    def boards_api(path, method: 'GET', data: nil, token: nil)
      endpoint = target_runtime.fetch('endpoints').fetch('target')
      uri = URI::HTTP.build(host: endpoint.fetch('host'), port: endpoint.fetch('port'), path: path)
      request = Net::HTTPGenericRequest.new(method, !data.nil?, true, uri.request_uri, 'Content-Type' => 'application/json')
      request['Authorization'] = 'Bearer ' + token if token
      request.body = JSON.generate(data) if data
      response = Net::HTTP.start(uri.host, uri.port, open_timeout: 10, read_timeout: 20) { |http| http.request(request) }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-http.jsonl'), 'a') do |file|
        file.puts(JSON.generate(method: method, path: path, authenticated: !token.nil?, status: response.code.to_i, body_base64: Base64.strict_encode64(response.body)))
      end
      [response.code.to_i, JSON.parse(response.body)]
    end

    def boards_remove_account(email)
      account = boards_users.find { |row| row.fetch('email').casecmp?(email) && row.fetch('deleted_at').nil? }
      return unless account

      status, data = boards_api('/api/access-tokens', method: 'POST', data: { 'emailOrUsername' => ADMIN, 'password' => PASSWORD })
      expect(status).to eq(200)
      status, removed = boards_api('/api/users/' + account.fetch('id'), method: 'DELETE', token: data.fetch('item'))
      expect([status, removed.fetch('item').fetch('id')]).to eq([200, account.fetch('id')])
      expect(boards_users.find { |row| row.fetch('id') == account.fetch('id') }.fetch('deleted_at')).not_to be_nil
    end

    def boards_reports
      raise ArgumentError, 'Invalid fixture workspace' unless @workspace.match?(/\Aboards_[0-9_]+\z/)

      services = JSON.parse(boards_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT s.id,host(h.address::inet) AS host,s.port,s.proto,s.name,s.state
          FROM services s JOIN hosts h ON h.id=s.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      vulnerabilities = JSON.parse(boards_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT v.id,v.name,v.info,v.service_id,host(h.address::inet) AS host,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name),'[]'::json) FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      loot = JSON.parse(boards_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT l.id,l.path,l.ltype,l.content_type,host(h.address::inet) AS host
          FROM loots l JOIN workspaces w ON w.id=l.workspace_id LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}'
        ) row
      SQL
      result = { 'services' => services, 'vulnerabilities' => vulnerabilities, 'loot' => loot }
      File.open(File.join(target_runtime.fetch('artifacts'), 'native-report-snapshots.jsonl'), 'a') do |file|
        file.puts(JSON.generate(workspace: @workspace, reports: result, users: @app ? boards_users : []))
      end
      result
    end

    def boards_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def boards_call(email, options = {})
      before = boards_loot
      output = nil
      begin
        values = { 'EMAIL' => email, 'ADMIN_USERNAME' => ADMIN, 'ADMIN_PASSWORD' => PASSWORD, 'HttpClientTimeout' => 15 }.merge(options)
        output = run_target_module(OWNER, 'target', values, allow_errors: true, command_timeout: 90)
      ensure
        text = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        File.open(File.join(target_runtime.fetch('artifacts'), 'owning-calls.jsonl'), 'a') do |file|
          file.puts(JSON.generate(email: email, options: options, workspace: @workspace, wrapper_returned: !output.nil?, output: text, new_loot: boards_loot - before))
        end
      end
      expect(text).not_to include('Unknown datastore option')
      [text, boards_loot - before]
    end

    def boards_harvest(email, options = {}, cleanup: true, login_failure: false)
      output, paths = boards_call(email, options)
      expect(output).to include("User '#{email}' registered successfully", 'Users information saved to: ')
      expect(paths.length).to eq(1)
      users = JSON.parse(File.binread(paths.fetch(0)))
      expected = @native.fetch('expected_users')
      expect(users.map { |user| user.fetch('id') }.sort).to eq(expected.map { |user| user.fetch('id') }.sort)
      users.each do |user|
        native = expected.find { |row| row.fetch('id') == user.fetch('id') }
        stable = @fixed ? PUBLIC_FIELDS : %w[id email name username phone organization isAdmin ssoGoogleEmail ssoGithubEmail ssoMicrosoftEmail ssoOidcEmail]
        expect(user.slice(*stable)).to eq(native.slice(*stable))
        expect(user.keys.sort).to eq(PUBLIC_FIELDS.sort) if @fixed
      end
      account = boards_users.find { |row| row.fetch('email').casecmp?(email) }
      expect(account).not_to be_nil
      if cleanup
        expect(output).to include("User '#{email}' deleted successfully")
        expect(account.fetch('deleted_at')).not_to be_nil
        expect(account.fetch('deleted_by_id')).to eq(@native.fetch('administrator').fetch('id'))
      else
        expect(account.fetch('deleted_at')).to be_nil
        expect(output).to include(login_failure ? 'Failed to login as administrator' : 'Administrator credentials not provided')
      end
      rows = boards_reports
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expect(rows.fetch('services').length).to eq(1)
      expect(rows.fetch('services').fetch(0).values_at('host', 'port', 'proto', 'name', 'state')).to eq([endpoint.fetch('host'), 1337, 'tcp', 'http', 'open'])
      expect(rows.fetch('loot').map { |row| row.fetch('path') }).to include(paths.fetch(0))
      if @fixed
        expect(rows.fetch('vulnerabilities')).to eq([])
      else
        expect(rows.fetch('vulnerabilities').length).to eq(1)
        record = rows.fetch('vulnerabilities').fetch(0)
        expect(record.values_at('host', 'service_id', 'name')).to eq([endpoint.fetch('host'), rows.fetch('services').fetch(0).fetch('id'), OWNER])
        expect(record.fetch('refs')).to include('CVE-2026-53959')
      end
      rows
    ensure
      boards_remove_account(email) if @app && email
    end
  end
end
