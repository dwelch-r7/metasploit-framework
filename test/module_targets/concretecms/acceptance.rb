# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'
require 'csv'
require 'nokogiri'
require 'digest'

module Acceptance
  # Real CMS, transport, loot and database controls for the serial target lab.
  module ConcreteCms
    OWNER = 'auxiliary/scanner/http/concrete_cms_file_usage_disclosure'
    HEADERS = ['File ID', 'Page ID', 'Version', 'Handle', 'Location'].freeze

    def cms_journal(name, record)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(record)) }
    end

    def cms_state
      JSON.parse(target_exec('target', 'su', '-s', '/bin/sh', 'www-data', '-c', 'php /lab/state.php state'))
    end

    def cms_request(path, phase, fields: nil, cookies: nil, redirects: 0)
      endpoint = target_endpoint('target')
      request = fields ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
      if fields
        request.set_form_data(fields)
        request['Referer'] = "http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{@prefix}/index.php/login"
        request['Origin'] = "http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}"
      end
      request['Cookie'] = cookies.map { |name, value| "#{name}=#{value}" }.join('; ') if cookies && !cookies.empty?
      response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil, open_timeout: 5, read_timeout: 15) { |http| http.request(request) }
      response.get_fields('set-cookie').to_a.each do |header|
        name, value = header.split(';', 2).first.split('=', 2)
        cookies[name] = value if cookies
      end
      cms_journal('native-http.jsonl', phase: phase, method: request.method, path: path, cookies: !cookies.nil?, status: response.code.to_i, body: response.body.to_s, sha256: Digest::SHA256.hexdigest(response.body.to_s))
      if response.is_a?(Net::HTTPRedirection)
        raise 'Too many CMS redirects' if redirects >= 5

        location = URI.join("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}#{path}", response.fetch('location'))
        expect([location.host, location.port]).to eq([endpoint.fetch('host'), endpoint.fetch('port')])
        return cms_request(location.request_uri, phase, cookies: cookies, redirects: redirects + 1)
      end
      response
    end

    def cms_path(path)
      @prefix + path
    end

    def cms_usage_path(fid)
      cms_path('/ccm/system/dialogs/file/usage/' + fid.to_s)
    end

    def cms_native_rows(fid)
      @rows ||= {}
      return @rows.fetch(fid) if @rows.key?(fid)

      response = cms_request(cms_usage_path(fid), 'native-usage')
      expect(response.code.to_i).to eq(@exposed ? 200 : 404)
      expected = @exposed ? @state.fetch('expected_usage').fetch(fid.to_s, []) : []
      if @exposed
        document = Nokogiri::HTML(response.body)
        table = document.at_css('div.ccm-ui table.table-striped')
        expect(table).not_to be_nil
        # The oracle comes from original Page/Usage APIs, independently of the
        # owner's parser. Check that the real HTTP view agrees before using it.
        rows = table.css('tbody tr').map { |row| [fid.to_s] + row.css('td').map { |cell| cell.text.strip } }
        expect(rows.sort).to eq(expected.sort)
      else
        expect(response.body).not_to include('table-striped')
      end
      @rows[fid] = expected
    end

    def cms_native_control(phase)
      root = cms_request(cms_path('/'), phase)
      expect(root.code.to_i).to eq(200)
      if @unrelated
        expect(root.body).to include('It works!')
        expect(cms_request(cms_usage_path(1), phase).code.to_i).to eq(404)
        return
      end
      verified = JSON.parse(target_exec('target', 'php', '/lab/verify.php'))
      expect(verified).to include('version' => @version, 'php' => '8.2.35')
      current = cms_state
      expect(current).to eq(@state) if @state
      cookies = {}
      protected = cms_path('/dashboard/system/basics/name')
      expect(cms_request(protected, phase, cookies: cookies).body).to include('concrete-login-form')
      ['wrong-module-password', '12345'].each do |password|
        login = cms_request(cms_path('/index.php/login'), phase, cookies: cookies)
        token = login.body[/name="ccm_token" value="([^"]+)"/, 1]
        expect(token).not_to be_nil
        cms_request(cms_path('/login/authenticate/concrete'), phase, fields: { uName: 'admin', uPassword: password, ccm_token: token }, cookies: cookies)
        dashboard = cms_request(protected, phase, cookies: cookies)
        if password == 'wrong-module-password'
          expect(dashboard.body).to include('concrete-login-form')
        else
          expect(dashboard.body).to include('ccm-dashboard')
          expect(dashboard.body).not_to include('concrete-login-form')
        end
      end
      private_path = cms_path(URI::DEFAULT_PARSER.escape(current.fetch('pages').fetch('private').fetch('path')))
      anonymous = cms_request(private_path, phase)
      expect(anonymous.body).to include('concrete-login-form')
      administrator = cms_request(private_path, phase, cookies: cookies)
      expect(administrator.code.to_i).to eq(200)
      expect(administrator.body).not_to include('concrete-login-form')
      %w[public unused private].each do |name|
        fid = current.fetch('seed').fetch('files').fetch(name)
        response = cms_request(cms_usage_path(fid), phase)
        expect(response.code.to_i).to eq(@exposed ? 200 : 404)
      end
      expect(cms_state).to eq(current)
    end

    def cms_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def cms_reports
      raise ArgumentError, 'Invalid CMS fixture workspace' unless @workspace.match?(/\Acms_[0-9_]+\z/)

      reports = JSON.parse(cms_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id), '[]'::json) FROM (
          SELECT v.id,v.name,v.info,host(h.address::inet) AS host,s.port,s.proto,
            (SELECT coalesce(json_agg(r.name ORDER BY r.name), '[]'::json)
             FROM refs r JOIN vulns_refs vr ON vr.ref_id=r.id WHERE vr.vuln_id=v.id) AS refs
          FROM vulns v JOIN hosts h ON h.id=v.host_id
          JOIN workspaces w ON w.id=h.workspace_id LEFT JOIN services s ON s.id=v.service_id
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      cms_journal('native-report-snapshots.jsonl', workspace: @workspace, vulnerabilities: reports)
      reports
    end

    def cms_loot
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '*')].select { |path| File.file?(path) }.sort
    end

    def cms_call(options)
      output = nil
      begin
        output = run_target_module(OWNER, 'target', { 'TARGETURI' => cms_path('/'), 'THREADS' => 1, 'HttpClientTimeout' => 8 }.merge(options), allow_errors: true, command_timeout: 90)
      ensure
        cms_journal('owning-calls.jsonl', options: options, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), wrapper_returned: !output.nil?)
      end
      output
    end

    def cms_collect_twice(options = {}, start: 1, count: 50, rejected: false)
      expected = if @unrelated || rejected
                   []
                 else
                   (start...(start + count)).flat_map { |fid| cms_native_rows(fid) }
                 end
      2.times do
        state = cms_state unless @unrelated
        before = cms_loot
        offset = target_exec('target', 'sh', '-c', 'wc -l < /var/log/nginx/access.log').to_i unless @unrelated
        output = cms_call(options)
        created = cms_loot - before
        if expected.empty?
          expect(created).to eq([]), output
          expect(cms_reports).to eq([])
          expect(output).not_to include('Loot saved to:')
        else
          expect(created.length).to eq(1), output
          rows = CSV.parse(File.binread(created.first).force_encoding(Encoding::UTF_8))
          expect(rows.shift).to eq(HEADERS)
          expect(rows.sort).to eq(expected.sort)
          expect(output).to include("Disclosed #{expected.length} file usage record(s)", 'Loot saved to:')
          reports = cms_reports
          expect(reports.length).to eq(1)
          expect(reports.first).to include('host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => 80, 'proto' => 'tcp', 'name' => 'Concrete CMS Unauthenticated File Usage Disclosure')
          expect(reports.first.fetch('refs')).to include('CVE-2026-6826')
          expect(reports.first.fetch('info')).to include("Disclosed #{expected.length} file usage records")
          cms_journal('verified-loot.jsonl', path: created.first, sha256: Digest::SHA256.file(created.first).hexdigest, rows: rows)
        end
        next if @unrelated

        expect(cms_state).to eq(state)
        next if rejected || !@exposed

        access = target_exec('target', 'tail', '-n', "+#{offset + 1}", '/var/log/nginx/access.log')
        identifiers = access.lines.filter_map { |line| line[%r{"GET #{Regexp.escape(cms_path('/ccm/system/dialogs/file/usage/'))}(\d+) HTTP/}, 1]&.to_i }
        expect(identifiers).to eq([start] + (start...(start + count)).to_a)
      end
    end
  end
end
