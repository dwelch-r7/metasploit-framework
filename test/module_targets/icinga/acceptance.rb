# frozen_string_literal: true

require_relative '../freeswitch_execution/acceptance'

module Acceptance
  # Real HTTP responses, filesystem bytes and persisted loot are independent oracles.
  module Icinga
    include FreeSwitchExecution

    ICINGA_OWNER = 'auxiliary/scanner/http/icinga_static_library_file_directory_traversal'

    def icinga_native(phase)
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      catalog = JSON.parse(File.read('test/module_targets/icinga/vendor.json')).fetch(@version)
      @affected = catalog.fetch('affected')
      # A separate Python client uses the exact address/ports reached by the owner.
      output = target_exec('framework', 'python3', '-B', 'test/module_targets/icinga/native_http.py', endpoint.fetch('host'), endpoint.fetch('port').to_s, @prefix, '8081')
      fx_record('icinga-native-http-status.jsonl', phase: phase, endpoint: endpoint, oracle: 'Independent Python client on the owning module network')
      protocol = JSON.parse(output)
      fx_record('icinga-native-http.jsonl', phase: phase, records: protocol)
      version = target_exec('target', 'icingacli', '--version')
      expect(version).to include(@version, catalog.fetch('source_commit'))
      controller = '/usr/share/icingaweb2/' + catalog.fetch('static_controller_path', 'library/Icinga/Web/Controller/StaticController.php')
      source = target_exec('target', 'sha256sum', controller)
      expect(source.split.first).to eq(catalog.fetch('static_controller_sha256'))
      source_manifest = nil
      if catalog.key?('source_archive_sha256')
        manifest = target_exec('target', 'cat', '/opt/icinga-source-files.sha256')
        source_manifest = Digest::SHA256.hexdigest(manifest)
        expect(source_manifest).to eq(catalog.fetch('source_manifest_sha256'))
        verified = target_exec('target', 'sha256sum', '-c', '/opt/icinga-source-files.sha256')
        expect(verified.lines.length).to eq(catalog.fetch('source_file_count'))
      end
      target_exec('target', 'test', '!', '-e', '/usr/share/icingaweb2/library/Icinga/Web/Controller/StaticController.php') if @version == '2.8.5'
      expect(protocol.fetch('home').fetch('status')).to eq(200)
      expect(Base64.strict_decode64(protocol.fetch('home').fetch('body_base64'))).to include('<meta name="application-name" content="Icinga Web 2">')
      expect(Base64.strict_decode64(protocol.fetch('unrelated_home').fetch('body_base64'))).to include('Unrelated service')
      expect(protocol.fetch('unrelated_read').fetch('status')).to eq(404)
      expect(protocol.fetch('refused')).to be(true)
      expect(Base64.strict_decode64(protocol.fetch('direct').fetch('body_base64'))).not_to eq(File.binread('test/module_targets/icinga/files/proof/proof.txt'))
      files = %w[proof.txt whitespace.txt binary.bin empty.txt]
      files.each do |name|
        row = protocol.fetch(name)
        expect(row.fetch('status')).to eq(@affected ? 200 : 404)
        expect(Base64.strict_decode64(row.fetch('body_base64'))).to eq(File.binread("test/module_targets/icinga/files/proof/#{name}")) if @affected
      end
      unicode_status = @affected ? 200 : 404
      ['space name.txt', 'unicode-Ω.txt'].each do |name|
        row = protocol.fetch(name)
        expect(row.fetch('status')).to eq(name.include?(' ') ? 400 : unicode_status)
        expect(protocol.fetch(name + ':encoded').fetch('status')).to eq(404)
        expect(Base64.strict_decode64(row.fetch('body_base64'))).to eq(File.binread("test/module_targets/icinga/files/proof/#{name}")) if row.fetch('status') == 200
      end
      %w[denied.txt missing.txt directory].each { |name| expect(protocol.fetch(name).fetch('status')).to eq(404) }
      target_exec('target', 'test', '-f', '/lab/proof/denied.txt')
      target_exec('target', 'test', '-r', '/lab/proof/denied.txt', expected_exit: 1)
      process = target_exec('target', 'sh', '-c', 'cat /proc/1/stat; parent=$(cat /var/run/apache2/apache2.pid); cat /proc/"$parent"/stat; child=$(cat /tmp/icinga-unrelated.pid); cat /proc/"$child"/stat; readlink /proc/"$parent"/exe')
      identity = process.lines.first(3).map { |line| [line.split.first, line.split(') ', 2).last.split.fetch(19)] }
      apache = target_exec('target', 'cat', '/usr/share/icingaweb2/packages/files/apache/icingaweb2.conf')
      proofs = target_exec('target', 'sh', '-c', 'find /lab -type f ! -name denied.txt -print0 | sort -z | xargs -0 sha256sum')
      record = { protocol: protocol, source: source, source_manifest: source_manifest, affected: @affected, version: version, identity: identity, apache: apache, proofs: proofs }
      fx_record('icinga-native-state.jsonl', phase: phase, state: record)
      record
    end

    def icinga_reports
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Aicinga_[0-9_]+\z/)

      data = JSON.parse(fs_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.id),'[]'::json) FROM (
          SELECT loot.id,loot.path,loot.ltype,loot.content_type,loot.name,host(host.address) AS address
          FROM loots loot JOIN workspaces workspace ON workspace.id=loot.workspace_id
          LEFT JOIN hosts host ON host.id=loot.host_id WHERE workspace.name='#{@workspace}'
        ) row;
      SQL
      fx_record('icinga-loot-snapshots.jsonl', workspace: @workspace, rows: data)
      data
    end

    def icinga_call(options = {}, action: 'run')
      values = { 'THREADS' => 1, 'HttpClientTimeout' => 5, 'ConnectTimeout' => 2 }.merge(options)
      values['TARGETURI'] = @prefix unless @prefix == '/' || values.key?('TARGETURI')
      output = nil
      begin
        output = run_target_module(ICINGA_OWNER, 'target', values, action: action, allow_errors: true, command_timeout: 40)
      ensure
        raw = output || console.all_data
        fx_record('icinga-owning-calls.jsonl', workspace: @workspace, action: action, options: values, wrapper_returned: !output.nil?, output_base64: Base64.strict_encode64(raw.b), output: raw.dup.force_encoding(Encoding::UTF_8).scrub)
      end
      output.b
    end

    def icinga_collect(name)
      path = '/lab/proof/' + name
      row = @native.fetch(:protocol).fetch(name)
      expected = row.fetch('status') == 200 ? Base64.strict_decode64(row.fetch('body_base64')) : nil
      2.times do |iteration|
        previous = icinga_reports
        output = icinga_call({ 'FILE' => path })
        current = icinga_reports
        if expected && !expected.empty?
          expect(current.length).to eq(iteration + 1), output
          expect(current.first(previous.length)).to eq(previous)
          saved = current.last
          expect(saved).to include('ltype' => 'icinga file', 'content_type' => 'text/plain', 'name' => path, 'address' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
          expect(File.binread(saved.fetch('path'))).to eq(expected)
          expect(output).to include(' saved to '.b)
        else
          expect(current).to eq([]), output
          expect(output).not_to include(' saved to '.b)
        end
      end
    end
  end
end
