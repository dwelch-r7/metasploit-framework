# frozen_string_literal: true

require 'base64'
require 'open3'
require 'sqlite3'

module Acceptance
  # Compare actual file bytes and authenticate generated tickets independently.
  module Ni8mare
    OWNER = 'auxiliary/gather/ni8mare_cve_2026_21858'

    def record(name, value)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(value)) }
    end

    def native(action, tag)
      argv = ['python3', '-B', 'test/module_targets/ni8mare/native_probe.py', action, tag]
      output, error, status = Open3.capture3(*argv)
      record('native-probe-status.jsonl', argv: argv, actual_exit: status.exitstatus, stdout: output, stderr: error)
      expect(status.exitstatus).to eq(0), error
      JSON.parse(output)
    end

    def sql(query)
      target_exec('reporting_db', 'psql', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query)
    end

    def reports
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Ani8mare_[0-9_]+\z/)

      loot = JSON.parse(sql("SELECT coalesce(json_agg(row_to_json(l) ORDER BY l.id),'[]'::json) FROM (SELECT loots.id,loots.path,loots.ltype,loots.content_type,host(hosts.address::inet) AS host FROM loots JOIN workspaces ON workspaces.id=loots.workspace_id LEFT JOIN hosts ON hosts.id=loots.host_id WHERE workspaces.name='#{@workspace}') l"))
      credentials = JSON.parse(sql("SELECT coalesce(json_agg(row_to_json(c) ORDER BY c.id),'[]'::json) FROM (SELECT cores.id,publics.username,privates.data AS private_data,privates.type AS private_type,privates.jtr_format,cores.origin_type,imports.filename,origins.module_full_name FROM metasploit_credential_cores cores JOIN workspaces ON workspaces.id=cores.workspace_id LEFT JOIN metasploit_credential_publics publics ON publics.id=cores.public_id LEFT JOIN metasploit_credential_privates privates ON privates.id=cores.private_id LEFT JOIN metasploit_credential_origin_services origins ON origins.id=cores.origin_id AND cores.origin_type='Metasploit::Credential::Origin::Service' LEFT JOIN metasploit_credential_origin_imports imports ON imports.id=cores.origin_id AND cores.origin_type='Metasploit::Credential::Origin::Import' WHERE workspaces.name='#{@workspace}') c"))
      result = { 'loot' => loot, 'credentials' => credentials }
      record('report-snapshots.jsonl', workspace: @workspace, data: result)
      result
    end

    def loot_files
      Dir[File.join(target_runtime.fetch('artifacts'), 'msf-config', 'loot', '**', '*')].select { |path| File.file?(path) }.sort
    end

    def call_owner(options = {}, reuse: false)
      history_path = File.join(target_runtime.fetch('artifacts'), 'owning-auth-completions.jsonl')
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      history = File.file?(history_path) ? File.readlines(history_path).map { |line| JSON.parse(line).fetch('monotonic') }.select { |value| now - value < 60.2 } : []
      if history.length >= 5
        delay = 60.2 - (now - history[-5])
        record('auth-budget-waits.jsonl', seconds: delay, reason: 'Preserve genuine default five-per-minute login policy')
        sleep(delay)
      end
      previous = loot_files
      values = { 'USERNAME' => @reader.fetch('email'), 'PASSWORD' => @reader.fetch('password'), 'HttpClientTimeout' => 10 }.merge(options)
      output = nil
      begin
        if reuse
          endpoint = target_runtime.fetch('module_endpoints').fetch('target')
          output = console_command('run ' + format_datastore_options({ 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(values)), timeout: 90)
        else
          output = run_target_module(OWNER, 'target', values, allow_errors: true, command_timeout: 90)
        end
      ensure
        record('owning-auth-completions.jsonl', monotonic: Process.clock_gettime(Process::CLOCK_MONOTONIC), workspace: @workspace)
        captured = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
        record('owning-calls.jsonl', workspace: @workspace, options: values, same_selected_instance: reuse, wrapper_returned: !output.nil?, output: captured, loot: loot_files - previous)
      end
      expect(output).not_to include('Unknown datastore option')
      [output, loot_files - previous]
    end

    def idle
      expect(native('registry', @case)).to include('preserved' => true, 'flow_ids' => @native.fetch('flow_ids'))
      output = console_command(%q{irb -e 'puts "NI8MARE_IDLE=" + {jobs: framework.jobs.keys, sessions: framework.sessions.keys}.to_json'})
      expect(output).to include('NI8MARE_IDLE={"jobs":[],"sessions":[]}')
    end

    def collect_file(name)
      expected = @native.fetch('files').fetch(name)
      2.times do |iteration|
        output, files = call_owner({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => expected.fetch('path') }, reuse: iteration.positive?)
        expect(output).not_to include('Auxiliary failed', 'Auxiliary aborted')
        expect(files.length).to eq(1)
        expect(Base64.strict_encode64(File.binread(files.fetch(0)))).to eq(expected.fetch('base64'))
        expect(reports.fetch('loot')).to include(include('path' => files.fetch(0), 'host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host')))
        record('file-proofs.jsonl', fixture: name, path: expected.fetch('path'), matched: true, loot: files.fetch(0))
        idle
      end
    end

    def rejected_file(path)
      2.times do |iteration|
        output, files = call_owner({ 'ACTION' => 'READ_FILE', 'TARGET_FILENAME' => path }, reuse: iteration.positive?)
        expect(output).to match(/Auxiliary (?:aborted due to failure|failed): (?:unexpected-reply|not-found|no-access)/)
        expect(files).to eq([])
        expect(reports.values).to all(eq([]))
        idle
      end
    end

    def session_extraction(kind)
      @fixture = native('seed', kind)
      2.times do |iteration|
        output, files = call_owner({ 'ACTION' => 'EXTRACT_SESSION', 'TARGET_EMAIL' => @fixture.fetch('email') }, reuse: iteration.positive?)
        expect(output).not_to include('Auxiliary failed', 'Auxiliary aborted')
        expect(files.length).to eq(2)
        database_path = files.find { |path| File.binread(path, 16) == "SQLite format 3\0" }
        expect(database_path).not_to be_nil
        database = SQLite3::Database.new(database_path, readonly: true)
        begin
          expect(database.get_first_row('SELECT id,email,password FROM user WHERE id=?', @fixture.fetch('id'))).to eq(@fixture.values_at('id', 'email', 'password_hash'))
        ensure
          database.close
        end
        config = JSON.parse(File.binread((files - [database_path]).fetch(0)))
        expect(config.fetch('encryptionKey')).to eq(@native.fetch('encryption_key'))
        token = output[/JWT ticket as [^\r\n]+: ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/, 1]
        expect(token).not_to be_nil, output
        tag = "#{@case}_#{iteration}"
        File.write(File.join(target_runtime.fetch('artifacts'), "token-#{tag}.json"), JSON.generate(token: token))
        actual = native('token', tag)
        record('token-proofs.jsonl', workspace: @workspace, kind: kind, claim: @fixture.fetch('claim'), actual: actual, loot: files)
        expect(actual).to include('status' => 200, 'id' => @fixture.fetch('id'), 'email' => @fixture.fetch('email'), 'role' => 'global:owner', 'can_create_users' => true)
        stored = reports
        expect(stored.fetch('loot').map { |row| row.fetch('path') }).to include(*files)
        expect(stored.fetch('credentials')).to include(include('username' => @fixture.fetch('email'), 'private_data' => @fixture.fetch('password_hash'), 'private_type' => 'Metasploit::Credential::NonreplayableHash', 'jtr_format' => 'bf', 'origin_type' => 'Metasploit::Credential::Origin::Import'))
        database_loot = stored.fetch('loot').map { |row| row.fetch('path') }.select { |path| File.binread(path, 16) == "SQLite format 3\0" }
        expect(database_loot).to include(*stored.fetch('credentials').map { |row| row.fetch('filename') })
        idle
      end
    end
  end
end
