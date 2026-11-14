# frozen_string_literal: true

require 'base64'
require 'securerandom'
require 'uri'
require_relative '../../../tools/dev/module_target_endpoint'

# Compare actual owner operations with genuine SDK and native process controls.
module MCPJamAcceptance
  OWNER = 'exploit/multi/http/mcpjam_inspector_rce'

  def record(name, value)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(value)) }
  end

  def native(action, **values)
    output = target_exec('target', 'node', '-e', File.read('test/module_targets/mcpjam/native_client.js'), JSON.generate(values.merge(action: action)))
    result = JSON.parse(output)
    record('mcpjam-native-observations.jsonl', action: action, inputs: values, result: result)
    result
  end

  def api(path, body = nil, method: nil)
    result = native('http', path: path, body: body, method: method, headers: @native_headers || {})
    expect(result.fetch('status')).to eq(200), result.inspect
    result.fetch('document')
  end

  def registry
    result = api('/api/mcp/servers')
    expect(result.fetch('success')).to be(true)
    result.fetch('servers').sort_by { |server| server.fetch('id') }
  end

  def process_identities
    native('processes').map { |row| row.except('state') }
  end

  def inspected(kind, identifier)
    argv = ['docker', kind, 'inspect', identifier]
    output, error, status = Open3.capture3(*argv)
    record('mcpjam-endpoint-inspections.jsonl', argv: argv, actual_exit: status.exitstatus, stdout: output, stderr: error)
    expect(status.exitstatus).to eq(0), error
    JSON.parse(output).fetch(0)
  end

  def select_endpoint
    compose = target_runtime.fetch('compose')
    selector = ModuleTargetEndpoint.new(project: compose.fetch(compose.index('--project-name') + 1), network: 'default', container: lambda { |service|
      output, error, status = Open3.capture3(*compose, 'ps', '-q', service)
      expect(status.exitstatus).to eq(0), error
      inspected('container', output.strip)
    }, network_inspection: ->(identifier) { inspected('network', identifier) })
    target_runtime.fetch('module_endpoints')['target'] = { 'host' => selector.address('target'), 'port' => 6274 }
  end

  def native_before
    expected = JSON.parse(File.read('test/module_targets/mcpjam/vendor.json')).fetch(ENV.fetch('MCPJAM_TARGET_VERSION'))
    metadata = native('metadata')
    @native_metadata = metadata
    expect(metadata).to include(expected.except('image').merge('uid' => 1000))
    html = native('http', path: '/', body: nil)
    expect(html.fetch('status')).to eq(200)
    expect(Base64.strict_decode64(html.fetch('body_base64'))).to include('MCPJam Inspector')
    version = expected.fetch('version')
    peer = native('http', path: '/', host: target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
    if %w[1.4.3 1.4.6].include?(version)
      expect(peer).to include('transport_error' => 'ECONNREFUSED')
    else
      expect(peer.fetch('status')).to eq(200)
    end
    unauthenticated = native('http', path: '/api/mcp/connect', body: { serverId: 'native-incomplete' })
    if version == '1.5.0'
      expect(unauthenticated.fetch('status')).to eq(401)
      token_response = native('http', path: '/api/session-token')
      expect(token_response.fetch('status')).to eq(200)
      token = token_response.fetch('document').fetch('token')
      expect(token).to match(/\A[0-9a-f]{64}\z/)
      # This genuine local administrative control is never supplied to the owner.
      @native_headers = { 'X-MCP-Session-Auth' => 'Bearer ' + token }
    else
      expect(unauthenticated).to include('status' => 400, 'document' => include('error' => 'serverConfig is required'))
    end
    expect(registry).to eq([])
    @foreign_id = 'native-foreign-' + SecureRandom.hex(6)
    @native_fixture = { path: '/tmp/module-target-mcpjam-native-' + SecureRandom.hex(6), marker: SecureRandom.hex(12) }
    config = { command: 'node', args: ['-e', File.read('test/module_targets/mcpjam/native_server.js'), JSON.generate(@native_fixture)] }
    expect(api('/api/mcp/connect', { serverId: @foreign_id, serverConfig: config })).to include('success' => true, 'status' => 'connected')
    marker = native('read', path: @native_fixture.fetch(:path))
    @native_identity = JSON.parse(Base64.strict_decode64(marker.fetch('base64')))
    expect(@native_identity).to include('marker' => @native_fixture.fetch(:marker), 'uid' => 1000)
    text = 'Native command café 雪'
    result = api('/api/mcp/tools/execute', { serverId: @foreign_id, toolName: 'native_command', parameters: { command: "printf '#{text}'" } })
    expect(result.fetch('result')).to include('isError' => false)
    expect(result.fetch('result').fetch('content').fetch(0).fetch('text')).to eq(text)
    # Prove the same backend accepts and removes a correctly encoded Unicode ID.
    unicode_id = 'native-café-雪-' + SecureRandom.hex(4)
    unicode_fixture = { path: '/tmp/module-target-mcpjam-unicode-control-' + SecureRandom.hex(6), marker: SecureRandom.hex(12) }
    unicode_config = { command: 'node', args: ['-e', File.read('test/module_targets/mcpjam/native_server.js'), JSON.generate(unicode_fixture)] }
    expect(api('/api/mcp/connect', { serverId: unicode_id, serverConfig: unicode_config })).to include('success' => true)
    unicode_identity = JSON.parse(Base64.strict_decode64(native('read', path: unicode_fixture.fetch(:path)).fetch('base64')))
    expect(unicode_identity).to include('marker' => unicode_fixture.fetch(:marker), 'uid' => 1000)
    escaped = URI.encode_www_form_component(unicode_id).gsub('+', '%20')
    api('/api/mcp/servers/' + escaped, nil, method: 'DELETE')
    wait_for_expect(40, 0.2) { expect(process_identities.map { |row| row.fetch('pid') }).not_to include(unicode_identity.fetch('pid')) }
    [unicode_fixture.fetch(:path), unicode_fixture.fetch(:path) + '.events'].each { |path| native('unlink', path: path) }
    @foreign_registry = registry
    @baseline_processes = process_identities
    expect(@baseline_processes).to include(include('pid' => @native_identity.fetch('pid'), 'uid' => 1000))
  end

  def start_console
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    code = 'load "test/module_targets/mcpjam/input_audit.rb";puts "MCPJAM_AUDIT="+MCPJamTargetInputs.install(framework)'
    expect(console_command("irb -e #{code.inspect}")).to include('MCPJAM_AUDIT=exploit/multi/http/mcpjam_inspector_rce')
    code = 'load "test/module_targets/mcpjam/session_control.rb";puts "MCPJAM_SESSION_CONTROL="+MCPJamSessionControl.install(framework).to_json'
    expect(console_command("irb -e #{code.inspect}")).to include('MCPJAM_SESSION_CONTROL={"installed":true,')
  end

  def preserved
    wait_for_expect(40, 0.2) do
      expect(registry).to eq(@foreign_registry)
      expect(process_identities).to eq(@baseline_processes)
    end
    idle
  end

  def idle
    output = console_command(%q{irb -e 'puts "MCPJAM_IDLE="+{jobs:framework.jobs.keys,sessions:framework.sessions.keys}.to_json'})
    expect(output).to include('MCPJAM_IDLE={"jobs":[],"sessions":[]}')
  end

  def owner_rows
    path = File.join(target_runtime.fetch('artifacts'), 'mcpjam-owner-calls.jsonl')
    File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
  end

  def invoke(options = {}, action: 'run', reuse: false, expected_check: 'vulnerable')
    offset = owner_rows.length
    defaults = { 'TARGET' => 0, 'PAYLOAD' => 'cmd/unix/generic', 'CMD' => 'true', 'DisablePayloadHandler' => true, 'AutoCheck' => true, 'ForceExploit' => false, 'EXEC_METHOD' => 'mcp_tool', 'FETCH_OUTPUT' => true, 'SERVER_ID' => 'module-case-' + @case, 'SSL' => false, 'HttpClientTimeout' => 5, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true }
    settings = defaults.merge(options)
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
      captured = (output || console.all_data).dup.force_encoding(Encoding::UTF_8)
      record('mcpjam-invocations.jsonl', action: action, options: settings, reuse: reuse, returned: !output.nil?, output: captured, rows: owner_rows.drop(offset))
    end
    text = output.dup.force_encoding(Encoding::UTF_8)
    expect(text.valid_encoding?).to be(true)
    expect(text).not_to match(/Unknown datastore option|Invalid option|undefined method/)
    checks = owner_rows.drop(offset).select { |row| row['kind'] == 'check-return' }
    if action == 'check' || settings.fetch('AutoCheck')
      expect(checks.length).to eq(1)
      expect(checks.fetch(0)).to include('code' => expected_check)
      expect(checks.fetch(0).fetch('reason')).not_to be_empty
    else
      expect(checks).to eq([])
    end
    text
  end

  def command_proof(text, options = {})
    2.times do |iteration|
      path = "/tmp/module-target-mcpjam-#{@case}-#{iteration}"
      @owned_files << path
      expect(native('exists', path: path)).to be(false)
      command = "printf '#{text}' > #{path}"
      output = invoke({ 'CMD' => command }.merge(options), reuse: iteration.positive?)
      expect(output).not_to include('Exploit failed', 'Exploit aborted due to failure', 'Unexpected tools/execute response')
      wait_for_expect(40, 0.2) { expect(native('exists', path: path)).to be(true), 'The owning command did not create its independently observed artifact' }
      proof = native('read', path: path)
      expect(proof).to include('uid' => 1000, 'base64' => Base64.strict_encode64(text.b))
      execute = owner_rows.reverse.find { |row| row['kind'] == 'execute-command' }
      expect(execute.fetch('command_base64')).to eq(Base64.strict_encode64(command.b))
      preserved
    end
  end

  def blocked_proof(options = {}, dispatch: false)
    2.times do |iteration|
      path = "/tmp/module-target-mcpjam-negative-#{@case}-#{iteration}"
      @owned_files << path
      offset = owner_rows.length
      output = invoke({ 'CMD' => "printf negative > #{path}" }.merge(options), reuse: iteration.positive?, expected_check: negative_check)
      calls = owner_rows.drop(offset)
      expect(calls.count { |row| row['kind'] == 'execute-command' }).to eq(dispatch ? 1 : 0)
      expect(native('exists', path: path)).to be(false)
      expect(output).not_to match(/session \d+ opened/)
      expect(output).to include('Exploit aborted due to failure') unless dispatch
      preserved
    end
  end

  def negative_check
    ENV.fetch('MCPJAM_TARGET_VERSION') == '1.5.0' ? 'safe' : 'unknown'
  end

  def rpc(expression)
    code = "puts 'MCPJAM_JSON='+(#{expression}).to_json"
    output = console_command("irb -e #{code.inspect}", timeout: 45)
    captured = output[/^MCPJAM_JSON=(.+)\r?$/, 1]
    expect(captured).not_to be_nil, output
    JSON.parse(captured)
  end

  def session_rows
    workspace = 'mcpjam_' + @case
    raise ArgumentError, 'Invalid controlled workspace' unless workspace.match?(/\Amcpjam_[0-9_]+\z/)

    query = "SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]') FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{workspace}'"
    JSON.parse(target_exec('reporting_db', 'psql', '-X', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query))
  end

  def session_proof(payload, options = {})
    2.times do |iteration|
      path = "/tmp/module-target-mcpjam-session-#{@case}-#{iteration}"
      marker = "mcpjam-session-#{@case}-#{iteration}"
      @owned_files << path
      identifier = nil
      settings = { 'PAYLOAD' => payload, 'DisablePayloadHandler' => false, 'FETCH_OUTPUT' => false, 'LHOST' => listener_host, 'LPORT' => 4495, 'WfsDelay' => 12 }.merge(options)
      expect(@native_metadata.fetch('executables').fetch('node')).not_to be_nil if payload == 'cmd/unix/reverse_nodejs'
      if payload.start_with?('cmd/linux/http/')
        expect(@native_metadata.fetch('executables').fetch('wget')).not_to be_nil
        settings.merge!('FETCH_COMMAND' => 'WGET', 'FETCH_SRVHOST' => listener_host, 'FETCH_SRVPORT' => 8081, 'FETCH_DELETE' => true, 'FETCH_WRITABLE_DIR' => '/tmp',
                        'FETCH_FILENAME' => "module-target-mcpjam-fetch-#{@case}-#{iteration}", 'FETCH_URIPATH' => "module-target-mcpjam-fetch-#{@case}-#{iteration}")
      end
      begin
        output = invoke(settings, action: 'run -z', reuse: iteration.positive?)
        identifier = output[/(?:Command shell|Meterpreter) session (\d+) opened/, 1]
        expect(identifier).not_to be_nil, output
        identifier = Integer(identifier, 10)
        wait_for_expect(60, 0.2) do
          events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
          expect(events.map { |row| row.fetch('id') }).to include(identifier)
        end
        proof = rpc("MCPJamSessionControl.proof(framework,#{identifier},#{path.inspect},#{marker.inspect})")
        expect(proof).not_to have_key('error')
        expect(proof).to include('via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'session_host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
        observed = native('read', path: path)
        expect(observed).to include('base64' => Base64.strict_encode64(marker), 'uid' => 1000)
        live = process_identities
        process = live.find { |row| row.fetch('pid') == proof.fetch('pid') }
        expect(process).to include('uid' => 1000)
        expect(@baseline_processes.map { |row| row.fetch('pid') }).not_to include(proof.fetch('pid'))
        chain = []
        while process && @baseline_processes.none? { |row| row.fetch('pid') == process.fetch('pid') }
          chain << process
          process = live.find { |row| row.fetch('pid') == process.fetch('ppid') }
        end
        expect(session_rows).to include(include('id' => proof.fetch('db_id'), 'via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
        record('mcpjam-session-lifecycle.jsonl', phase: 'used', payload: payload, proof: proof, target_ancestry: chain)
        expect(rpc("MCPJamSessionControl.shutdown(framework,#{identifier})")).to include('graceful_remote_exit_requested' => true)
        wait_for_expect(40, 0.2) { expect(process_identities.map { |row| row.fetch('pid') }).not_to include(proof.fetch('pid')) }
        record('mcpjam-session-lifecycle.jsonl', phase: 'remote-exit', id: identifier, payload: payload, remote_session_pid_gone: true)
        # The Node payload's transport stays alive until its Framework peer closes.
        rpc("framework.sessions[#{identifier}]&.shell_close;true") if proof.fetch('type') == 'shell'
        rpc("framework.sessions[#{identifier}]&.kill;true")
        wait_for_expect(75, 0.2) do
          current = process_identities
          expect(current.select { |row| chain.any? { |old| old.values_at('pid', 'start') == row.values_at('pid', 'start') } }).to eq([])
        end
        preserved
        expect(session_rows).to all(include('closed_at' => be_a(String)))
        if settings['FETCH_FILENAME']
          fetch_path = '/tmp/' + settings.fetch('FETCH_FILENAME')
          wait_for_expect(40, 0.2) { expect(native('exists', path: fetch_path)).to be(false) }
        end
        expect(output).not_to include('Exploit aborted', 'Exploit failed')
        record('mcpjam-session-lifecycle.jsonl', phase: 'closed', id: identifier, payload: payload, target_pids_gone: true, database_rows: session_rows)
      ensure
        rpc("framework.sessions[#{identifier}]&.kill;true") if identifier
        console_command('jobs -K')
      end
    end
  end

  def native_after
    current = registry
    if current.any? { |row| row.fetch('id') == @foreign_id }
      api('/api/mcp/servers/' + URI.encode_www_form_component(@foreign_id), nil, method: 'DELETE')
    end
    expect(registry).to eq([])
    [@native_fixture.fetch(:path), @native_fixture.fetch(:path) + '.events'].each do |path|
      native('unlink', path: path) if native('exists', path: path)
    end
    %w[target framework reporting_db].each do |service|
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end
end
