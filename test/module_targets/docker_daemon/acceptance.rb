# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/module_target_endpoint'

# Independent native daemon/gateway controls and observations of the real owner.
module DockerDaemonAcceptance
  OWNER = 'exploit/linux/http/docker_daemon_tcp'

  def record(name, row)
    File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(row)) }
  end

  def select_endpoint
    compose = target_runtime.fetch('compose')
    inspect_object = lambda do |kind, identifier|
      output, error, status = Open3.capture3('docker', kind, 'inspect', identifier)
      expect(status.exitstatus).to eq(0), error
      record('docker-daemon-endpoint.jsonl', kind: kind, identifier: identifier, output: output)
      JSON.parse(output).fetch(0)
    end
    selector = ModuleTargetEndpoint.new(project: compose.fetch(compose.index('--project-name') + 1), network: 'default', container: lambda { |service|
      output, error, status = Open3.capture3(*compose, 'ps', '-q', service)
      expect(status.exitstatus).to eq(0), error
      inspect_object.call('container', output.strip)
    }, network_inspection: ->(identifier) { inspect_object.call('network', identifier) })
    target_runtime.fetch('module_endpoints')['target'] = { 'host' => selector.address('target'), 'port' => 2375 }
  end

  def native_http(origin, credentials = nil, path: '/version', method: nil, data: nil, timeout: 10)
    args = ['curl', '--silent', '--show-error', '--max-time', timeout.to_s, '--cacert', '/etc/nginx/module-target.crt', '--write-out', '\n%{http_code}'] # rubocop:disable Style/FormatStringToken
    args += ['--user', credentials] if credentials
    args += ['--request', method] if method
    args += ['--header', 'Content-Type: application/json', '--data-binary', JSON.generate(data)] if data
    output = target_exec('target', *args, origin + path)
    body, _separator, status = output.rpartition("\n")
    result = { origin: origin, credentials: credentials, path: path, method: method || 'GET', request_data: data, status: Integer(status, 10), body_base64: Base64.strict_encode64(body.b) }
    record('docker-daemon-native-http.jsonl', result)
    result
  end

  def native_before
    cli = JSON.parse(target_exec('target', 'env', 'DOCKER_CONTEXT=default', 'BUILDX_BUILDER=default', 'docker', '--host', 'unix:///var/run/docker.sock', 'version', '--format', '{{json .Server}}'))
    expect(cli.fetch('Version')).to eq(ENV.fetch('MODULE_TARGET_DOCKER_VERSION', '26.1.4'))
    direct = native_http('http://127.0.0.1:2375')
    expect(direct.fetch(:status)).to eq(200)
    document = JSON.parse(Base64.strict_decode64(direct.fetch(:body_base64)))
    expect(document.fetch('Version')).to eq(cli.fetch('Version'))
    [['http://127.0.0.1:8080', nil], ['http://127.0.0.1:8081', 'module-target-user:module-target-password'], ['https://localhost:8443', 'module-target-user:module-target-password']].each do |origin, credentials|
      result = native_http(origin, credentials)
      expect(result.fetch(:status)).to eq(200)
      expect(JSON.parse(Base64.strict_decode64(result.fetch(:body_base64)))).to eq(document)
    end
    %w[http://127.0.0.1:8081 https://localhost:8443].each do |origin|
      expect(native_http(origin).fetch(:status)).to eq(401)
      expect(native_http(origin, 'module-target-user:wrong-password').fetch(:status)).to eq(401)
    end
    seed_image
    @baseline_core = core_processes
    preserved
  end

  def start_console
    expect(console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)).not_to match(/\[-\]|Error|Exception/)
    code = 'load "test/module_targets/docker_daemon/input_audit.rb";puts "DOCKER_DAEMON_AUDIT="+DockerDaemonTargetInputs.install(framework)'
    expect(console_command("irb -e #{code.inspect}")).to include('DOCKER_DAEMON_AUDIT=' + OWNER)
    code = 'load "test/module_targets/docker_daemon/session_control.rb";puts "DOCKER_SESSION_CONTROL="+DockerDaemonSessionControl.install(framework).to_json'
    expect(console_command("irb -e #{code.inspect}")).to include('DOCKER_SESSION_CONTROL={"installed":true,')
  end

  def owner_rows
    path = File.join(target_runtime.fetch('artifacts'), 'docker-daemon-owner-calls.jsonl')
    File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
  end

  def check_twice(settings = {}, expected: 'appears')
    2.times do |iteration|
      offset = owner_rows.length
      options = { 'SSL' => false, 'HttpClientTimeout' => 5, 'VERBOSE' => true }.merge(settings)
      output = run_target_module(OWNER, 'target', options, action: 'check', allow_errors: true, command_timeout: 45)
      observed = owner_rows.drop(offset)
      record('docker-daemon-invocations.jsonl', action: 'check', settings: options, iteration: iteration, output: output, rows: observed)
      expect(observed.select { |row| row['kind'] == 'check-raise' }).to eq([])
      expect(observed.select { |row| row['kind'] == 'check-return' }).to contain_exactly(include('code' => expected, 'reason' => be_a(String)))
      preserved
    end
  end

  def preserved
    expect(target_exec('target', 'env', 'DOCKER_CONTEXT=default', 'BUILDX_BUILDER=default', 'docker', '--host', 'unix:///var/run/docker.sock', 'ps', '--all', '--quiet').strip).to eq('')
  end

  def rpc(expression)
    code = "puts 'DOCKER_DAEMON_JSON='+(#{expression}).to_json"
    output = console_command("irb -e #{code.inspect}", timeout: 45)
    captured = output[/^DOCKER_DAEMON_JSON=(.+)\r?$/, 1]
    expect(captured).not_to be_nil, output
    JSON.parse(captured)
  end

  def inner(*)
    target_exec('target', 'env', 'DOCKER_CONTEXT=default', 'BUILDX_BUILDER=default', 'docker', '--host', 'unix:///var/run/docker.sock', *)
  end

  def seed_image
    inner('import', '/opt/module-target-seed.tar', 'module-target-native:base')
    document = JSON.parse(inner('image', 'inspect', 'module-target-native:base')).fetch(0)
    expect(document).to include('Architecture' => 'amd64', 'Os' => 'linux')
    record('docker-daemon-native-image.jsonl', document)
  end

  def process_identity(identifier)
    script = %q{import json,pathlib,sys
prefix=pathlib.Path('/proc')/sys.argv[1]
try:
 text=(prefix/'stat').read_text();fields=text[text.rindex(') ')+2:].split();uid=int(next(line.split()[1] for line in (prefix/'status').read_text().splitlines() if line.startswith('Uid:')));print(json.dumps({'pid':int(sys.argv[1]),'ppid':int(fields[1]),'start':fields[19],'uid':uid}))
except (FileNotFoundError,ProcessLookupError):print('null')}
    JSON.parse(target_exec('target', 'python3', '-c', script, identifier.to_s))
  end

  def session_rows
    workspace = 'dockerdaemon_' + @case
    raise ArgumentError, 'Invalid controlled workspace' unless workspace.match?(/\Adockerdaemon_[0-9_]+\z/)

    query = "SELECT coalesce(json_agg(row_to_json(session) ORDER BY session.id),'[]') FROM sessions session JOIN hosts host ON host.id=session.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{workspace}'"
    JSON.parse(target_exec('reporting_db', 'psql', '-X', '-U', 'module_framework', '-d', 'module_targets', '-Atc', query))
  end

  def session_proof(payload, target:, options: {})
    2.times do |iteration|
      marker_path = "/tmp/module-target-docker-session-#{@case}-#{iteration}"
      marker = "docker-session-#{@case}-#{iteration}"
      @owned_markers << marker_path
      identifier = nil
      settings = {
        'PAYLOAD' => payload, 'TARGET' => target, 'DOCKERIMAGE' => 'module-target-native:base',
        'LHOST' => listener_host, 'LPORT' => 4497, 'WfsDelay' => 75,
        'DisablePayloadHandler' => false, 'HttpClientTimeout' => 10,
        'VERBOSE' => true, 'HttpTrace' => true, 'HttpTraceHeadersOnly' => true
      }.merge(options)
      offset = owner_rows.length
      begin
        output = run_target_module(OWNER, 'target', settings, action: 'run -z', allow_errors: true, command_timeout: 120)
        observed = owner_rows.drop(offset)
        record('docker-daemon-invocations.jsonl', action: 'run -z', iteration: iteration, settings: settings, output: output, rows: observed)
        expect(output).not_to include('Exploit failed', 'Exploit aborted due to failure')
        captured = output[/(?:Meterpreter|Command shell) session (\d+) opened/, 1]
        expect(captured).not_to be_nil, output
        identifier = Integer(captured, 10)
        wait_for_expect(45, 0.2) do
          events = File.readlines(File.join(target_runtime.fetch('artifacts'), 'ready-sessions.jsonl')).map { |line| JSON.parse(line) }
          expect(events.map { |row| row.fetch('id') }).to include(identifier)
        end
        proof = rpc("DockerDaemonSessionControl.proof(framework,#{identifier},#{marker_path.inspect},#{marker.inspect})")
        expect(proof).not_to have_key('error')
        expect(proof).to include('via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'session_host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
        expect(target_exec('target', 'cat', marker_path).b).to eq(marker.b)
        expect(target_exec('target', 'stat', '-c', '%u', marker_path).strip).to eq('0')
        original = process_identity(proof.fetch('pid'))
        expect(original).to include('uid' => 0)
        expect(session_rows).to include(include('id' => proof.fetch('db_id'), 'via_exploit' => OWNER, 'via_payload' => 'payload/' + payload, 'closed_at' => nil))
        record('docker-daemon-session-lifecycle.jsonl', phase: 'used', payload: payload, proof: proof, native_process: original)
        expect(rpc("DockerDaemonSessionControl.shutdown(framework,#{identifier})")).to include('graceful_remote_exit_requested' => true)
        wait_for_expect(45, 0.2) do
          current = process_identity(proof.fetch('pid'))
          expect(current.nil? || current.fetch('start') != original.fetch('start')).to be(true)
        end
        record('docker-daemon-session-lifecycle.jsonl', phase: 'remote-exit', id: identifier, target_pid_gone: true)
        rpc("framework.sessions[#{identifier}]&.shell_close;true") if proof.fetch('type') == 'shell'
        rpc("framework.sessions[#{identifier}]&.kill;true")
        wait_for_expect(45, 0.2) { expect(session_rows).to all(include('closed_at' => be_a(String))) }
        expect(inner('ps', '--all', '--quiet').strip).to eq('')
        idle = rpc('{jobs:framework.jobs.keys,sessions:framework.sessions.keys}')
        expect(idle).to eq('jobs' => [], 'sessions' => [])
        record('docker-daemon-session-lifecycle.jsonl', phase: 'closed', id: identifier, database_rows: session_rows)
        verify_source_cleanup(source_owned_effects(offset, @before_files))
        expect(core_processes).to eq(@baseline_core)
      ensure
        rpc("framework.sessions[#{identifier}]&.kill;true") if identifier
        console_command('jobs -K')
      end
    end
  end

  # Capture the state before dispatch; never infer ownership from a random-looking name.
  def host_file_names
    script = %q{import json,os
print(json.dumps([directory+'/'+name for directory in ['/tmp','/etc/cron.d'] for name in os.listdir(directory)]))}
    JSON.parse(target_exec('target', 'python3', '-c', script))
  end

  def source_owned_effects(offset, before_files)
    owner_rows.drop(offset).filter_map do |row|
      next unless row['kind'] == 'http' && row['method'] == 'POST' && row['uri'].start_with?('/containers/create?') && row['status'] == 201

      request = JSON.parse(Base64.strict_decode64(row.fetch('data_base64')))
      response = JSON.parse(Base64.strict_decode64(row.fetch('response_base64')))
      identifier = response.fetch('Id')
      expect(identifier).to match(/\A[0-9a-f]{64}\z/)
      binds = request.fetch('HostConfig').fetch('Binds')
      expect(binds).to contain_exactly(match(%r{\A/:/mnt/[A-Za-z]{8}\z}))
      mount = binds.fetch(0).delete_prefix('/:')
      command = request.fetch('Cmd')
      expect(command).to be_a(String)
      paths = command.scan(%r{#{Regexp.escape(mount)}(/etc/cron\.d/[A-Za-z]{8}|/tmp/[A-Za-z]{8})}).flatten.uniq
      expect(paths).to contain_exactly(match(%r{\A/etc/cron\.d/[A-Za-z]{8}\z}), match(%r{\A/tmp/[A-Za-z]{8}\z}))
      expect(before_files & paths).to eq([]), 'A source-requested path existed before this dispatch; do not delete it'
      { 'container_id' => identifier, 'host_paths' => paths, 'image' => request.fetch('Image'), 'command_base64' => Base64.strict_encode64(command.b) }
    end
  end

  def native_file_state(paths)
    script = %q{import base64,json,os,pathlib,sys
result=[]
for path in json.loads(sys.argv[1]):
 entry=pathlib.Path(path)
 try:
  state=entry.stat();result.append({'path':path,'exists':True,'uid':state.st_uid,'mode':state.st_mode & 0o777,'bytes_base64':base64.b64encode(entry.read_bytes()).decode()})
 except FileNotFoundError:result.append({'path':path,'exists':False})
print(json.dumps(result))}
    JSON.parse(target_exec('target', 'python3', '-c', script, JSON.generate(paths)))
  end

  def verify_source_cleanup(effects)
    expect(effects).not_to be_empty
    states = native_file_state(effects.flat_map { |effect| effect.fetch('host_paths') })
    record('docker-daemon-owner-artifacts.jsonl', phase: 'before-test-cleanup', effects: effects, file_states: states, inner_containers: inner('ps', '--all', '--quiet'))
    expect(states).to all(include('exists' => false))
    expect(inner('ps', '--all', '--quiet').strip).to eq('')
  end

  # Invoke only after preserving failure state. Effects must come from successful
  # native source responses and have passed the pre-dispatch collision check.
  def cleanup_proven_effects(effects)
    record('docker-daemon-owner-artifacts.jsonl', phase: 'test-failure-cleanup', effects: effects, file_states: native_file_state(effects.flat_map { |effect| effect.fetch('host_paths') }))
    effects.each do |effect|
      effect.fetch('host_paths').each { |path| target_exec('target', 'rm', '-f', '--', path) }
      remove_owned_container(effect.fetch('container_id'))
    end
  end

  def remove_owned_container(identifier)
    raise ArgumentError, 'Invalid recorded native container ID' unless identifier.match?(/\A[0-9a-f]{64}\z/)

    output = target_exec('target', 'curl', '--silent', '--show-error', '--max-time', '15', '--request', 'DELETE', '--write-out', '\n%{http_code}', "http://127.0.0.1:2375/containers/#{identifier}?force=true&v=true") # rubocop:disable Style/FormatStringToken
    _body, _separator, status = output.rpartition("\n")
    expect([204, 404]).to include(Integer(status, 10))
  end

  def core_processes
    script = %q{import json,pathlib,subprocess
identifiers={'dockerd':int(pathlib.Path('/var/run/docker.pid').read_text()),'nginx':int(pathlib.Path('/run/nginx.pid').read_text())}
for name in ['cron','registry']:identifiers[name]=int(subprocess.check_output(['pgrep','-x',name]).strip())
result={}
for name,pid in identifiers.items():
 text=pathlib.Path('/proc/'+str(pid)+'/stat').read_text();fields=text[text.rindex(') ')+2:].split();result[name]={'pid':pid,'start':fields[19]}
print(json.dumps(result))}
    JSON.parse(target_exec('target', 'python3', '-c', script))
  end

  def native_after
    %w[target framework reporting_db].each do |service|
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/memory.events')).to include("oom 0\n", "oom_kill 0\n")
      expect(target_exec(service, 'cat', '/sys/fs/cgroup/pids.events').strip).to eq('max 0')
    end
  end
end
