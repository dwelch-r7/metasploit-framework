# frozen_string_literal: true

require_relative '../docker_daemon/acceptance'

# Compare real owner image pulls with independent native registry operations.
module DockerDaemonRegistryAcceptance
  def native_pull(reference)
    result = native_http('http://127.0.0.1:2375', path: '/images/create?fromImage=' + reference, method: 'POST', timeout: 25).merge(reference: reference)
    record('docker-daemon-native-registry.jsonl', result)
    result
  end

  def image_tags
    inner('image', 'ls', '--format', '{{.Repository}}:{{.Tag}}').lines.map(&:strip)
  end

  def prepare_registry_pull(reference)
    original = JSON.parse(inner('image', 'inspect', 'module-target-native:base')).fetch(0)
    inner('tag', 'module-target-native:base', reference)
    inner('push', reference)
    inner('image', 'rm', reference)
    expect(image_tags).not_to include(reference)
    control = native_pull(reference)
    expect(control.fetch(:status)).to eq(200)
    stream = Base64.strict_decode64(control.fetch(:body_base64)).lines.map { |line| JSON.parse(line) }
    expect(stream).not_to be_empty
    expect(stream).to all(satisfy { |row| !row.key?('error') && !row.key?('errorDetail') })
    expect(JSON.parse(inner('image', 'inspect', reference)).fetch(0).fetch('Id')).to eq(original.fetch('Id'))
    inner('image', 'rm', reference)
    expect(image_tags).not_to include(reference)
    record('docker-daemon-native-registry.jsonl', phase: 'before-owner', reference: reference, original_image_id: original.fetch('Id'), exact_tag_absent: true, tags: image_tags)
    original.fetch('Id')
  end

  def registry_sessions(payload, target:, prefix_collision: false)
    reference = "127.0.0.1:5000/module-target-native/owner-#{@case}:#{prefix_collision ? '3.2' : 'base'}"
    expected = prepare_registry_pull(reference)
    if prefix_collision
      shadow = reference + '0'
      inner('tag', 'module-target-native:base', shadow)
      expect(image_tags).to include(shadow)
      expect(image_tags).not_to include(reference)
      body = target_exec('target', 'curl', '--silent', '--show-error', '--max-time', '10', 'http://127.0.0.1:2375/images/json')
      expect(body).to include(reference)
      expect(JSON.parse(body).flat_map { |image| image.fetch('RepoTags', []) }).not_to include(reference)
      record('docker-daemon-native-registry.jsonl', phase: 'before-owner-prefix-collision', reference: reference, shadow_tag: shadow, exact_tag_absent: true, native_listing_base64: Base64.strict_encode64(body.b))
    end
    offset = owner_rows.length
    session_proof(payload, target: target, options: { 'DOCKERIMAGE' => reference })
    observed = owner_rows.drop(offset)
    pulls = observed.select { |row| row['kind'] == 'http' && row['method'] == 'POST' && row['uri'] == '/images/create?fromImage=' + reference }
    expect(pulls.length).to eq(1), 'First execution must pull; second must use the exact cached image'
    expect(pulls.fetch(0).fetch('status')).to eq(200)
    stream = Base64.strict_decode64(pulls.fetch(0).fetch('response_base64')).lines.map { |line| JSON.parse(line) }
    expect(stream).not_to be_empty
    expect(stream).to all(satisfy { |row| !row.key?('error') && !row.key?('errorDetail') })
    expect(JSON.parse(inner('image', 'inspect', reference)).fetch(0).fetch('Id')).to eq(expected)
    record('docker-daemon-owner-registry.jsonl', reference: reference, pull_count: pulls.length, restored_native_image_id: expected, session_executions: 2, native_stream: stream)
    inner('image', 'rm', reference)
    inner('image', 'rm', shadow) if prefix_collision
  end

  def missing_registry_image
    reference = "127.0.0.1:5000/module-target-native/missing-#{@case}:absent"
    control = native_pull(reference)
    expect(control.fetch(:status)).to eq(404)
    expect(image_tags).not_to include(reference)
    offset = owner_rows.length
    settings = { 'DOCKERIMAGE' => reference, 'TARGET' => 0, 'PAYLOAD' => 'linux/x64/shell_reverse_tcp', 'LHOST' => listener_host, 'LPORT' => 4497, 'DisablePayloadHandler' => false, 'WfsDelay' => 0, 'HttpClientTimeout' => 10 }
    output = run_target_module(DockerDaemonAcceptance::OWNER, 'target', settings, action: 'run -z', allow_errors: true, command_timeout: 45)
    observed = owner_rows.drop(offset)
    record('docker-daemon-invocations.jsonl', action: 'run -z', settings: settings, output: output, rows: observed)
    expect(output).to include('Failed to pull the docker image')
    expect(observed.select { |row| row['kind'] == 'check-return' }).to contain_exactly(include('code' => 'appears'))
    expect(observed.select { |row| row['kind'] == 'http' && row['method'] == 'POST' }).to contain_exactly(include('uri' => '/images/create?fromImage=' + reference, 'status' => 404))
    expect(session_rows).to eq([])
    expect(rpc('{jobs:framework.jobs.keys,sessions:framework.sessions.keys}')).to eq('jobs' => [], 'sessions' => [])
    expect(host_file_names).to match_array(@before_files)
    expect(image_tags).not_to include(reference)
  end
end
