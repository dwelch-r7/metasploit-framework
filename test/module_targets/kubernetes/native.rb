# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'open3'
require 'openssl'

# Native Kubernetes controls use the real kubectl binary and HTTPS API.
class KubernetesTarget
  IMAGE = 'python:3.11.11-alpine3.21@sha256:d5e2fc72296647869f5eeb09e7741088a1841195059de842b05b94cb9d3771bb'
  NAMESPACE = 'module-lab'
  EMPTY_NAMESPACE = 'module-empty'
  POD = 'fixture-pod'

  # @return [Array<Hash>] unmodified native operations, including failed controls
  attr_reader :commands

  # @param pods [Array<Hash>] actual Kubernetes pod documents
  # @return [Array<Array>] stable native names, UIDs and images
  def self.pod_projection(pods)
    pods.map { |pod| [pod.dig('metadata', 'name'), pod.dig('metadata', 'uid'), pod.dig('spec', 'containers').map { |container| container.fetch('image') }] }.sort
  end

  # @param secrets [Array<Hash>] actual Kubernetes secret documents
  # @return [Array<Array>] exact names, types and encoded data
  def self.secret_projection(secrets)
    secrets.map { |secret| [secret.dig('metadata', 'name'), secret.fetch('type'), secret.fetch('data', {})] }.sort_by(&:first)
  end

  # Native captures show rule entries returned in different orders.
  # @param status [Hash] actual SelfSubjectRulesReview status
  # @return [Hash] complete status with only the rule-entry ordering normalized
  def self.auth_projection(status)
    status.merge(%w[resourceRules nonResourceRules].to_h do |name|
      [name, status.fetch(name).sort_by { |rule| JSON.generate(rule.sort.to_h) }]
    end)
  end

  # @param items [Array<Hash>] independently read native secrets
  # @return [Hash] exact expected loot bytes by fixture type
  def self.secret_bytes(items)
    secrets = items.to_h { |secret| [secret.dig('metadata', 'name'), secret] }
    token = secrets.fetch('service-token').fetch('data').dup
    %w[token namespace].each { |key| token[key] = Base64.strict_decode64(token.fetch(key)) }
    {
      'ssh' => Base64.strict_decode64(secrets.fetch('ssh-auth').dig('data', 'ssh-privatekey')),
      'tls-key' => Base64.strict_decode64(secrets.fetch('tls-auth').dig('data', 'tls.key')),
      'tls-cert' => Base64.strict_decode64(secrets.fetch('tls-auth').dig('data', 'tls.crt')),
      'docker' => Base64.strict_decode64(secrets.fetch('docker-auth').dig('data', '.dockerconfigjson')),
      'service-token' => token
    }
  end

  # @param compose [Array<String>] task-owned Compose command
  # @param endpoint [Hash] loopback API endpoint
  def initialize(compose:, endpoint:)
    @compose = compose
    @endpoint = endpoint
    @commands = []
  end

  # @return [Hash] independent native responses, credentials and controls
  def prepare
    version = JSON.parse(kubectl('version', '-o', 'json')).fetch('serverVersion')
    raise 'Unexpected Kubernetes version' unless version.fetch('gitVersion') == 'v1.32.3+k3s1'

    kubectl('apply', '-f', '-', input: JSON.generate(apiVersion: 'v1', kind: 'List', items: resources))
    kubectl('wait', '--for=condition=Ready', "pod/#{POD}", '-n', NAMESPACE, '--timeout=90s')
    kubectl('wait', '--for=jsonpath={.data.token}', 'secret/service-token', '-n', NAMESPACE, '--timeout=30s')
    tokens = %w[viewer limited executor blocked].to_h do |name|
      [name, kubectl('create', 'token', name, '-n', NAMESPACE, '--duration=2h').strip]
    end
    controls = {
      version: api('/version', tokens.fetch('viewer')),
      namespaces: api('/api/v1/namespaces', tokens.fetch('viewer')),
      pods: api("/api/v1/namespaces/#{NAMESPACE}/pods", tokens.fetch('viewer')),
      secrets: api("/api/v1/namespaces/#{NAMESPACE}/secrets", tokens.fetch('viewer')),
      empty_pods: api("/api/v1/namespaces/#{EMPTY_NAMESPACE}/pods", tokens.fetch('viewer')),
      empty_secrets: api("/api/v1/namespaces/#{EMPTY_NAMESPACE}/secrets", tokens.fetch('viewer')),
      denied_namespaces: api('/api/v1/namespaces', tokens.fetch('limited'), expected: 403),
      denied_secrets: api("/api/v1/namespaces/#{NAMESPACE}/secrets", tokens.fetch('limited'), expected: 403),
      invalid_token: api("/api/v1/namespaces/#{NAMESPACE}/pods", 'invalid-module-target-token', expected: 401),
      missing_pod: api("/api/v1/namespaces/#{NAMESPACE}/pods/missing-pod", tokens.fetch('viewer'), expected: 404)
    }
    raise 'Native pod list is incorrect' unless controls.fetch(:pods).fetch('items').map { |pod| pod.dig('metadata', 'name') } == [POD]
    raise 'Native empty resources are not empty' unless %i[empty_pods empty_secrets].all? { |key| controls.fetch(key).fetch('items').empty? }

    identity = kubectl('exec', '-n', NAMESPACE, POD, '--', 'python3', '-c', 'import json,os,platform; print(json.dumps(dict(hostname=platform.node(),uid=os.getuid(),python=platform.python_version(),token=open("/run/secrets/kubernetes.io/serviceaccount/token").read(),namespace=open("/run/secrets/kubernetes.io/serviceaccount/namespace").read(),service_host=os.environ["KUBERNETES_SERVICE_HOST"],service_port=os.environ["KUBERNETES_SERVICE_PORT_HTTPS"])))')
    identity = JSON.parse(identity)
    raise 'Native pod identity is incorrect' unless identity.fetch('hostname') == POD && identity.fetch('uid').zero? && identity.fetch('namespace') == NAMESPACE

    internal_api = internal_api_control
    before = pod_files
    2.times do |iteration|
      proof = "/tmp/native-exec-#{iteration}"
      command = "printf native-#{iteration} > #{proof}; cat #{proof}; id -u; hostname; rm #{proof}"
      output = kubectl(*authenticated(tokens.fetch('executor')), 'exec', '-n', NAMESPACE, POD, '--', '/bin/sh', '-c', command)
      raise 'Native authenticated exec proof is incorrect' unless output == "native-#{iteration}0\n#{POD}\n"
      raise 'Native exec did not restore pod files' unless pod_files == before
    end
    denied = kubectl(*authenticated(tokens.fetch('blocked')), 'exec', '-n', NAMESPACE, POD, '--', '/bin/true', expected: 1)
    raise 'Native blocked exec was not forbidden' unless denied.include?('Forbidden')

    created = { apiVersion: 'v1', kind: 'Pod', metadata: { name: 'native-created', namespace: EMPTY_NAMESPACE }, spec: { containers: [{ name: 'app', image: IMAGE, command: ['/bin/sh', '-c', 'exec tail -f /dev/null'] }], terminationGracePeriodSeconds: 0 } }
    kubectl(*authenticated(tokens.fetch('executor')), 'create', '-f', '-', input: JSON.generate(created))
    kubectl('wait', '--for=condition=Ready', 'pod/native-created', '-n', EMPTY_NAMESPACE, '--timeout=40s')
    raise 'Native created pod identity is incorrect' unless kubectl(*authenticated(tokens.fetch('executor')), 'exec', '-n', EMPTY_NAMESPACE, 'native-created', '--', 'hostname').strip == 'native-created'

    kubectl(*authenticated(tokens.fetch('executor')), 'delete', 'pod/native-created', '-n', EMPTY_NAMESPACE, '--wait=true', '--timeout=30s')
    raise 'Native created pod cleanup failed' unless JSON.parse(kubectl('get', 'pods', '-n', EMPTY_NAMESPACE, '-o', 'json')).fetch('items').empty?

    auth = api('/apis/authorization.k8s.io/v1/selfsubjectrulesreviews', tokens.fetch('limited'), expected: 201, method: :post, body: { apiVersion: 'authorization.k8s.io/v1', kind: 'SelfSubjectRulesReview', spec: { namespace: NAMESPACE } })
    { version: version, tokens: tokens, controls: controls, identity: identity, internal_api: internal_api, auth: auth, pod_files: before, commands: @commands }
  end

  # @param arguments [Array<String>] kubectl arguments
  # @param input [String, nil] native standard input
  # @param expected [Integer] exact expected process status
  # @return [String] native standard output and error
  def kubectl(*arguments, input: nil, expected: 0)
    argv = @compose + ['exec', '-T', 'cluster', '/bin/kubectl', *arguments]
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    stdout, stderr, status = Open3.capture3(*argv, stdin_data: input.to_s)
    @commands << { argv: arguments, stdin: input, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus, elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started }
    raise "Native kubectl failed #{arguments.inspect}: #{status.exitstatus}: #{stderr}" unless status.exitstatus == expected

    stdout + stderr
  end

  # @return [Array<String>] exact files in the test writable directory
  def pod_files
    JSON.parse(kubectl('exec', '-n', NAMESPACE, POD, '--', 'python3', '-c', 'import json,pathlib; print(json.dumps(sorted(p.name for p in pathlib.Path("/tmp").iterdir())))'))
  end

  # @param path [String] Kubernetes API path
  # @param token [String] genuine task service-account token
  # @param expected [Integer] exact native HTTP status
  # @param method [Symbol] request method
  # @param body [Hash, nil] request document
  # @return [Hash] native JSON response
  def api(path, token, expected: 200, method: :get, body: nil)
    request = method == :post ? Net::HTTP::Post.new(path) : Net::HTTP::Get.new(path)
    request['Authorization'] = "Bearer #{token}"
    request['Content-Type'] = 'application/json'
    request.body = JSON.generate(body) if body
    response = Net::HTTP.start(@endpoint.fetch('host'), @endpoint.fetch('port'), nil, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE, read_timeout: 20) { |http| http.request(request) }
    @commands << { api: path, method: method, code: response.code.to_i, body: response.body }
    raise "Native API #{path} returned #{response.code}, expected #{expected}: #{response.body}" unless response.code.to_i == expected

    JSON.parse(response.body)
  end

  private

  def internal_api_control
    program = <<~'PYTHON'
      import json,os,pathlib,ssl,urllib.request
      base=pathlib.Path("/run/secrets/kubernetes.io/serviceaccount")
      namespace=(base/"namespace").read_text()
      url="https://"+os.environ["KUBERNETES_SERVICE_HOST"]+":"+os.environ["KUBERNETES_SERVICE_PORT_HTTPS"]+"/api/v1/namespaces/"+namespace+"/pods"
      request=urllib.request.Request(url,headers={"Authorization":"Bearer "+(base/"token").read_text()})
      with urllib.request.urlopen(request,context=ssl.create_default_context(cafile=str(base/"ca.crt")),timeout=10) as response:
          body=json.load(response)
          print(json.dumps(dict(url=url,status=response.status,namespace=namespace,pod_names=sorted(p["metadata"]["name"] for p in body["items"]),certificate_verified=True)))
    PYTHON
    result = JSON.parse(kubectl('exec', '-n', NAMESPACE, POD, '--', 'python3', '-c', program))
    unless result.fetch('status') == 200 && result.fetch('certificate_verified') && result.fetch('namespace') == NAMESPACE && result.fetch('pod_names') == [POD]
      raise 'Native projected-token and CA API request failed'
    end

    result
  end

  def authenticated(token)
    ['--kubeconfig=/dev/null', '--server=https://127.0.0.1:6443', '--insecure-skip-tls-verify=true', "--token=#{token}"]
  end

  def resources
    namespaces = [NAMESPACE, EMPTY_NAMESPACE].map { |name| { apiVersion: 'v1', kind: 'Namespace', metadata: { name: name } } }
    accounts = %w[viewer limited executor blocked].map { |name| { apiVersion: 'v1', kind: 'ServiceAccount', metadata: { name: name, namespace: NAMESPACE } } }
    reader = { apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRole', metadata: { name: 'module-reader' }, rules: [{ apiGroups: [''], resources: %w[namespaces pods secrets], verbs: %w[get list] }] }
    reader_binding = { apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'ClusterRoleBinding', metadata: { name: 'module-reader' }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'module-reader' }, subjects: [{ kind: 'ServiceAccount', name: 'viewer', namespace: NAMESPACE }] }
    roles = [
      role('limited', [{ apiGroups: [''], resources: ['pods'], verbs: %w[get list] }]),
      role('executor', [{ apiGroups: [''], resources: ['pods'], verbs: %w[get list create delete] }, { apiGroups: [''], resources: ['pods/exec'], verbs: %w[get create] }])
    ]
    bindings = %w[limited executor].map { |name| { apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'RoleBinding', metadata: { name: name, namespace: NAMESPACE }, roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'Role', name: name }, subjects: [{ kind: 'ServiceAccount', name: name, namespace: NAMESPACE }] } }
    pod = { apiVersion: 'v1', kind: 'Pod', metadata: { name: POD, namespace: NAMESPACE }, spec: { serviceAccountName: 'executor', containers: [{ name: 'app', image: IMAGE, command: ['/bin/sh', '-c', 'exec tail -f /dev/null'] }], terminationGracePeriodSeconds: 0 } }
    empty_role = roles.last.merge(metadata: { name: 'executor', namespace: EMPTY_NAMESPACE })
    empty_binding = bindings.last.merge(metadata: { name: 'executor', namespace: EMPTY_NAMESPACE })
    namespaces + accounts + [reader, reader_binding] + roles + bindings + [empty_role, empty_binding, pod] + secrets
  end

  def role(name, rules)
    { apiVersion: 'rbac.authorization.k8s.io/v1', kind: 'Role', metadata: { name: name, namespace: NAMESPACE }, rules: rules }
  end

  def secret(name, type, data)
    { apiVersion: 'v1', kind: 'Secret', metadata: { name: name, namespace: NAMESPACE }, type: type, data: data.transform_values { |value| Base64.strict_encode64(value) } }
  end

  def secrets
    ssh_key = OpenSSL::PKey::RSA.new(2048)
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.serial = 1
    certificate.version = 2
    certificate.subject = certificate.issuer = OpenSSL::X509::Name.parse('/CN=module-target.invalid')
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 86_400
    certificate.sign(key, OpenSSL::Digest.new('SHA256'))
    [
      secret('basic-auth', 'kubernetes.io/basic-auth', { 'username' => 'moduleuser', 'password' => 'public-module-password' }),
      secret('ssh-auth', 'kubernetes.io/ssh-auth', { 'ssh-privatekey' => ssh_key.to_pem }),
      secret('tls-auth', 'kubernetes.io/tls', { 'tls.crt' => certificate.to_pem, 'tls.key' => key.to_pem }),
      secret('docker-auth', 'kubernetes.io/dockerconfigjson', { '.dockerconfigjson' => JSON.generate(auths: { 'registry.invalid' => { auth: Base64.strict_encode64('moduleuser:public-module-password') } }) }),
      secret('empty-secret', 'Opaque', {}),
      { apiVersion: 'v1', kind: 'Secret', metadata: { name: 'service-token', namespace: NAMESPACE, annotations: { 'kubernetes.io/service-account.name' => 'executor' } }, type: 'kubernetes.io/service-account-token' }
    ]
  end
end
