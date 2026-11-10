# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'
require 'uri'
require 'yaml'
require 'timeout'

# Independent controls use official promtool, PromQL and actual kernel files.
class PrometheusTarget
  USERNAME = 'metrics-user'
  PASSWORD = 'public-metrics-password'
  ESCAPED_MOUNT = '/data/metrics,"quote"'
  PREFIXES = { 'old' => '/', 'modern' => '/prom/', 'secured' => '/', 'empty' => '/' }.freeze

  # @return [Array<Hash>] complete native command and HTTP records
  attr_reader :records

  # @param runtime [Hash] task-owned Compose command and loopback endpoints
  def initialize(runtime)
    @runtime = runtime
    @records = []
  end

  # @return [Hash] independently validated native API and exporter information
  def prepare
    api_profiles = PREFIXES.to_h do |service, prefix|
      command(service, '/bin/promtool', 'check', 'config', "/etc/prometheus/fixtures/#{service == 'empty' ? 'empty' : 'prometheus'}.yml")
      basic = service == 'secured' ? [USERNAME, PASSWORD] : nil
      build = document(service, prefix + 'api/v1/status/buildinfo', basic: basic)
      config = document(service, prefix + 'api/v1/status/config', basic: basic)
      flags = document(service, prefix + 'api/v1/status/flags', basic: basic)
      targets = wait_targets(service, prefix, basic: basic)
      {
        'build' => build, 'config' => config, 'flags' => flags, 'targets' => targets,
        'parsed_config' => YAML.safe_load(config.fetch('data').fetch('yaml'))
      }.then { |profile| [service, profile] }
    end
    raise 'Unexpected API target versions' unless api_profiles.dig('old', 'build', 'data', 'version') == '2.39.1' && api_profiles.dig('modern', 'build', 'data', 'version') == '3.2.1'
    raise 'Native empty targets are not empty' unless api_profiles.dig('empty', 'targets', 'data', 'activeTargets').empty?

    requests = [
      ['secured', '/api/v1/status/buildinfo', nil, 401],
      ['secured', '/api/v1/status/buildinfo', [USERNAME, 'incorrect-password'], 401],
      ['node_auth', '/metrics', nil, 401],
      ['node_auth', '/metrics', [USERNAME, 'incorrect-password'], 401],
      ['discovery', '/protected/discovery.json', nil, 401],
      ['discovery', '/protected/discovery.json', ['module-test-user', 'incorrect-password'], 401],
      ['discovery', '/protected/discovery.json', ['module-test-user', 'module-test-password'], 200]
    ]
    requests.each { |service, path, basic, status| request(service, path, basic: basic, expected: status) }
    request('discovery', '/bearer/metrics', expected: 403)
    request('discovery', '/bearer/metrics', bearer: 'incorrect-token', expected: 403)
    request('discovery', '/bearer/metrics', bearer: 'public-prometheus-bearer-token')

    nodes = %w[node node_legacy node_auth node_empty].to_h do |service|
      basic = service == 'node_auth' ? [USERNAME, PASSWORD] : nil
      root = request(service, '/', basic: basic).body
      metrics = request(service, '/metrics', basic: basic).body
      lint = command('old', '/bin/promtool', 'check', 'metrics', input: metrics, expected: service == 'node_legacy' ? 3 : 0)
      if service == 'node_legacy' && lint != "http_request_duration_microseconds use base unit \"seconds\" instead of \"microseconds\"\n"
        raise 'Legacy metrics produced an unexpected native parser/lint diagnostic'
      end

      version = command(service, '/bin/node_exporter', '--version')
      hostname = command(service, '/bin/hostname').strip
      mounts = command(service, '/bin/cat', '/proc/self/mountinfo')
      source = command(service, '/bin/sh', '-c', 'uname -a; cat /etc/os-release 2>/dev/null || true; for p in /sys/class/net/*; do printf "%s " "$p"; cat "$p/address" "$p/broadcast" "$p/operstate"; done')
      job = { 'node' => 'node-modern', 'node_legacy' => 'node-legacy', 'node_auth' => 'static-basic' }[service]
      query = job ? metric_query(job) : []
      if %w[node node_legacy].include?(service)
        command(service, '/bin/test', '-d', ESCAPED_MOUNT)
        unless query.any? { |sample| sample.dig('metric', 'mountpoint') == ESCAPED_MOUNT }
          raise "Official Prometheus parser did not report the real escaped mount on #{service}"
        end
      end
      [service, { 'root' => root, 'metrics' => metrics, 'version' => version, 'hostname' => hostname, 'mountinfo' => mounts, 'native_files' => source, 'query' => query }]
    end
    command('old', '/bin/cat', '/etc/prometheus/fixtures/basic-password')
    command('old', '/bin/cat', '/etc/prometheus/fixtures/bearer-secret')
    { 'api' => api_profiles, 'nodes' => nodes, 'records' => records }
  end

  # @param service [String] actual Compose service
  # @param path [String] real HTTP request path
  # @param basic [Array<String>, nil] public fixture credentials
  # @param bearer [String, nil] public fixture token
  # @param expected [Integer] exact expected native status
  # @return [Net::HTTPResponse] actual response
  def request(service, path, basic: nil, bearer: nil, expected: 200)
    endpoint = @runtime.fetch('endpoints').fetch(service)
    message = Net::HTTP::Get.new(path)
    message.basic_auth(*basic) if basic
    message['Authorization'] = "Bearer #{bearer}" if bearer
    response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil, read_timeout: 20) { |http| http.request(message) }
    @records << { service: service, path: path, basic_username: basic&.first, bearer: !bearer.nil?, code: response.code.to_i, body: response.body, headers: response.to_hash }
    raise "Native #{service} #{path} returned #{response.code}, expected #{expected}: #{response.body}" unless response.code.to_i == expected

    response
  end

  # @param service [String] actual Compose service
  # @param path [String] real JSON API path
  # @param options [Hash] request controls
  # @return [Hash] native JSON document
  def document(service, path, **)
    JSON.parse(request(service, path, **).body)
  end

  # @param service [String] actual Compose service
  # @param arguments [Array<String>] package CLI and separate arguments
  # @param input [String, nil] actual standard input
  # @param expected [Integer] exact native exit status
  # @return [String] unmodified native output
  def command(service, *arguments, input: nil, expected: 0)
    stdout, stderr, status = Open3.capture3(*@runtime.fetch('compose'), 'exec', '-T', service, *arguments, stdin_data: input.to_s)
    @records << { service: service, argv: arguments, stdin: input, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
    raise "Native #{service} command failed: #{arguments.inspect}: #{stderr}" unless status.exitstatus == expected

    stdout + stderr
  end

  # Volatile scrape timings/health are retained in raw documents and verified
  # independently; identity/discovery fields must match exactly across reads.
  # @param document [Hash] actual targets response
  # @return [Hash] stable target identity projection
  def self.target_projection(document)
    data = document.fetch('data')
    data.transform_values do |value|
      next value unless value.is_a?(Array)

      value.map { |target| target.except('lastScrape', 'lastScrapeDuration', 'lastError', 'health') }.sort_by { |target| JSON.generate(target.sort.to_h) }
    end
  end

  private

  def wait_targets(service, prefix, basic:)
    result = nil
    Timeout.timeout(30) do
      delay = 0.1
      loop do
        result = document(service, prefix + 'api/v1/targets', basic: basic)
        targets = result.fetch('data').fetch('activeTargets')
        break if service == 'empty' || (targets.length == 7 && targets.all? { |target| target.fetch('health') == 'up' })

        sleep delay
        delay = [delay * 1.5, 0.5].min
      end
    end
    result
  end

  def metric_query(job)
    selector = "{job=\"#{job}\",__name__=~\"go_info|node_uname_info|node_os_info|node_network_info|node_filesystem_avail_bytes|node_filesystem_avail|node_time_zone_offset_seconds|node_selinux_enabled\"}"
    document('old', '/api/v1/query?' + URI.encode_www_form('query' => selector)).fetch('data').fetch('result')
  end
end
