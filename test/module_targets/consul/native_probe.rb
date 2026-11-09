# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime.fetch('compose')
requests = []
commands = []
profiles = {}
management_token = '6ecebcac-a700-4b54-80ad-ad8d64ed7a4c'
wrong_token = 'e121cd92-841e-4aa8-bb73-0b5cb06d3c27'
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', service, *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{argv.inspect}: #{stdout} #{stderr}" unless status.success? && stderr.empty?

  stdout
end
request = lambda do |service, path, token = nil|
  endpoint = runtime.fetch('endpoints').fetch(service)
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 3
  http.read_timeout = 5
  req = Net::HTTP::Get.new(path)
  req['X-Consul-Token'] = token if token
  res = http.request(req)
  requests << { service: service, path: path, token: token, code: res.code.to_i, headers: res.to_hash, body: res.body }
  res
end

begin
  %w[open_old open_current acl_old acl_current].each do |service|
    version = service.end_with?('old') ? '1.20.6' : '2.0.4'
    cli = native.call(service, 'consul', 'version')
    raise "Native Consul version differs: #{service}" unless cli.start_with?("Consul v#{version}\n")

    leader = request.call(service, '/v1/status/leader')
    raise "Native Consul leader unavailable: #{service}" unless leader.code == '200' && JSON.parse(leader.body).match?(/:\d+\z/)

    self_res = request.call(service, '/v1/agent/self')
    expected = service.start_with?('acl') ? '403' : '200'
    raise "Native anonymous self policy differs: #{service}" unless self_res.code == expected

    if service.start_with?('acl')
      rejected = request.call(service, '/v1/agent/self', wrong_token)
      raise "Native wrong token accepted: #{service}" unless rejected.code == '403'

      self_res = request.call(service, '/v1/agent/self', management_token)
      raise "Native management token refused: #{service}" unless self_res.code == '200'
    end
    config = JSON.parse(self_res.body).fetch('Config')
    raise "Native agent identity differs: #{service}" unless config.fetch('Version') == version && config.fetch('Datacenter') == 'dc1' && !config.fetch('NodeName').empty?

    api = request.call(service, '/v1/agent/version')
    ui = request.call(service, '/ui/')
    raise "Native Consul UI unavailable: #{service}" unless ui.code == '200' && ui.body.include?('consul-ui/config/environment')

    profiles[service] = {
      version: version, config: config, version_status: api.code.to_i,
      version_body: api.body, ui_version: ui.body[/CONSUL_VERSION:\s*([\d.]+)/, 1]
    }
  end
  raise 'Native UI-only version differs' unless native.call('ui_only', 'consul', 'version').start_with?("Consul v1.20.6\n")

  blocked_config = JSON.parse(native.call('ui_only', 'cat', '/consul/config/local.json'))
  raise 'Native API deny configuration differs' unless blocked_config.fetch('http_config').fetch('block_endpoints') == %w[/v1/agent/self /v1/agent/version]

  %w[/v1/agent/self /v1/agent/version].each do |path|
    raise "Native API resource was not denied: #{path}" unless request.call('ui_only', path).code == '403'
  end
  ui = request.call('ui_only', '/ui/')
  raise 'Native public UI version differs' unless ui.code == '200' && ui.body.include?('consul-ui/config/environment') && ui.body[/CONSUL_VERSION:\s*([\d.]+)/, 1] == '1.20.6'

  profiles['ui_only'] = { version: '1.20.6', blocked_config: blocked_config }
  prefixed = request.call('prefix', '/consul/v1/agent/self')
  raise 'Native prefixed API differs' unless prefixed.code == '200' && JSON.parse(prefixed.body).fetch('Config').fetch('Version') == '2.0.4'

  %w[/ /v1/agent/self /v1/agent/version /ui/].each do |path|
    unrelated = request.call('unrelated', path)
    raise 'Unrelated HTTP contains Consul identity' if unrelated.body.match?(%r{CONSUL_VERSION:|consul-ui/config/environment})
    raise 'Unrelated native HTTP differs' if path == '/' && !(unrelated.code == '200' && unrelated.body.include?('Module target'))
  end
ensure
  puts JSON.pretty_generate(profiles: profiles, requests: requests, commands: commands, management_token: management_token, wrong_token: wrong_token)
end
