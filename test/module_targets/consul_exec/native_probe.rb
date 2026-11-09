# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime.fetch('compose')
commands = []
requests = []
profiles = {}
token = '6ecebcac-a700-4b54-80ad-ad8d64ed7a4c'
wrong_token = 'e121cd92-841e-4aa8-bb73-0b5cb06d3c27'
native = lambda do |service, *arguments, expected: 0|
  argv = compose + ['exec', '-T', service, *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  accepted = expected == :nonzero ? !status.success? : status.exitstatus == expected
  raise "Native command result differs: #{argv.inspect}: #{stdout} #{stderr}" unless accepted

  stdout
end
request = lambda do |service, method, path, acl_token, body = nil|
  endpoint = runtime.fetch('endpoints').fetch(service)
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 3
  http.read_timeout = 5
  req = Net::HTTP.const_get(method).new(path)
  req['X-Consul-Token'] = acl_token if acl_token
  req['Content-Type'] = 'application/json' if body
  req.body = JSON.generate(body) if body
  res = http.request(req)
  requests << { service: service, method: method, path: path, token: acl_token, body: req.body, code: res.code.to_i, headers: res.to_hash, response_body: res.body }
  res
end

begin
  %w[open secured disabled].each do |service|
    acl = service == 'secured' ? token : nil
    version = native.call(service, 'consul', 'version')
    raise "Native version differs: #{service}" unless version.start_with?("Consul v1.20.6\n")

    # Health checks run the same binary, so pidof can include a transient CLI.
    processes = native.call(service, 'ps', '-o', 'pid,args')
    agents = processes.scan(%r{^\s*(\d+)\s+(?:\S*/)?consul\s+agent(?:\s|$)}).flatten
    raise "Native agent process is not unique: #{service}" unless agents.length == 1

    daemon_pid = Integer(agents.first)
    status = native.call(service, 'cat', "/proc/#{daemon_pid}/status")
    raise "Native daemon process differs: #{service}" unless status.match?(/^Name:\s+consul$/)

    uid = status[/^Uid:\s+(\d+)/, 1]
    raise "Native daemon UID missing: #{service}" unless uid

    self_res = request.call(service, 'Get', '/v1/agent/self', acl)
    raise "Native agent info unavailable: #{service}" unless self_res.code == '200'

    info = JSON.parse(self_res.body)
    debug = info.fetch('DebugConfig')
    enabled = service != 'disabled'
    raise "Native script-check policy differs: #{service}" unless debug.fetch('EnableRemoteScriptChecks') == enabled
    raise "Native rexec policy differs: #{service}" unless debug.fetch('DisableRemoteExec') == !enabled

    if service == 'secured'
      [nil, wrong_token].each do |attempt|
        raise 'Native agent accepted an unauthorised token' unless request.call(service, 'Get', '/v1/agent/self', attempt).code == '403'
      end
    end
    initial_services = JSON.parse(request.call(service, 'Get', '/v1/agent/services', acl).body)
    name = 'module-target-native-service'
    path = '/tmp/module-target-native-service-proof'
    native.call(service, 'test', '!', '-e', path)
    registered = request.call(service, 'Put', '/v1/agent/service/register', acl, {
      'ID' => name, 'Name' => name,
      'Check' => { 'Args' => ['/bin/touch', path], 'Interval' => '1s', 'Timeout' => '2s' }
    })
    if enabled
      raise 'Native script registration failed' unless registered.code == '200'

      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      loop do
        owner = native.call(service, 'sh', '-c', "if test -f #{path}; then stat -c %u #{path}; fi").strip
        break if owner == uid
        raise 'Native service did not execute the command' if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

        sleep 0.1
      end
      removed = request.call(service, 'Put', "/v1/agent/service/deregister/#{name}", acl)
      raise 'Native service removal failed' unless removed.code == '200'

      native.call(service, 'rm', path)
    else
      raise 'Native disabled script registration was accepted' if registered.code == '200'

      native.call(service, 'test', '!', '-e', path)
    end
    final_services = JSON.parse(request.call(service, 'Get', '/v1/agent/services', acl).body)
    raise 'Native service state was not restored' unless final_services == initial_services

    path = '/tmp/module-target-native-rexec-proof'
    native.call(service, 'test', '!', '-e', path)
    output = native.call(service, 'consul', 'exec', '-wait=1s', '-wait-repl=100ms', '/bin/touch', path)
    if enabled
      raise 'Native rexec command ownership differs' unless native.call(service, 'stat', '-c', '%u', path).strip == uid

      native.call(service, 'rm', path)
    else
      raise 'Native disabled rexec unexpectedly had an acknowledgement' unless output.strip == '0 / 0 node(s) completed / acknowledged'

      native.call(service, 'test', '!', '-e', path)
    end
    if service == 'secured'
      refused = request.call(service, 'Put', '/v1/agent/service/register', wrong_token, {
        'ID' => name, 'Name' => name,
        'Check' => { 'Args' => ['/bin/touch', path], 'Interval' => '1s', 'Timeout' => '2s' }
      })
      raise 'Native service registration accepted the wrong token' unless refused.code == '403'

      sessions_before = request.call(service, 'Get', '/v1/session/list', acl)
      refused_session = request.call(service, 'Put', '/v1/session/create', wrong_token, { 'Behavior' => 'delete', 'Name' => 'Remote Exec', 'TTL' => '15s' })
      sessions_after = request.call(service, 'Get', '/v1/session/list', acl)
      raise 'Native session creation accepted the wrong token' unless refused_session.code == '403'
      unless sessions_before.code == '200' && sessions_after.code == '200' && JSON.parse(sessions_before.body) == JSON.parse(sessions_after.body)
        raise 'Native denied session creation altered session state'
      end

      native.call(service, 'consul', 'exec', "-token=#{wrong_token}", '-wait=1s', '-wait-repl=100ms', '/bin/touch', path, expected: :nonzero)
      native.call(service, 'env', '-u', 'CONSUL_HTTP_TOKEN', 'consul', 'exec', '-wait=1s', '-wait-repl=100ms', '/bin/touch', path, expected: :nonzero)
      native.call(service, 'test', '!', '-e', path)
      raise 'Native rejected registration altered service state' unless JSON.parse(request.call(service, 'Get', '/v1/agent/services', acl).body) == initial_services
    end
    profiles[service] = { uid: uid, version: info.fetch('Config').fetch('Version'), debug: debug, rexec_output: output, initial_services: initial_services }
  end
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands, requests: requests)
end
