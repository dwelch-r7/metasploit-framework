# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'
require_relative 'tree'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
commands = []
requests = []
profiles = {}
password = 'module-target-etcd-root-password'
values = { '/module-target/message' => "Native etcd proof\nsecond line", '/module-target/nested/unicode' => 'etcd café ✓', '/module-target/empty' => '' }
native = lambda do |service, *arguments|
  argv = runtime.fetch('compose') + ['exec', '-T', service, *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{commands.last.inspect}" unless status.success?

  stdout
end
request = lambda do |service, path, method: 'GET', form: nil, json: nil, auth: nil|
  endpoint = runtime.fetch('endpoints').fetch(service)
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 3
  http.read_timeout = 5
  message = Net::HTTPGenericRequest.new(method, !form.nil? || !json.nil?, true, path)
  message.set_form_data(form) if form
  if json
    message['Content-Type'] = 'application/json'
    message.body = JSON.generate(json)
  end
  message.basic_auth(*auth) if auth
  response = http.request(message)
  response.body.force_encoding(Encoding::UTF_8)
  raise 'Native text response is not valid UTF-8' unless response.body.valid_encoding?

  requests << { service: service, path: path, method: method, form: form, json: json, auth_user: auth&.first, code: response.code.to_i, headers: response.to_hash, body: response.body }
  response
end
expect_code = lambda do |response, *codes|
  raise "Native HTTP differs: #{requests.last.inspect}" unless codes.map(&:to_s).include?(response.code)

  response
end
flatten = lambda do |node|
  node.fetch('dir', false) ? node.fetch('nodes', []).flat_map { |child| flatten.call(child).to_a }.to_h : { node.fetch('key') => node.fetch('value') }
end

begin
  %w[old modern secured empty v2_disabled].each do |service|
    version = service == 'old' ? '3.4.35' : '3.5.18'
    cli = native.call(service, '/usr/local/bin/etcd', '--version')
    raise "Native version differs: #{service}" unless cli.include?("etcd Version: #{version}\n")

    native.call(service, '/usr/local/bin/etcdctl', '--endpoints=http://127.0.0.1:2379', 'endpoint', 'health')
    version_response = expect_code.call(request.call(service, '/version'), 200)
    version_document = JSON.parse(version_response.body)
    raise 'Version API differs from native CLI' unless version_document.fetch('etcdserver') == version

    profiles[service] = { version: version_document }
    if service == 'v2_disabled'
      expect_code.call(request.call(service, '/v2/keys/?recursive=true'), 404)
      expect_code.call(request.call(service, '/v3/kv/put', method: 'POST', json: { key: ['native-v3'].pack('m0'), value: ['independent v3 value'].pack('m0') }), 200)
      read = expect_code.call(request.call(service, '/v3/kv/range', method: 'POST', json: { key: ['native-v3'].pack('m0') }), 200)
      raise 'Actual v3 value differs' unless JSON.parse(read.body).fetch('kvs').first.fetch('value').unpack1('m0') == 'independent v3 value'

      next
    end
    unless service == 'empty'
      values.each do |key, value|
        expect_code.call(request.call(service, "/v2/keys#{key}", method: 'PUT', form: { 'value' => value }), 200, 201)
      end
    end
    if service == 'secured'
      expect_code.call(request.call(service, '/v2/auth/users/root', method: 'PUT', json: { user: 'root', password: password }), 200, 201)
      expect_code.call(request.call(service, '/v2/auth/enable', method: 'PUT'), 200)
      expect_code.call(request.call(service, '/v2/auth/roles/guest', method: 'PUT', auth: ['root', password], json: { role: 'guest', revoke: { kv: { read: ['/*'], write: ['/*'] } } }), 200)
      expect_code.call(request.call(service, '/v2/keys/?recursive=true'), 401)
      expect_code.call(request.call(service, '/v2/keys/?recursive=true', auth: ['root', 'incorrect-module-target-password']), 401)
    end
    auth = service == 'secured' ? ['root', password] : nil
    tree_response = expect_code.call(request.call(service, '/v2/keys/?recursive=true', auth: auth), 200)
    tree = JSON.parse(tree_response.body)
    raise 'Native recursive values differ' unless flatten.call(tree.fetch('node')) == (service == 'empty' ? {} : values)

    profiles.fetch(service)[:tree] = tree
  end
  version = expect_code.call(request.call('prefix', '/etcd/version'), 200)
  raise 'Native reverse proxy version differs' unless JSON.parse(version.body) == profiles.fetch('modern').fetch(:version)

  tree = expect_code.call(request.call('prefix', '/etcd/v2/keys/?recursive=true'), 200)
  raise 'Native reverse proxy data differs' unless EtcdTarget.canonical_document(JSON.parse(tree.body)) == EtcdTarget.canonical_document(profiles.fetch('modern').fetch(:tree))

  unrelated = expect_code.call(request.call('unrelated', '/version'), 200)
  raise 'Unrelated resource differs' unless JSON.parse(unrelated.body).fetch('name') == 'Module target unrelated inventory'

  unrelated_keys = expect_code.call(request.call('unrelated', '/v2/keys/?recursive=true'), 200)
  raise 'Unrelated inventory document differs' unless JSON.parse(unrelated_keys.body) == { 'action' => 'list', 'node' => { 'name' => 'Module target unrelated inventory' } }
ensure
  puts JSON.pretty_generate(profiles: profiles, requests: requests, commands: commands, username: 'root', password: password)
end
