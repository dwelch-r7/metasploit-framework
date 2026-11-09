# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
documents = JSON.parse(File.read(File.join(__dir__, 'documents.json')))
requests = []
profiles = {}
endpoints = %w[open secured unrelated].to_h do |service|
  if runtime
    [service, runtime.fetch('endpoints').fetch(service)]
  else
    binding, status = Open3.capture2(*compose, 'port', service, service == 'unrelated' ? '80' : '9200')
    raise "Missing endpoint: #{service}" unless status.success?

    host, port = binding.strip.split(':')
    [service, { 'host' => host, 'port' => Integer(port) }]
  end
end
request = lambda do |service, method, path, body: nil, credentials: nil, expected: 200, ctype: 'application/json'|
  address = endpoints.fetch(service)
  http = Net::HTTP.new(address.fetch('host'), address.fetch('port'), nil)
  http.open_timeout = 5
  http.read_timeout = 10
  message = Net::HTTPGenericRequest.new(method, !body.nil?, true, path)
  message['Content-Type'] = ctype
  message.basic_auth(*credentials) if credentials
  message.body = body.is_a?(String) ? body : JSON.generate(body) if body
  response = http.request(message)
  text = response.body&.dup&.force_encoding(Encoding::UTF_8)
  requests << { service: service, method: method, path: path, credentials: credentials, body: body, code: response.code.to_i, headers: response.to_hash, response: text }
  raise "Native #{service} #{method} #{path}: expected #{expected}, got #{response.code}: #{text}" unless response.code.to_i == expected

  response['content-type']&.include?('json') ? JSON.parse(text) : text
end

begin
  %w[open secured].each do |service|
    credentials = service == 'secured' ? ['elastic', 'module-target-password'] : nil
    root = request.call(service, 'GET', '/', credentials: credentials)
    raise "Wrong native version: #{root}" unless root.dig('version', 'number') == '7.9.1'
    raise "Wrong native cluster: #{root}" unless root.fetch('cluster_name') == "module-target-#{service}"

    profiles[service] = { version: root }
    settings = { settings: { number_of_shards: 1, number_of_replicas: 0 } }
    %w[module_target_records module_target_empty].each do |index|
      request.call(service, 'PUT', "/#{index}", body: settings, credentials: credentials)
    end
    bulk = documents.each_with_index.map do |document, index|
      JSON.generate(index: { _index: 'module_target_records', _id: (index + 1).to_s }) + "\n" + JSON.generate(document) + "\n"
    end.join
    inserted = request.call(service, 'POST', '/_bulk?refresh=true', body: bulk, credentials: credentials, ctype: 'application/x-ndjson')
    raise "Native bulk insertion failed: #{inserted}" if inserted.fetch('errors')

    stored = request.call(service, 'GET', '/module_target_records/_search?size=100&sort=count:asc', credentials: credentials)
    raise 'Native stored documents differ' unless stored.fetch('hits').fetch('hits').map { |hit| hit.fetch('_source') } == documents

    empty = request.call(service, 'GET', '/module_target_empty/_count', credentials: credentials)
    raise 'Native empty index is populated' unless empty.fetch('count').zero?

    profiles.fetch(service)[:stored] = stored
    profiles.fetch(service)[:samples] = [1, 5, 10].to_h do |limit|
      sample = request.call(service, 'GET', "/module_target_records/_search?q=*&from=0&size=#{limit}", credentials: credentials)
      [limit.to_s, sample.fetch('hits').fetch('hits').map { |hit| hit.fetch('_source') }]
    end
    profiles.fetch(service)[:nodes] = request.call(service, 'GET', '/_cat/nodes?format=json&h=ip,port,version,http,name', credentials: credentials)
    profiles.fetch(service)[:cluster] = request.call(service, 'GET', '/_cluster/health', credentials: credentials)
    profiles.fetch(service)[:indices] = request.call(service, 'GET', '/_cat/indices?format=json', credentials: credentials)
    zero = request.call(service, 'POST', '/module_target_records/_search', credentials: credentials, body: { size: 0 })
    raise 'Native zero-row query returned document data' unless zero.fetch('hits').fetch('hits').empty?

    profiles.fetch(service)[:zero] = zero
  end
  admin = ['elastic', 'module-target-password']
  request.call('secured', 'POST', '/_security/role/module_target_reader', credentials: admin, body: {
    cluster: ['monitor'], indices: [{ names: ['module_target_*'], privileges: %w[read view_index_metadata monitor] }]
  })
  request.call('secured', 'POST', '/_security/user/module_target_reader', credentials: admin, body: {
    password: 'module-target-reader-password', roles: ['module_target_reader'], email: 'module-target-reader@example.test', metadata: { purpose: 'module-target-native-control' }
  })
  request.call('secured', 'POST', '/_security/user/module_target_denied', credentials: admin, body: {
    password: 'module-target-denied-password', roles: []
  })
  profiles.fetch('secured')[:users] = request.call('secured', 'GET', '/_security/user', credentials: admin)
  %w[anonymous wrong blank missing].each do |mode|
    credentials = { 'anonymous' => nil, 'wrong' => ['elastic', 'wrong-password'], 'blank' => ['elastic', ''], 'missing' => ['missing-user', 'module-target-password'] }.fetch(mode)
    request.call('secured', 'GET', '/', credentials: credentials, expected: 401)
  end
  reader = ['module_target_reader', 'module-target-reader-password']
  profiles.fetch('secured')[:reader] = request.call('secured', 'GET', '/module_target_records/_count', credentials: reader)
  profiles.fetch('secured')[:reader_nodes] = request.call('secured', 'GET', '/_cat/nodes?format=json&h=ip,port,version,http,name', credentials: reader)
  profiles.fetch('secured')[:reader_indices] = request.call('secured', 'GET', '/_cat/indices?format=json', credentials: reader)
  unless profiles.fetch('secured').fetch(:reader_indices).map { |index| index.fetch('index') }.sort == %w[module_target_empty module_target_records]
    raise 'Native scoped index enumeration differs'
  end

  request.call('secured', 'GET', '/_security/user', credentials: reader, expected: 403)
  request.call('secured', 'GET', '/_cat/nodes?format=json', credentials: ['module_target_denied', 'module-target-denied-password'], expected: 403)
  request.call('secured', 'GET', '/', credentials: ['module_target_denied', 'module-target-denied-password'], expected: 403)
  unrelated = request.call('unrelated', 'GET', '/')
  raise 'Unrelated native HTTP differs' unless unrelated.include?('Module target')
ensure
  puts JSON.pretty_generate(profiles: profiles, requests: requests)
end
