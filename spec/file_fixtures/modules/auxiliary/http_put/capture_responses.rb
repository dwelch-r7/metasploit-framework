# frozen_string_literal: true

# Run only against the managed Apache WebDAV fixture's published loopback port.
# HTTP semantics: https://www.rfc-editor.org/rfc/rfc9110.html#name-put
require 'json'
require 'net/http'
require 'time'

host, port, output = ARGV
raise ArgumentError, 'Use HOST PORT OUTPUT_JSON for the owned WebDAV lab' unless host && port && output

client = Net::HTTP.new(host, Integer(port, 10), nil)
client.open_timeout = 3
client.read_timeout = 5
client.max_retries = 0
requests = []
request = lambda do |method, path, body = nil|
  message = Net::HTTPGenericRequest.new(method, !body.nil?, true, path)
  message.body = body if body
  response = client.request(message)
  result = { method: method, path: path, status: response.code.to_i, headers: response.to_hash, body: response.body.to_s }
  requests << result
  result
end

responses = {}
{
  literal: 'module-target [literal] (a+b).*',
  multiline: "Module target first line\nSecond line with \"quotes\" and a \\ backslash\n"
}.each do |name, body|
  path = "/dav/module-target-native-unit-capture-#{name}.txt"
  raise "Capture file exists: #{path}" unless request.call('GET', path).fetch(:status) == 404

  begin
    uploaded = request.call('PUT', path, body)
    raise uploaded.inspect unless uploaded.fetch(:status) == 201

    responses[:put_created] ||= uploaded
    found = request.call('GET', path)
    raise found.inspect unless found.values_at(:status, :body) == [200, body]

    responses["#{name}_get"] = found
    deleted = request.call('DELETE', path)
    raise deleted.inspect unless deleted.fetch(:status) == 204

    responses[:delete_success] ||= deleted
    absent = request.call('GET', path)
    raise absent.inspect unless absent.fetch(:status) == 404

    responses[:missing_get] ||= absent
  ensure
    request.call('DELETE', path)
  end
end
responses[:unauthorized_get] = request.call('GET', '/auth/existing.txt')
raise responses[:unauthorized_get].inspect unless responses[:unauthorized_get].fetch(:status) == 401

existing = request.call('GET', '/readonly/existing.txt')
raise existing.inspect unless existing.values_at(:status, :body) == [200, "module-target-existing-content\n"]

responses[:existing_get] = existing
responses[:forbidden_put] = request.call('PUT', '/readonly/existing.txt', existing.fetch(:body))
raise responses[:forbidden_put].inspect unless responses[:forbidden_put].fetch(:status) == 403
raise 'Denied PUT modified the actual file' unless request.call('GET', '/readonly/existing.txt').fetch(:body) == existing.fetch(:body)

File.write(output, JSON.pretty_generate(
  captured_at: Time.now.utc.iso8601,
  image: 'httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e',
  source: File.basename(__FILE__), responses: responses, native_requests: requests
) + "\n")
