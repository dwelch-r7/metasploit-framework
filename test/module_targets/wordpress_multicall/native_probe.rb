# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'open3'
require 'rexml/document'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
accounts = JSON.parse(File.read(File.join(__dir__, 'accounts.json')))
evidence = { profiles: {}, commands: [], requests: [] }
profiles = { 'vulnerable' => ['4.3.1', '', false], 'fixed' => ['4.4', '', true], 'modern' => ['6.8.3', '/wordpress', true] }

def encode_value(node, data)
  case data
  when Array
    parent = node.add_element('array').add_element('data')
    data.each { |item| encode_value(parent.add_element('value'), item) }
  when Hash
    parent = node.add_element('struct')
    data.each do |name, item|
      member = parent.add_element('member')
      member.add_element('name').text = name
      encode_value(member.add_element('value'), item)
    end
  when Integer
    node.add_element('int').text = data.to_s
  else
    node.add_element('string').text = data.to_s
  end
end

def decode_value(node)
  type = node.elements[1]
  return node.text.to_s unless type

  case type.name
  when 'array'
    type.get_elements('data/value').map { |item| decode_value(item) }
  when 'struct'
    type.get_elements('member').to_h { |member| [member.elements['name'].text, decode_value(member.elements['value'])] }
  when 'int', 'i4'
    Integer(type.text)
  when 'boolean'
    type.text == '1'
  when 'string'
    type.text.to_s
  else
    raise "Unexpected native XML-RPC type: #{type.name}"
  end
end

def blogs_in(data)
  return data.flat_map { |item| blogs_in(item) } if data.is_a?(Array)
  return [data] if data.is_a?(Hash) && data['blogid']

  []
end

native = lambda do |service|
  argv = compose + ['exec', '-T', '--user', 'www-data', service, 'timeout', '25', 'php', '/opt/module-target/prep.php']
  stdout, stderr, status = Open3.capture3(*argv)
  [stdout, stderr].each { |value| value.force_encoding(Encoding::UTF_8) }
  evidence.fetch(:commands) << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native setup failed: #{service}: #{stderr}" unless status.success?

  JSON.parse(stdout)
end
http_for = lambda do |service|
  endpoint = if runtime
               runtime.fetch('endpoints').fetch(service)
             else
               binding, status = Open3.capture2(*compose, 'port', service, '80')
               raise 'Missing native HTTP binding' unless status.success?

               host, port = binding.strip.split(':')
               { 'host' => host, 'port' => Integer(port) }
             end
  Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil).tap do |http|
    http.open_timeout = 5
    http.read_timeout = 15
  end
end
request = lambda do |service, message|
  response = http_for.call(service).request(message)
  body = response.body.to_s.dup.force_encoding(Encoding::UTF_8)
  raise 'Native response is not UTF-8' unless body.valid_encoding?

  evidence.fetch(:requests) << {
    service: service, method: message.method, path: message.path, code: response.code.to_i,
    request_body_base64: message.body && Base64.strict_encode64(message.body), headers: response.to_hash, body: body
  }
  response.body = body
  response
end
rpc = lambda do |service, prefix, method, params|
  document = REXML::Document.new
  document << REXML::XMLDecl.new('1.0', 'UTF-8')
  call = document.add_element('methodCall')
  call.add_element('methodName').text = method
  arguments = call.add_element('params')
  params.each { |item| encode_value(arguments.add_element('param').add_element('value'), item) }
  body = +''
  document.write(body)
  message = Net::HTTP::Post.new("#{prefix}/xmlrpc.php")
  message['Content-Type'] = 'text/xml; charset=UTF-8'
  message.body = body
  response = request.call(service, message)
  raise "Native XML-RPC HTTP status differs: #{service}: #{response.code}" unless response.code.to_i == 200

  reply = REXML::Document.new(response.body)
  value = reply.elements['methodResponse/fault/value'] || reply.elements['methodResponse/params/param/value']
  raise 'Native XML-RPC response value missing' unless value

  decode_value(value)
end

begin
  profiles.each do |service, (version, prefix, latched)|
    profile = native.call(service)
    evidence.fetch(:profiles)[service] = profile
    raise 'Native WordPress release differs' unless profile.fetch('version') == version
    raise 'Native authentication latch differs' unless profile.fetch('has_auth_failed_latch') == latched
    raise 'Native plugins must remain inactive' unless profile.fetch('active_plugins').empty?

    availability = request.call(service, Net::HTTP::Get.new("#{prefix}/xmlrpc.php"))
    raise 'Native XML-RPC identity differs' unless [200, 405].include?(availability.code.to_i) && availability.body.include?('XML-RPC server accepts POST requests only')
    raise 'Native XML-RPC greeting differs' unless rpc.call(service, prefix, 'demo.sayHello', []) == 'Hello!'

    profile['individual'] = accounts.to_h do |user, account|
      result = rpc.call(service, prefix, 'wp.getUsersBlogs', [user, account.fetch('password')])
      raise "Native valid credentials were refused: #{service}/#{user}" unless blogs_in(result).any? { |blog| blog.fetch('blogid').to_i == 1 }

      [user, result]
    end
    user = 'module_admin'
    correct = accounts.fetch(user).fetch('password')
    wrong = 'module-target-wrong-password'
    profile['wrong'] = rpc.call(service, prefix, 'wp.getUsersBlogs', [user, wrong])
    profile['missing'] = rpc.call(service, prefix, 'wp.getUsersBlogs', ['module_target_missing', correct])
    raise 'Native wrong/missing credentials were accepted' unless %w[wrong missing].all? { |label| profile.fetch(label).fetch('faultCode') == 403 }

    profile['batches'] = {}
    { 'wrong_then_right' => [wrong, correct], 'right_then_wrong' => [correct, wrong], 'both_right' => [correct, correct] }.each do |label, passwords|
      calls = passwords.map { |password| { 'methodName' => 'wp.getUsersBlogs', 'params' => [user, password] } }
      result = rpc.call(service, prefix, 'system.multicall', [calls])
      raise 'Native batch result count differs' unless result.is_a?(Array) && result.length == passwords.length

      statuses = result.map do |item|
        if item.is_a?(Hash) && item['faultCode']
          item.fetch('faultCode')
        else
          blogs_in(item).empty? ? 'missing' : 'success'
        end
      end
      expected = case label
                 when 'wrong_then_right' then [403, latched ? 403 : 'success']
                 when 'right_then_wrong' then ['success', 403]
                 else %w[success success]
                 end
      raise "Native #{service} batch boundary differs: #{label}: #{statuses}" unless statuses == expected

      profile.fetch('batches')[label] = { statuses: statuses, result: result }
    end
    fresh = rpc.call(service, prefix, 'wp.getUsersBlogs', [user, correct])
    raise 'Native failed-batch state escaped its HTTP request' if blogs_in(fresh).empty?

    profile['fresh_after_failed_batch'] = fresh
  end
  response = request.call('unrelated', Net::HTTP::Get.new('/'))
  raise 'Unrelated HTTP differs' unless response.code.to_i == 200 && response.body.include?('module-target-http-marker')
ensure
  puts JSON.pretty_generate(evidence)
end
