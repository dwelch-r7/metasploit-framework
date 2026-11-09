# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'
require 'rexml/document'
require 'uri'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
profiles = {}
commands = []
requests = []
prefixes = { 'root' => '', 'prefix' => '/wordpress', 'plain' => '', 'blocked' => '' }
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', service, 'timeout', '25', *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  [stdout, stderr].each do |value|
    value.force_encoding(Encoding::UTF_8)
    raise 'Native output is not valid UTF-8' unless value.valid_encoding?
  end
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{service}: #{stderr}" unless status.success?

  stdout
end
http_for = lambda do |service|
  endpoint = if runtime
               runtime.fetch('endpoints').fetch(service)
             else
               binding, status = Open3.capture2(*compose, 'port', service, '80')
               raise "Missing endpoint: #{service}" unless status.success?

               host, port = binding.strip.split(':')
               { 'host' => host, 'port' => Integer(port) }
             end
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 5
  http.read_timeout = 15
  http
end
request = lambda do |service, message, expected: nil|
  response = http_for.call(service).request(message)
  body = response.body&.dup&.force_encoding(Encoding::UTF_8)
  raise 'Native HTTP body is not valid UTF-8' if body && !body.valid_encoding?

  requests << { service: service, method: message.method, path: message.path, request_body: message.body, code: response.code.to_i, headers: response.to_hash, body: body }
  raise "Native #{service} #{message.path}: expected #{expected}, got #{response.code}" if expected && !Array(expected).include?(response.code.to_i)

  response
end
rpc_body = lambda do |user, password|
  document = REXML::Document.new
  document << REXML::XMLDecl.new('1.0', 'UTF-8')
  call = document.add_element('methodCall')
  call.add_element('methodName').text = 'wp.getUsers'
  params = call.add_element('params')
  ['1', user, password].each { |value| params.add_element('param').add_element('value').add_element('string').text = value }
  output = +''
  document.write(output)
  output.force_encoding(Encoding::UTF_8)
end

begin
  prefixes.each do |service, prefix|
    data = JSON.parse(native.call(service, 'php', '/opt/module-target/inspect.php'))
    raise "Wrong native WordPress: #{data}" unless data.fetch('version') == '6.8.3'
    raise 'Native fixture account count differs' unless data.fetch('users').size == 4

    profiles[service] = data
    root = request.call(service, Net::HTTP::Get.new("#{prefix}/"), expected: 200)
    raise 'Native front page omitted the actual post' unless root.body.include?('module-target-native-post-content')

    rest_path = URI(data.fetch('rest_url')).request_uri
    users = request.call(service, Net::HTTP::Get.new(rest_path), expected: 200)
    authors = JSON.parse(users.body)
    raise 'Native REST author list differs' unless authors.map { |author| author.fetch('slug') } == ['module_author']

    data['rest_users'] = authors
    data['rest_path'] = rest_path
    data['remote_versions'] = {}
    data.fetch('plugins').each do |path, metadata|
      next unless path.include?('/')

      slug = path.split('/').first
      response = request.call(service, Net::HTTP::Get.new("#{prefix}/wp-content/plugins/#{slug}/readme.txt"), expected: service == 'blocked' ? 403 : 200)
      next if response.code.to_i == 403

      version = response.body[/^Stable tag:\s*(\S+)/i, 1]
      raise "Native plugin release/readme mismatch: #{slug}" unless version == metadata.fetch('version')

      data.fetch('remote_versions')[slug] = version
    end
    data.fetch('themes').each do |slug, metadata|
      response = request.call(service, Net::HTTP::Get.new("#{prefix}/wp-content/themes/#{slug}/style.css"), expected: 200)
      raise "Native theme version differs: #{slug}" unless response.body[/^Version:\s*(\S+)/i, 1] == metadata.fetch('version')
    end
    data['author_routes'] = [2, 5].to_h do |identifier|
      response = request.call(service, Net::HTTP::Get.new("#{prefix}/?author=#{identifier}"))
      [identifier.to_s, { code: response.code.to_i, location: response['Location'], body: response.body }]
    end
    raise 'Missing native author must not have an archive' unless data.fetch('author_routes').fetch('5').fetch(:code) == 404

    data['html_login'] = {}
    {
      'valid' => ['module_author', 'module-target-author-password'],
      'special' => ['module_editor', 'module-target-&<café>'],
      'wrong' => ['module_author', 'module-target-wrong-password'],
      'blank' => ['module_author', ''],
      'missing' => ['module_target_missing', 'module-target-author-password']
    }.each do |label, (user, password)|
      login = Net::HTTP::Post.new("#{prefix}/wp-login.php")
      login.set_form_data('log' => user, 'pwd' => password, 'redirect_to' => "#{prefix}/wp-admin/profile.php", 'wp-submit' => 'Log In')
      response = request.call(service, login, expected: %w[valid special].include?(label) ? 302 : 200)
      cookies = response.get_fields('set-cookie')&.map { |value| value.split(';').first }&.join('; ')
      if %w[valid special].include?(label)
        raise "Native login cookie missing: #{service}/#{label}" unless cookies&.include?('wordpress_logged_in_')

        profile = Net::HTTP::Get.new("#{prefix}/wp-admin/profile.php")
        profile['Cookie'] = cookies
        actual = request.call(service, profile, expected: 200)
        raise 'Native authenticated identity differs' unless actual.body.include?("value=\"#{user}\"")
      elsif cookies&.include?('wordpress_logged_in_')
        raise "Native incorrect login returned a session: #{service}/#{label}"
      end
      data.fetch('html_login')[label] = { code: response.code.to_i, cookies: cookies }
    end
    availability = request.call(service, Net::HTTP::Get.new("#{prefix}/xmlrpc.php"), expected: service == 'blocked' ? 403 : [200, 405])
    data['xmlrpc_get'] = { code: availability.code.to_i, body: availability.body }
    next if service == 'blocked'

    raise 'Native XML-RPC identity missing' unless availability.body.include?('XML-RPC server accepts POST requests only')

    data['rpc'] = {}
    {
      'admin' => ['module_admin', 'module-target-password', nil],
      'subscriber' => ['module_subscriber', 'module-target-subscriber-password', 401],
      'special' => ['module_editor', 'module-target-&<café>', 401],
      'wrong' => ['module_admin', 'module-target-wrong-password', 403],
      'missing' => ['module_target_missing', 'module-target-password', 403]
    }.each do |label, (user, password, expected_fault)|
      message = Net::HTTP::Post.new("#{prefix}/xmlrpc.php")
      message['Content-Type'] = 'text/xml; charset=UTF-8'
      message.body = rpc_body.call(user, password)
      response = request.call(service, message, expected: 200)
      xml = REXML::Document.new(response.body)
      fault = REXML::XPath.first(xml, '//fault/value/struct/member[name="faultCode"]/value/int')&.text&.to_i
      raise "Native RPC policy differs: #{service}/#{label}: #{response.body}" unless fault == expected_fault
      raise 'Native RPC administrator result omitted users' if label == 'admin' && !response.body.include?('<name>user_id</name>')

      data.fetch('rpc')[label] = { fault: fault, body: response.body }
    end
  end
  response = request.call('unrelated', Net::HTTP::Get.new('/'), expected: 200)
  raise 'Unrelated actual HTTP differs' unless response.body.include?('Module target')
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands, requests: requests)
end
