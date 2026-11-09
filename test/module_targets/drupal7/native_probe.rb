# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'shellwords'
require 'timeout'
require 'uri'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '--project-name', ARGV.fetch(0), '--file', File.join(__dir__, 'compose.yaml')]
evidence = { profiles: {}, commands: [], requests: [], executions: [], callbacks: [] }
profiles = {
  'root' => ['', '7.57', true, true],
  'prefix' => ['/drupal', '7.57', true, true],
  'fixed' => ['', '7.58', false, false],
  'assert_off' => ['', '7.57', true, true],
  'no_changelog' => ['', '7.57', true, true]
}
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', '--user', 'www-data', service, 'timeout', '20', *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  evidence.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(stdout), stderr: stderr, exitstatus: status.exitstatus }
  raise "Native #{service} command failed: #{stderr}" unless status.success?

  stdout.force_encoding(Encoding::UTF_8)
end
endpoint_for = lambda do |service|
  if runtime
    runtime.fetch('endpoints').fetch(service)
  else
    binding, status = Open3.capture2(*compose, 'port', service, '80')
    raise 'Missing native HTTP binding' unless status.success?

    host, port = binding.strip.split(':')
    { 'host' => host, 'port' => Integer(port) }
  end
end
request = lambda do |service, message|
  endpoint = endpoint_for.call(service)
  http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
  http.open_timeout = 5
  http.read_timeout = 10
  http.max_retries = 0
  response = http.request(message)
  body = response.body.to_s.dup.force_encoding(Encoding::UTF_8)
  raise 'Native response is not UTF-8' unless body.valid_encoding?

  evidence.fetch(:requests) << {
    service: service, method: message.method, path: message.path, code: response.code.to_i,
    request_cookie: message['Cookie'], request_body_base64: message.body && Base64.strict_encode64(message.body),
    headers: response.to_hash, body: body
  }
  response.body = body
  response
end
execute_form = lambda do |service, prefix, function, code|
  query = URI.encode_www_form(
    'q' => 'user/password', 'name[#post_render][]' => function,
    'name[#markup]' => code, 'name[#type]' => 'markup'
  )
  message = Net::HTTP::Post.new("#{prefix}/?#{query}")
  message.set_form_data('form_id' => 'user_pass', '_triggering_element_name' => 'name')
  form = request.call(service, message)
  raise "Native form stage failed: #{service}: HTTP #{form.code}" unless form.code.to_i == 200

  build_id = Nokogiri::HTML(form.body).at_css('form#user-pass input[name="form_build_id"]')&.[]('value')
  raise "Native form build identifier missing: #{service}" unless build_id && !build_id.empty?

  query = URI.encode_www_form('q' => "file/ajax/name/#value/#{build_id}")
  message = Net::HTTP::Post.new("#{prefix}/?#{query}")
  message.set_form_data('form_build_id' => build_id)
  request.call(service, message)
end

begin
  profiles.each do |service, (prefix, version, php_execution, command_execution)|
    profile = JSON.parse(native.call(service, 'php', '/opt/module-target/inspect.php'))
    evidence.fetch(:profiles)[service] = profile
    raise 'Native release/runtime identity differs' unless profile.values_at('version', 'php', 'account', 'profile', 'database_driver') == [version, '5.6.40', 'www-data', 'standard', 'mysql']
    raise 'Native bundled File module is unavailable' unless profile.fetch('modules').include?('file')
    raise 'Native assert policy differs' unless profile.fetch('assert_active') == (service != 'assert_off')
    raise 'Native patch sanitizer presence differs' unless profile.fetch('request_sanitizer') == (service == 'fixed')
    raise 'Native changelog policy differs' unless profile.fetch('changelog') == (service != 'no_changelog')
    raise 'Native seeded administrator differs' unless profile.fetch('admin') == { 'name' => 'module_admin', 'active' => '1' }

    page = request.call(service, Net::HTTP::Get.new("#{prefix}/"))
    raise 'Native Drupal page identity differs' unless page.code.to_i == 200 && page.body.include?('Drupal 7')

    form = request.call(service, Net::HTTP::Get.new("#{prefix}/?q=user/password"))
    raise 'Native anonymous password form unavailable' unless form.code.to_i == 200 && Nokogiri::HTML(form.body).at_css('input[name="form_id"][value="user_pass"]')

    denied = request.call(service, Net::HTTP::Get.new("#{prefix}/?q=admin"))
    raise 'Native anonymous administration policy differs' unless denied.code.to_i == 403

    changelog = request.call(service, Net::HTTP::Get.new("#{prefix}/CHANGELOG.txt"))
    raise 'Native changelog route differs' unless changelog.code.to_i == (service == 'no_changelog' ? 404 : 200)

    # Drupal 7 post-render callbacks pass an element array as argument two.
    # PHP 5.6 assert() requires a string description there, so the real module
    # must use its existing PHP CLI fallback even when assertions are enabled.
    { 'assert' => ['assert', false], 'php' => ['passthru', php_execution], 'command' => ['passthru', command_execution] }.each do |kind, (function, expected)|
      2.times do |iteration|
        marker = "module-target-drupal-native-#{service}-#{kind}-#{iteration}"
        path = "/tmp/#{marker}"
        native.call(service, 'test', '!', '-e', path)
        begin
          php = "file_put_contents(\"#{path}\", \"#{marker}\");"
          code = case kind
                 when 'assert' then php
                 when 'php' then "php -r #{Shellwords.escape(php)}"
                 else "/usr/bin/printf #{marker} | /usr/bin/tee #{path}"
                 end
          reply = execute_form.call(service, prefix, function, code)
          present = native.call(service, 'php', '-r', 'echo is_file($argv[1]) ? "yes" : "no";', path) == 'yes'
          evidence.fetch(:executions) << { service: service, kind: kind, iteration: iteration, expected: expected, present: present, response_code: reply.code.to_i, marker: marker }
          raise "Native #{service} #{kind} execution boundary differs" unless present == expected

          if expected
            raise 'Native fresh marker bytes differ' unless native.call(service, 'cat', path) == marker
            raise 'Native web execution identity differs' unless native.call(service, 'stat', '-c', '%U', path).strip == 'www-data'
          end
        ensure
          native.call(service, 'rm', '-f', path)
        end
        native.call(service, 'test', '!', '-e', path)
      end
    end
  end
  missing = request.call('root', Net::HTTP::Get.new('/module-target-missing/?q=user/password'))
  raise 'Native missing installation path was accepted' unless missing.code.to_i == 404

  unrelated = request.call('unrelated', Net::HTTP::Get.new('/'))
  raise 'Unrelated Apache identity differs' unless unrelated.code.to_i == 200 && unrelated.body.include?('module-target-http-marker')

  if runtime
    services = %w[root prefix assert_off]
    script = 'require "socket"; server=TCPServer.new("0.0.0.0",4143); puts "READY"; STDOUT.flush; 3.times { raise "Callback timed out" unless IO.select([server],nil,nil,10); client=server.accept; puts client.gets; STDOUT.flush; client.close }; server.close'
    Open3.popen3(*compose, 'exec', '-T', 'framework', 'ruby', '-e', script) do |stdin, stdout, stderr, waiter|
      stdin.close
      raise 'Native callback listener did not start' unless Timeout.timeout(15) { stdout.gets }&.strip == 'READY'

      services.each do |service|
        marker = "module-target-drupal-callback-#{service}"
        php = "$socket=fsockopen(\"#{runtime.fetch('listener_host')}\",4143,$errno,$error,5); if (!$socket) {exit(1);} fwrite($socket,\"#{marker}\\n\"); fclose($socket);"
        command = "php -r #{Shellwords.escape(php)}"
        execute_form.call(service, profiles.fetch(service).first, 'passthru', command)
        actual = Timeout.timeout(15) { stdout.gets }&.strip
        evidence.fetch(:callbacks) << { service: service, expected: marker, actual: actual }
        raise 'Native reverse connection proof differs' unless actual == marker
      end
      raise 'Native callback listener failed' unless waiter.value.success?
      raise 'Native callback listener reported errors' unless stderr.read.empty?
    end
  end
ensure
  puts JSON.pretty_generate(evidence)
end
