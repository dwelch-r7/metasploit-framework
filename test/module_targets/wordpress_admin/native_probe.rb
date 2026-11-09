# frozen_string_literal: true

require 'base64'
require 'json'
require 'net/http'
require 'nokogiri'
require 'open3'
require 'stringio'
require 'timeout'
require 'zip'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
evidence = { profiles: {}, commands: [], requests: [], callbacks: [] }
profiles = { 'root' => '', 'prefix' => '/wordpress', 'locked' => '' }
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', '--user', 'www-data', service, 'timeout', '20', *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  evidence.fetch(:commands) << { argv: argv, stdout_base64: Base64.strict_encode64(stdout), stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{service}: #{stderr}" unless status.success?

  stdout.force_encoding(Encoding::UTF_8)
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
    http.read_timeout = 20
  end
end
request = lambda do |service, message, expected|
  response = http_for.call(service).request(message)
  body = response.body.to_s.dup.force_encoding(Encoding::UTF_8)
  raise 'Native response is not UTF-8' unless body.valid_encoding?

  evidence.fetch(:requests) << {
    service: service, method: message.method, path: message.path, code: response.code.to_i,
    request_body_base64: message.body && Base64.strict_encode64(message.body), headers: response.to_hash, body: body
  }
  raise "Native #{service} #{message.path} expected #{expected}, got #{response.code}" unless response.code.to_i == expected

  response.body = body
  response
end
login = lambda do |service, prefix, user, password, valid|
  message = Net::HTTP::Post.new("#{prefix}/wp-login.php")
  message.set_form_data('log' => user, 'pwd' => password, 'redirect_to' => "#{prefix}/wp-admin/profile.php", 'wp-submit' => 'Log In')
  response = request.call(service, message, valid ? 302 : 200)
  cookies = response.get_fields('set-cookie').to_a.map { |value| value.split(';').first }.join('; ')
  raise 'Native HTML authentication differs' unless cookies.include?('wordpress_logged_in_') == valid

  if valid
    message = Net::HTTP::Get.new("#{prefix}/wp-admin/profile.php")
    message['Cookie'] = cookies
    profile = request.call(service, message, 200)
    raise 'Native authenticated identity differs' unless profile.body.include?("value=\"#{user}\"")
  end
  cookies
end
plugin_source = <<~PHP
  <?php
  /**
   * Plugin Name: Module target native upload control
   * Version: 1.0
   */
  $proof = 'module-target-native-upload|' . trim(shell_exec('/usr/bin/id -un'));
  file_put_contents('/tmp/module-target-native-upload-proof', json_encode(['proof' => $proof, 'cwd' => getcwd()]));
  echo $proof;
PHP
archive = Zip::OutputStream.write_buffer do |zip|
  zip.put_next_entry('module-target-native/module-target-native.php')
  zip.write(plugin_source)
end.string

begin
  profiles.each do |service, prefix|
    profile = JSON.parse(native.call(service, 'php', '/opt/module-target/inspect-admin.php'))
    evidence.fetch(:profiles)[service] = profile
    raise 'Native WordPress identity differs' unless profile.values_at('version', 'account', 'native_command_account') == ['6.8.3', 'www-data', 'www-data']
    raise 'Native filesystem method differs' unless profile.fetch('filesystem_method') == 'direct' && profile.fetch('plugins_writable')
    raise 'Native modification policy differs' unless profile.fetch('file_mods_disabled') == (service == 'locked')
    raise 'Native administrator capability differs' unless profile.fetch('accounts').fetch('module_admin').fetch('upload_plugins') == (service != 'locked')

    %w[module_author module_editor module_subscriber].each do |user|
      raise 'Native limited account can upload plugins' if profile.fetch('accounts').fetch(user).fetch('upload_plugins')
    end
    login.call(service, prefix, 'module_admin', 'module-target-wrong-password', false)
    login.call(service, prefix, 'module_target_missing', 'module-target-password', false)
    cookie = login.call(service, prefix, 'module_admin', 'module-target-password', true)
    editor = login.call(service, prefix, 'module_editor', 'module-target-&<café>', true)
    subscriber = login.call(service, prefix, 'module_subscriber', 'module-target-subscriber-password', true)
    page = Net::HTTP::Get.new("#{prefix}/wp-admin/plugin-install.php?tab=upload")
    page['Cookie'] = editor
    request.call(service, page, 403)
    page['Cookie'] = subscriber
    request.call(service, page, 403)
    if service == 'locked'
      page['Cookie'] = cookie
      request.call(service, page, 403)
      next
    end

    2.times do
      native.call(service, 'test', '!', '-e', '/tmp/module-target-native-upload-proof')
      native.call(service, 'test', '!', '-e', "#{profile.fetch('plugin_root')}/module-target-native")
      page['Cookie'] = cookie
      response = request.call(service, page, 200)
      nonce = Nokogiri::HTML(response.body).at_css('form input[name="_wpnonce"]')&.[]('value')
      raise 'Native upload nonce missing' if nonce.to_s.empty?

      upload = Net::HTTP::Post.new("#{prefix}/wp-admin/update.php?action=upload-plugin")
      upload['Cookie'] = cookie
      upload.set_form([
        ['_wpnonce', nonce], ['_wp_http_referer', "#{prefix}/wp-admin/plugin-install.php?tab=upload"],
        ['pluginzip', StringIO.new(archive), { filename: 'module-target-native.zip', content_type: 'application/zip' }],
        ['install-plugin-submit', 'Install Now']
      ], 'multipart/form-data')
      request.call(service, upload, 200)
      response = request.call(service, Net::HTTP::Get.new("#{prefix}/wp-content/plugins/module-target-native/module-target-native.php"), 200)
      raise 'Native uploaded PHP did not execute as the web account' unless response.body == 'module-target-native-upload|www-data'

      actual = JSON.parse(native.call(service, 'cat', '/tmp/module-target-native-upload-proof'))
      raise 'Native upload proof differs' unless actual.fetch('proof') == response.body
      raise 'Native uploaded PHP working directory missing' if actual.fetch('cwd').to_s.empty?

      profile['native_upload_cwd'] = actual.fetch('cwd')
      native.call(service, 'test', '-d', actual.fetch('cwd'))

      native.call(service, 'php', '/opt/module-target/cleanup-admin-native.php')
      final = JSON.parse(native.call(service, 'php', '/opt/module-target/inspect-admin.php'))
      raise 'Native control cleanup changed installed plugins' unless final.fetch('plugins') == profile.fetch('plugins')
    end
  end
  response = request.call('unrelated', Net::HTTP::Get.new('/'), 200)
  raise 'Unrelated HTTP identity differs' unless response.body.include?('module-target-http-marker')

  if runtime
    script = 'require "socket"; server=TCPServer.new("0.0.0.0",4141); puts "READY"; STDOUT.flush; 3.times { raise "Callback timed out" unless IO.select([server],nil,nil,10); client=server.accept; puts client.gets; STDOUT.flush; client.close }; server.close'
    Open3.popen3(*compose, 'exec', '-T', 'framework', 'ruby', '-e', script) do |stdin, stdout, stderr, waiter|
      stdin.close
      raise 'Native callback listener did not start' unless Timeout.timeout(15) { stdout.gets }&.strip == 'READY'

      profiles.each_key do |service|
        marker = "module-target-callback-#{service}"
        code = '$s=fsockopen($argv[1],4141,$errno,$errstr,5); if (!$s) {exit(1);} fwrite($s,$argv[2]."\n"); fclose($s);'
        native.call(service, 'php', '-r', code, runtime.fetch('listener_host'), marker)
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
