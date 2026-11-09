# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
records = []
commands = []
profiles = {}
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', service, *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  [stdout, stderr].each do |output|
    output.force_encoding(Encoding::UTF_8)
    raise "Native output is not UTF-8: #{arguments.inspect}" unless output.valid_encoding?
  end
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{argv.inspect}: #{stdout} #{stderr}" unless status.success?

  stdout
end
begin
  %w[open secured unrelated].each do |service|
    endpoint = if runtime
                 runtime.fetch('endpoints').fetch(service)
               else
                 binding, status = Open3.capture2(*compose, 'port', service, service == 'unrelated' ? '80' : '8080')
                 raise "Missing native endpoint: #{service}" unless status.success?

                 host, port = binding.strip.split(':')
                 { 'host' => host, 'port' => Integer(port) }
               end
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 15
    request = lambda do |label, req|
      res = http.request(req)
      records << { service: service, label: label, method: req.method, path: req.path, code: res.code.to_i, headers: res.to_hash, body: res.body }
      res
    end
    if service == 'unrelated'
      response = request.call('root', Net::HTTP::Get.new('/'))
      raise 'Unrelated native HTTP differs' unless response.code == '200' && response.body.include?('Module target')

      next
    end
    version = native.call(service, 'java', '-jar', '/usr/share/jenkins/jenkins.war', '--version').strip
    raise "Unexpected Jenkins version #{version}" unless version == '2.442'

    system = request.call('systemInfo', Net::HTTP::Get.new('/jenkins/systemInfo'))
    script = request.call('script', Net::HTTP::Get.new('/jenkins/script'))
    expected = service == 'open' ? '200' : '403'
    raise "Actual Jenkins policy differs: #{service}" unless [system, script].all? { |res| res.code == expected && res['X-Jenkins'] == version }

    profiles[service] = { version: version, system_info_status: system.code.to_i, script_status: script.code.to_i }
    next unless service == 'open'

    account = native.call(service, 'id', '-un').strip
    crumb = script.body[/data-crumb-value="([a-z0-9]+)"/, 1]
    name = script.body[/data-crumb-header="([^"]+)"/, 1]
    cookie = script.get_fields('set-cookie').map { |value| value.split(';').first }.join('; ')
    raise 'Native session or CSRF crumb missing' unless crumb && name && cookie.include?('JSESSIONID')

    [false, true].each do |keep_cookie|
      req = Net::HTTP::Post.new('/jenkins/scriptText')
      req['Cookie'] = cookie if keep_cookie
      req.set_form_data('script' => "println new ProcessBuilder('/usr/bin/id','-un').start().inputStream.text.trim()", name => crumb)
      res = request.call("native-id-cookie-#{keep_cookie}", req)
      raise 'Native CSRF session boundary differs' unless res.code.to_i == (keep_cookie ? 200 : 403)
      raise 'Native command account differs' if keep_cookie && res.body.strip != account
    end
    proof_path = '/tmp/module-target-native-command-proof'
    native.call(service, 'test', '!', '-e', proof_path)
    req = Net::HTTP::Post.new('/jenkins/scriptText')
    req['Cookie'] = cookie
    req.set_form_data('script' => "println new ProcessBuilder('/usr/bin/touch','#{proof_path}').start().waitFor()", name => crumb)
    res = request.call('native-file-proof', req)
    raise 'Native file command failed' unless res.code == '200' && res.body.strip == '0'
    raise 'Native target owner differs' unless native.call(service, 'stat', '-c', '%U', proof_path).strip == account

    native.call(service, 'rm', proof_path)
    profiles.fetch(service)[:account] = account
    %w[true missing].each do |command|
      path = command == 'true' ? '/usr/bin/true' : '/module-target-no-command'
      req = Net::HTTP::Post.new('/jenkins/scriptText')
      req['Cookie'] = cookie
      req.set_form_data('script' => "def proc='#{path}'.execute(); proc.waitForOrKill(1000); println proc.inputStream.text", name => crumb)
      res = request.call("native-#{command}", req)
      raise 'Native script endpoint failed' unless res.code == '200'
      raise 'Native missing command was not refused' if command == 'missing' && !res.body.include?('No such file or directory')
    end
    profiles.fetch(service)[:literal] = %q{module-target-'"\&<>out>err>}
    profiles.fetch(service)[:entities] = 'module-target-&lt;-out>-err>'
    profiles.fetch(service)[:unicode] = 'module-target-café-漢字-$name'
    %i[literal entities unicode].each do |kind|
      value = profiles.fetch(service).fetch(kind)
      raise 'Native argument bytes differ' unless native.call(service, '/usr/bin/printf', '%s', value) == value
    end
  end
ensure
  puts JSON.pretty_generate(profiles: profiles, requests: records, commands: commands)
end
