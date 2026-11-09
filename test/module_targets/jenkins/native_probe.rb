# frozen_string_literal: true

require 'json'
require 'net/http'
require 'open3'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
versions = JSON.parse(File.read(File.join(__dir__, 'profiles.json'))).transform_values { |profile| profile.fetch('version') }
catalog = JSON.parse(File.read(File.join(__dir__, 'fixtures.json')))
commands = []
profiles = {}
native = lambda do |service, *arguments, input: ''|
  argv = compose + ['exec', '-T', service, 'timeout', '25', *arguments]
  stdout, stderr, status = Open3.capture3(*argv, stdin_data: input)
  [stdout, stderr].each do |output|
    output.force_encoding(Encoding::UTF_8)
    raise "Native text output is not UTF-8: #{service} #{arguments.inspect}" unless output.valid_encoding?
  end
  commands << { service: service, argv: argv, stdin: input, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command timed out: #{service} #{arguments.inspect}" if status.exitstatus == 124

  [stdout, stderr, status.exitstatus]
end

begin
  versions.each do |service, version|
    report = { version: version, files: {} }
    profiles[service] = report
    stdout, stderr, code = native.call(service, 'java', '-jar', '/usr/share/jenkins/jenkins.war', '--version')
    raise "Native version differs: #{stdout} #{stderr}" unless code.zero? && stdout.strip == version

    jar = "/tmp/module-target-#{service}-cli.jar"
    stdout, stderr, code = native.call('native_client', 'curl', '--fail', '--silent', '--show-error', '-o', jar, "http://#{service}:8080/jenkins/jnlpJars/jenkins-cli.jar")
    raise "Cannot obtain the actual controller CLI: #{stdout} #{stderr}" unless code.zero?

    native.call(service, 'sha256sum', '/usr/share/jenkins/jenkins.war')
    native.call('native_client', 'sha256sum', jar)
    cli = ['java', '-jar', jar, '-s', "http://#{service}:8080/jenkins/", '-http']
    catalog.each do |name, fixture|
      path = fixture.fetch('path')
      if fixture['content']
        stdout, stderr, code = native.call(service, 'cat', path)
        raise "Native fixture bytes differ: #{service}/#{name}: #{stderr}" unless code.zero? && stdout == fixture.fetch('content')
      elsif name == 'missing'
        _, _, code = native.call(service, 'test', '-e', path)
        raise "Missing fixture exists: #{service}" unless code == 1
      else
        _, _, exists = native.call(service, 'test', '-e', path)
        _, _, readable = native.call(service, 'test', '-r', path)
        raise "Denied fixture is not actually unreadable: #{service}" unless exists.zero? && readable == 1
      end
      next if service == 'open'

      _, _, absent_from_client = native.call('native_client', 'test', '-e', path)
      raise "Native CLI client can read the controller fixture locally: #{path}" unless absent_from_client == 1

      vulnerable = service.end_with?('_vulnerable')
      arguments = ['help']
      arguments << '1' if name == 'one' || !vulnerable
      arguments << "@#{path}"
      stdout, stderr, code = native.call('native_client', *cli, *arguments)
      combined = stdout + stderr
      report[:files][name] = { stdout: stdout, stderr: stderr, exitstatus: code, path: path }
      raise "Native help did not return a bounded error: #{service}/#{name}" if code.zero? || combined.empty?

      if vulnerable && fixture['content'] && !fixture['content'].empty?
        expected = fixture.fetch('content').lines.map(&:chomp).first(name == 'one' ? 1 : 2)
        raise "Native CLI did not expose real content: #{service}/#{name}: #{combined}" unless expected.all? { |line| combined.include?(line) }
      elsif !vulnerable
        raise "Fixed CLI still exposed fixture content: #{service}/#{name}" if combined.include?('module-target-first-line') || combined.include?('module-target-single-line') || combined.include?('module-target-long-first') || combined.include?('module-target-café-漢字')
      end
    end
    # The official CLI independently proves real Groovy permissions and both
    # configured credentials; it is not a Framework-crafted protocol fixture.
    auth_modes = if service == 'open'
                   { 'anonymous' => [] }
                 else
                   {
                     'password' => ['-auth', 'module_target:module-target-password'],
                     'token' => ['-auth', 'module_target:1100000000000000000000000000000000']
                   }
                 end
    auth_modes.each do |mode, flags|
      stdout, stderr, code = native.call('native_client', *cli, *flags, 'groovy', '=', input: "println 'module-target-native-groovy'\n")
      raise "Native Groovy #{mode} failed: #{service}: #{stdout} #{stderr}" unless code.zero? && stdout.strip == 'module-target-native-groovy'

      report[mode] = { stdout: stdout, stderr: stderr, exitstatus: code }
    end
    endpoint = if runtime
                 runtime.fetch('endpoints').fetch(service)
               else
                 binding, status = Open3.capture2(*compose, 'port', service, '8080')
                 raise "Missing host endpoint: #{service}" unless status.success?

                 host, port = binding.strip.split(':')
                 { 'host' => host, 'port' => port.to_i }
               end
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 5
    http.read_timeout = 10
    http_modes = service == 'open' ? { 'anonymous' => nil } : { 'anonymous' => nil, 'password' => 'module-target-password', 'token' => '1100000000000000000000000000000000', 'wrong' => 'wrong-password' }
    http_modes.each do |mode, password|
      request = Net::HTTP::Get.new('/jenkins/script')
      request.basic_auth('module_target', password) if password
      response = http.request(request)
      report["http_#{mode}"] = { code: response.code.to_i, headers: response.to_hash, body: response.body&.dup&.force_encoding(Encoding::UTF_8) }
      if mode == 'wrong'
        raise "Missing native authentication challenge: #{service}" unless response['WWW-Authenticate'] == 'Basic realm="Jenkins"'
      else
        raise "Wrong native HTTP product: #{service}" unless response['X-Jenkins'] == version
      end

      expected = if service == 'open'
                   200
                 elsif mode == 'wrong'
                   401
                 elsif mode == 'anonymous'
                   403
                 else
                   200
                 end
      raise "Native HTTP #{mode} policy differs: #{service}: #{response.code}" unless response.code.to_i == expected
    end
  end
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands)
end
