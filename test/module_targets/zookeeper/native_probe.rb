# frozen_string_literal: true

require 'json'
require 'socket'
require 'timeout'
require 'open3'
require 'net/http'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
commands = []
requests = []
profiles = {}
permissions = {
  'legacy' => %w[srvr ruok envi stat], 'modern' => %w[srvr ruok envi stat],
  'environment_only' => %w[srvr ruok envi], 'statistics_only' => %w[srvr ruok stat],
  'restricted' => ['srvr']
}
native = lambda do |service, *arguments|
  argv = runtime.fetch('compose') + ['exec', '-T', service, *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{commands.last.inspect}" unless status.success?

  stdout
end
request = lambda do |service, command|
  endpoint = runtime.fetch('endpoints').fetch(service)
  response = Timeout.timeout(5) do
    Socket.tcp(endpoint.fetch('host'), endpoint.fetch('port'), connect_timeout: 3) do |socket|
      socket.write(command)
      socket.read
    end
  end
  response.force_encoding(Encoding::UTF_8)
  raise 'Native ZooKeeper response is not valid UTF-8' unless response.valid_encoding?

  requests << { service: service, command: command, response: response }
  response
end

begin
  permissions.each do |service, allowed|
    version = service == 'legacy' ? '3.4.14' : '3.9.3'
    config = native.call(service, 'bash', '-c', 'cat "$ZOO_CONF_DIR/zoo.cfg"')
    raise 'Native whitelist differs' unless config.lines.grep(/^4lw\.commands\.whitelist=/).last&.strip == "4lw.commands.whitelist=#{allowed.join(',')}"

    status = native.call(service, 'zkServer.sh', 'status')
    raise 'Native server is not standalone' unless status.include?('Mode: standalone')

    cli_output = native.call(service, 'bash', '-c', 'ZOOBINDIR="$PWD/bin"; . "$ZOOBINDIR/zkEnv.sh"; exec "$JAVA" -Xms16m -Xmx32m -cp "$CLASSPATH" org.apache.zookeeper.Version --full')
    # Modern Version also logs JVM shutdown to stdout; retain it in the receipt
    # and require one precise version line instead of treating it as version text.
    version_lines = cli_output.lines.map(&:strip).select { |line| line.start_with?(version + '-') }
    raise "Native version differs: #{cli_output}" unless version_lines.length == 1

    cli = version_lines.first

    responses = %w[ruok envi stat].to_h do |command|
      response = request.call(service, command)
      if allowed.include?(command)
        raise "Native allowed command denied: #{command}" if response.empty? || response.include?('whitelist')
      else
        raise "Native command not denied: #{command}" unless response.include?("#{command} is not executed because it is not in the whitelist")
      end
      [command, response]
    end
    raise 'Native ruok differs' if allowed.include?('ruok') && responses.fetch('ruok') != 'imok'

    environment = responses.fetch('envi').lines.filter_map { |line| line.strip.split('=', 2) if line.include?('=') }.to_h
    if allowed.include?('envi')
      raise 'Native environment and CLI versions differ' unless environment.fetch('zookeeper.version') == cli
      raise 'Native environment identity differs' unless %w[host.name java.version os.name os.arch os.version user.name].all? { |field| !environment.fetch(field).empty? }
    end
    if allowed.include?('stat')
      raise 'Native statistics and CLI version differ' unless responses.fetch('stat').include?("Zookeeper version: #{cli}\n")
      raise 'Native statistics mode differs' unless responses.fetch('stat').include?("Mode: standalone\n")
      raise 'Native node count is absent' unless responses.fetch('stat').match?(/^Node count: \d+$/)
    end
    profiles[service] = { cli_version: cli, allowed: allowed, environment: environment, responses: responses }
  end
  endpoint = runtime.fetch('endpoints').fetch('unrelated')
  response = Net::HTTP.start(endpoint.fetch('host'), endpoint.fetch('port'), nil) { |http| http.get('/') }
  raise 'Native unrelated Apache control differs' unless response.code == '200' && response.body.include?('Module target')
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands, requests: requests)
end
