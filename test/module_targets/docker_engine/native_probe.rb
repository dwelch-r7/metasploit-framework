# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'
require 'open3'
require 'time'

# Genuine daemon/client controls, independent of Framework's module and parser.
class NativeDockerEngineProbe
  VERSIONS = { 'old' => '26.1.4', 'modern' => '28.0.4' }.freeze
  USERNAME = 'module-test-user'
  PASSWORD = 'module-test-password'

  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { commands: [], http: [], engines: {} }
  end

  def run
    VERSIONS.each do |service, version|
      server = JSON.parse(command(service, 'docker', '--host', 'unix:///var/run/docker.sock', 'version', '--format', '{{json .Server}}'))
      info = JSON.parse(command(service, 'docker', '--host', 'unix:///var/run/docker.sock', 'info', '--format', '{{json .}}'))
      status = command(service, 'cat', '/proc/1/status')
      caps = Integer(status.match(/^CapEff:\s*([0-9a-f]+)$/)[1], 16)
      raise 'Nested daemon gained forbidden capabilities' unless (caps & ((1 << 21) | (1 << 25))).zero?
      raise 'Native daemon version or storage differs' unless server.fetch('Version') == version && info.fetch('Driver') == 'vfs'
      raise 'Native daemon contains a workload' unless info.fetch('Containers').zero? && info.fetch('Images').zero?

      response = request(service, '/version')
      document = JSON.parse(response.body)
      raise 'Native HTTP/CLI version documents differ' unless response.code == '200' && cli_document(document) == server
      raise 'Daemon native ping failed' unless request(service, '/_ping').body == 'OK'

      @records[:engines][service] = document
    end

    modern = @records.fetch(:engines).fetch('modern')
    response = request('gateway', '/version', credentials: [USERNAME, PASSWORD])
    raise 'Authenticated gateway changed the actual daemon document' unless response.code == '200' && JSON.parse(response.body) == modern

    [nil, [USERNAME, 'wrong-password']].each do |credentials|
      raise 'Gateway did not enforce native authentication' unless request('gateway', '/version', credentials: credentials).code == '401'
    end
    certificate = command('gateway', 'cat', '/usr/local/apache2/conf/module-target.crt')
    @certificate = File.join(@runtime.fetch('artifacts'), 'native-docker-gateway.crt')
    File.write(@certificate, certificate)
    binding = compose('port', 'gateway', '443').strip
    host, port = binding.split(':')
    response = request('gateway', '/version', tls_endpoint: { host: host, port: Integer(port) })
    raise 'TLS gateway changed the actual daemon document' unless response.code == '200' && JSON.parse(response.body) == modern

    unrelated = request('unrelated', '/version')
    raise 'Unrelated HTML control differs' unless unrelated.code == '200' && unrelated['Content-Type'].start_with?('text/html') && unrelated.body.include?('module-target-http-marker')
    raise 'Unrelated missing resource is not 404' unless request('missing', '/version').code == '404'

    database = command('reporting_db', 'env', "PGPASSWORD=#{PASSWORD_DATABASE}", 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-Atc', 'SELECT current_user, current_database(), version()')
    raise 'Native reporting database differs' unless database.include?('module_framework|module_targets|PostgreSQL 16.')

    @records
  ensure
    File.write(File.join(@runtime.fetch('artifacts'), 'native-docker-engine-partial.json'), JSON.pretty_generate(@records))
  end

  PASSWORD_DATABASE = 'module-target-framework-db-password'

  private

  def command(service, *)
    compose('exec', '-T', service, *)
  end

  def cli_document(document)
    JSON.parse(JSON.generate(document)).tap do |copy|
      # Docker CLI renders component BuildTime in UTC ANSIC instead of RFC3339.
      copy.fetch('Components').each do |component|
        details = component['Details']
        details['BuildTime'] = Time.iso8601(details.fetch('BuildTime')).utc.strftime('%a %b %e %H:%M:%S %Y') if details&.key?('BuildTime')
      end
    end
  end

  def compose(*arguments)
    argv = @runtime.fetch('compose') + arguments
    stdout, stderr, status = Open3.capture3(*argv)
    @records[:commands] << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
    raise "Native Docker lab command failed: #{arguments.inspect}: #{stderr}" unless status.success?

    stdout
  end

  def request(service, path, credentials: nil, tls_endpoint: nil)
    endpoint = tls_endpoint || @runtime.fetch('endpoints').fetch(service).transform_keys(&:to_sym)
    http = Net::HTTP.new(tls_endpoint ? 'destination' : endpoint.fetch(:host), endpoint.fetch(:port), nil)
    http.open_timeout = http.read_timeout = 3
    if tls_endpoint
      http.ipaddr = endpoint.fetch(:host)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.ca_file = @certificate
    end
    request = Net::HTTP::Get.new(path)
    request.basic_auth(*credentials) if credentials
    response = http.request(request)
    @records[:http] << { service: service, path: path, tls: !tls_endpoint.nil?, credentials: credentials, code: response.code, headers: response.to_hash, body: response.body }
    response
  end
end

puts JSON.pretty_generate(NativeDockerEngineProbe.new.run) if $PROGRAM_NAME == __FILE__
