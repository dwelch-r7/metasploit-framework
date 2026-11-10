# frozen_string_literal: true

require 'json'
require 'base64'
require 'digest'
require 'open3'

# Uses real vendor JMS and curl controls in one isolated target project.
class LegacyActiveMqNative
  PROVENANCE = JSON.parse(File.read(File.join(__dir__, 'provenance.json'))).freeze
  CLASSPATH = '/opt/module-target:/opt/activemq/lib/*:/opt/activemq/lib/optional/*'
  HTTP_PORT = 8161

  def initialize
    @runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @records = { profiles: {}, commands: [], http: [] }
  end

  private

  def command(service, *arguments)
    argv = @runtime.fetch('compose') + ['exec', '-T', service] + arguments
    output, status = Open3.capture2e(*argv)
    @records[:commands] << { service: service, argv: arguments, exitstatus: status.exitstatus, output_base64: Base64.strict_encode64(output) }
    raise "Native command failed: #{argv.inspect}: #{output}" unless status.success?

    output
  end

  def field(output, name)
    line = output.lines.find { |value| value.start_with?("#{name}=") }
    raise "Native field missing: #{name}" unless line

    line.strip.split('=', 2).last
  end

  def identity(service, version)
    java = command(service, 'java', '-version')
    raise 'Native JDK version mismatch' unless java.include?(PROVENANCE.fetch('runtime').fetch('java_version'))

    data = command(service, 'timeout', '10', 'java', '-Xmx128m', '-cp', CLASSPATH, 'NativeControl', 'jms')
    raise 'Native vendor/version mismatch' unless field(data, 'PROVIDER_NAME') == 'ActiveMQ' && field(data, 'PROVIDER_VERSION') == version
    raise 'Native JMS state mismatch' unless field(data, 'JMS_ROUNDTRIP') == 'matched' && field(data, 'JMS_DESTINATION_REMOVED') == 'true'

    @records[:profiles][service] = { version: version, java: java, jms: data }
  end

  def request(service, method, path, credentials: nil, body: nil, upload: nil, headers: {})
    args = ['curl', '--silent', '--show-error', '--globoff', '--path-as-is', '--max-time', '8', '--include', '--request', method, '--header', 'Expect:', '--write-out', "\nMODULE_TARGET_STATUS=%{http_code}"] # rubocop:disable Style/FormatStringToken
    args += ['--user', credentials] if credentials
    headers.each { |name, value| args += ['--header', "#{name}: #{value}"] }
    args += ['--data-binary', body] unless body.nil?
    args += ['--data-binary', "@#{upload}"] if upload
    output = command(service, *args, "http://127.0.0.1:#{HTTP_PORT}#{path}")
    raw, marker, status = output.rpartition("\nMODULE_TARGET_STATUS=")
    raise 'Native status marker missing' if marker.empty?

    head, separator, data = raw.partition("\r\n\r\n")
    raise 'Native curl headers missing' if separator.empty?

    record = { service: service, method: method, path: path, credentials: credentials, headers: headers, request_body: body, upload: upload, code: Integer(status), response_headers: head, body_base64: Base64.strict_encode64(data), body_sha256: Digest::SHA256.hexdigest(data) }
    @records[:http] << record
    record
  end

  def save_partial(name)
    File.write(File.join(@runtime.fetch('artifacts'), name), JSON.pretty_generate(@records))
  end
end
