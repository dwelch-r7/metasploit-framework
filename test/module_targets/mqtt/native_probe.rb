# frozen_string_literal: true

require 'json'
require 'open3'

runtime_path = ENV['MODULE_TARGET_RUNTIME']
compose = if runtime_path
            JSON.parse(File.read(runtime_path)).fetch('compose')
          else
            ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
          end
commands = []
profiles = {}
run = lambda do |service, *arguments|
  stdout, stderr, status = Open3.capture3(*compose, 'exec', '-T', service, *arguments)
  commands << { service: service, argv: arguments, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  [stdout, stderr, status.exitstatus]
end
begin
  %w[open auth prefix tls].each do |service|
    version, error, code = run.call(service, 'mosquitto', '-h')
    raise "Missing native Mosquitto: #{error}" unless code.zero? && version.include?('mosquitto version 2.0.22')

    port = service == 'tls' ? '8883' : '1883'
    base = ['-h', '127.0.0.1', '-p', port, '-V', 'mqttv311']
    base += ['--cafile', '/mosquitto/config/certificates/server.crt'] if service == 'tls'
    credentials = %w[auth tls].include?(service) ? ['-u', 'lab-mqtt-user', '-P', 'lab-mqtt-password'] : []
    flags = base + credentials
    report = { port: port.to_i, authenticated: !credentials.empty?, tls: service == 'tls' }
    if report[:authenticated]
      [['anonymous', []], ['wrong', ['-u', 'lab-mqtt-user', '-P', 'wrong-password']]].each do |label, rejected|
        stdout, stderr, code = run.call(service, 'mosquitto_pub', *base, *rejected, '-i', 'module-target-native-denied', '-t', 'module-target/proof', '-m', 'denied', '-d')
        raise "#{service} #{label} unexpectedly accepted: #{stdout} #{stderr}" unless code == 5 && stdout.include?('received CONNACK (5)')
      end
    elsif service == 'prefix'
      stdout, stderr, code = run.call(service, 'mosquitto_pub', *base, '-i', 'wrong-native', '-t', 'module-target/proof', '-m', 'denied', '-d')
      raise "Client ID prefix not enforced: #{stdout} #{stderr}" unless code == 5 && stdout.include?('received CONNACK (5)')
    end
    # Framework's current packet gem defaults to MQTT3.1 with a 23-byte ID limit.
    legacy_flags = flags.map { |argument| argument == 'mqttv311' ? 'mqttv31' : argument }
    stdout, stderr, code = run.call(service, 'mosquitto_pub', *legacy_flags, '-i', 'module-target-v31', '-t', 'module-target/version-proof', '-m', 'native-version-proof', '-q', '1', '-d')
    raise "Native MQTT3.1 CONNECT failed: #{stdout} #{stderr}" unless code.zero? && stdout.include?('received CONNACK (0)')

    2.times do
      marker = "module-target-native-#{service}"
      stdout, stderr, code = run.call(service, 'mosquitto_pub', *flags, '-i', 'module-target-native-pub', '-t', 'module-target/proof', '-m', marker, '-r', '-q', '1', '-d')
      raise "Native publish failed: #{stdout} #{stderr}" unless code.zero? && stdout.include?('received CONNACK (0)')

      stdout, stderr, code = run.call(service, 'mosquitto_sub', *flags, '-i', 'module-target-native-sub', '-t', 'module-target/proof', '-C', '1', '-W', '3')
      raise "Native retained readback differs: #{stdout} #{stderr}" unless code.zero? && stdout.strip == marker

      stdout, stderr, code = run.call(service, 'mosquitto_pub', *flags, '-i', 'module-target-native-delete', '-t', 'module-target/proof', '-n', '-r', '-q', '1')
      raise "Native retained deletion failed: #{stdout} #{stderr}" unless code.zero?

      stdout, stderr, code = run.call(service, 'mosquitto_sub', *flags, '-i', 'module-target-native-empty', '-t', 'module-target/proof', '-C', '1', '-W', '1')
      raise "Native retained deletion left data: #{stdout} #{stderr}" unless code == 27 && stdout.empty?
    end
    profiles[service] = report
  end
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands)
end
