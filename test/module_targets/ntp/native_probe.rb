# frozen_string_literal: true

require 'json'
require 'open3'
require 'digest'
require_relative 'wire_probe'

runtime = ENV['MODULE_TARGET_RUNTIME'] && JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
compose = runtime ? runtime.fetch('compose') : ['docker', 'compose', '-p', ARGV.fetch(0), '-f', File.join(__dir__, 'compose.yaml')]
commands = []
profiles = {}
native = lambda do |service, *arguments|
  argv = compose + ['exec', '-T', service, 'timeout', '8', *arguments]
  stdout, stderr, status = Open3.capture3(*argv)
  commands << { argv: argv, stdout: stdout, stderr: stderr, exitstatus: status.exitstatus }
  raise "Native command failed: #{argv.inspect}: #{stdout} #{stderr}" unless status.success?

  stdout + stderr
end
endpoint = lambda do |service, port|
  if runtime
    runtime.fetch('endpoints').fetch(service)
  else
    binding, status = Open3.capture2(*compose, 'port', '--protocol', 'udp', service, port.to_s)
    raise "Missing native UDP binding: #{service}" unless status.success?

    host, public_port = binding.strip.split(':')
    { 'host' => host, 'port' => Integer(public_port) }
  end
end

begin
  %w[open closed].each do |service|
    status = native.call(service, 'cat', '/proc/1/status')
    capabilities = status[/^CapEff:\s*([0-9a-f]+)$/, 1]
    raise "Target has SYS_TIME: #{service}" unless capabilities && (capabilities.to_i(16) & (1 << 25)).zero?

    config = native.call(service, 'cat', "/etc/module-target/#{service}.conf")
    raise "Target clock discipline is not disabled: #{service}" unless config.lines.include?("disable ntp kernel monitor mode7\n")
    raise "Target contains an external clock source: #{service}" if config.match?(/^\s*(?:server|peer|pool|broadcast|manycastclient)\s/)

    package = native.call(service, 'dpkg-query', '-W', '-f=${Version}', 'ntp')
    raise "Unexpected native package: #{package}" unless package == '1:4.2.8p15+dfsg-1ubuntu2'

    profiles[service] = { capabilities: capabilities, config_sha256: Digest::SHA256.hexdigest(config), package: package }
  end
  %w[2 3 4].each do |version|
    text = native.call('open', 'ntpq', '-n', '-c', "ntpversion #{version}", '-c', 'rv', 'open')
    properties = %w[version processor system module_target].to_h do |name|
      match = text.match(/\b#{Regexp.escape(name)}=(?:"([^"]+)"|([^,\r\n]+))/)
      value = match && (match[1] || match[2].strip)
      raise "Missing native #{name}: #{text}" unless value

      [name, value]
    end
    raise 'Native information variable differs' unless properties.fetch('module_target') == 'module-target-native-ntp-proof'

    address = endpoint.call('open', 123)
    wire = NativeNtpWire.query(address.fetch('host'), address.fetch('port'), Integer(version))
    raise "Incomplete actual NTP response: #{wire}" unless wire.fetch('complete')

    properties.each_value { |value| raise "Native wire omitted #{value}" unless wire.fetch('text').include?(value) }
    profiles.fetch('open')[version] = { ntpq: text, properties: properties, wire: wire }
  end
  denied = native.call('open', 'ntpq', '-n', '-c', 'timeout 400', '-c', 'rv', 'closed')
  unless denied.include?('***Request timed out') && !denied.include?('module-target-native-ntp-proof')
    raise "Native remote query was not refused: #{denied}"
  end

  profiles.fetch('closed')[:ntpq] = denied
  address = endpoint.call('closed', 123)
  profiles.fetch('closed')[:wire] = NativeNtpWire.query(address.fetch('host'), address.fetch('port'), 2)
  raise 'Denied server disclosed information' if profiles.fetch('closed').fetch(:wire).fetch('complete')

  dns = native.call('unrelated', 'dig', '+time=2', '+tries=1', '@127.0.0.1', 'module-target.test', 'A', '+short')
  raise "Unrelated native DNS differs: #{dns}" unless dns.strip == '192.0.2.10'

  address = endpoint.call('unrelated', 53)
  profiles['unrelated'] = { dns: dns, wire: NativeNtpWire.query(address.fetch('host'), address.fetch('port'), 2) }
  raise 'Unrelated server returned actual NTP information' if profiles.fetch('unrelated').fetch(:wire).fetch('complete')
ensure
  puts JSON.pretty_generate(profiles: profiles, commands: commands)
end
