# frozen_string_literal: true

require 'json'
require_relative 'wire'

runtime = JSON.parse(File.read(ARGV.fetch(0)))
result = { 'status' => 'native_failed', 'framework_calls' => 0, 'profiles' => {} }
begin
  { 'legacy' => '1.4.39', 'modern' => '1.6.26', 'disabled' => '1.6.26' }.each do |service, version|
    host = runtime.fetch('module_endpoints').fetch(service).fetch('host')
    tcp = NativeMemcachedWire.tcp(host, "version\r\n")
    raise "Native TCP version differs: #{service}" unless tcp == "VERSION #{version}\r\n"

    settings = NativeMemcachedWire.tcp(host, "stats settings\r\n")
    udp_port = service == 'disabled' ? 0 : 11211
    raise "Native UDP configuration differs: #{service}" unless settings.lines.include?("STAT udpport #{udp_port}\r\n")

    probes = %w[version stats].to_h do |command|
      wire = NativeMemcachedWire.udp(host, 11211, "#{command}\r\n", timeout: service == 'disabled' ? 0.4 : 2)
      if service == 'disabled'
        raise 'UDP-disabled server responded' unless wire.fetch('packets').empty? && !wire.fetch('complete')
      else
        raise 'Native UDP response is incomplete' unless wire.fetch('complete')

        valid = command == 'version' ? wire.fetch('text') == tcp : wire.fetch('text').start_with?('STAT pid ') && wire.fetch('text').end_with?("END\r\n")
        raise 'Native UDP response differs' unless valid
      end
      [command, wire]
    end
    closed = NativeMemcachedWire.udp(host, 11212, "version\r\n", timeout: 0.4)
    raise 'Closed UDP port responded' unless closed.fetch('packets').empty?

    result.fetch('profiles')[service] = { 'version' => version, 'tcp_version' => tcp, 'settings' => settings, 'udp' => probes, 'closed' => closed }
  end
  result['status'] = 'native_passed'
rescue StandardError => e
  result['error'] = { 'class' => e.class.name, 'message' => e.message, 'backtrace' => e.backtrace }
ensure
  puts JSON.pretty_generate(result)
end
exit(result['status'] == 'native_passed' ? 0 : 1)
