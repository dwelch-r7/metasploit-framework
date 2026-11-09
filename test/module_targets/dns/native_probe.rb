# frozen_string_literal: true

require 'json'
require 'open3'

runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
commands = []
native = lambda do |service, argv, input = nil|
  output, error, status = Open3.capture3(*runtime.fetch('compose'), 'exec', '-T', service, *argv, stdin_data: input.to_s)
  commands << { service: service, argv: argv, input: input, output: output, error: error, exitstatus: status.exitstatus }
  [output, error, status.exitstatus]
end
dig = lambda do |service, name, type, *extra|
  output, error, code = native.call(service, ['dig', '+time=2', '+tries=1', '+noedns', '+noadflag', '@127.0.0.1', name, type, *extra])
  raise "Native dig failed for #{service} #{name}/#{type}: #{error}" unless code.zero?

  output
end
update = lambda do |service, operation|
  text = "server 127.0.0.1 53\nzone module-target.test.\nupdate #{operation}\nsend\n"
  native.call(service, ['nsupdate', '-t', '3', '-u', '1'], text)
end

begin
  profiles = %w[open closed].to_h do |service|
    output, error, code = native.call(service, ['named-checkconf', '-z', "/etc/bind/#{service}.conf"])
    raise "Native configuration failed: #{error}" unless code.zero? && output.include?('loaded serial')

    version, error, code = native.call(service, ['named', '-v'])
    raise "Native version differs: #{version} #{error}" unless code.zero? && version.start_with?('BIND 9.20.30 ')

    records = [
      ['module-target.test', 'A', ['192.0.2.10']],
      ['module-target.test', 'AAAA', ['2001:db8::10']],
      ['www.module-target.test', 'CNAME', ['module-target.test.']],
      ['module-target.test', 'MX', ['10 mail.module-target.test.']],
      ['module-target.test', 'NS', ['ns.module-target.test.']],
      ['module-target.test', 'TXT', ['"module-target-native-dns-proof"']],
      ['_ldap._tcp.module-target.test', 'SRV', ['0 100 389 ldap.module-target.test.']],
      ['10.2.0.192.in-addr.arpa', 'PTR', ['module-target.test.']],
      ['random-probe.wild.module-target.test', 'A', ['192.0.2.99']]
    ].to_h do |name, type, expected|
      actual = dig.call(service, name, type, '+short').lines.map(&:strip)
      raise "Native #{name}/#{type} differs: #{actual.inspect}" unless actual == expected

      ["#{name}/#{type}", actual]
    end
    %w[+tcp +notcp].each do |transport|
      answer = dig.call(service, 'module-target.test', 'A', transport, '+short').strip
      raise "Native #{service} #{transport} differs" unless answer == '192.0.2.10'
    end
    %w[+tcp +notcp].each do |transport|
      output, error, code = native.call(service, ['dig', '+time=2', '+tries=1', '-6', '@::1', 'module-target.test', 'A', transport, '+short'])
      raise "Native IPv6 #{service} #{transport} differs: #{error}" unless code.zero? && output.strip == '192.0.2.10'
    end
    absent = dig.call(service, 'missing.module-target.test', 'A')
    raise 'Native missing record did not return NXDOMAIN' unless absent.include?('status: NXDOMAIN')

    refused = dig.call(service, 'outside.invalid', 'A')
    raise 'Native authoritative server did not refuse outside recursion' unless refused.include?('status: REFUSED')

    transfer = dig.call(service, 'module-target.test', 'AXFR')
    if service == 'open'
      raise 'Native zone transfer omitted real records' unless transfer.include?('module-target-native-dns-proof') && transfer.include?('www.module-target.test.')
    else
      # dig returns zero even when the server refuses an AXFR: check its result.
      raise 'Native zone transfer was not denied' unless transfer.include?('Transfer failed.') && !transfer.include?('module-target-native-dns-proof')
    end

    marker = 'native-probe.module-target.test'
    raise 'Native update marker already exists' unless dig.call(service, marker, 'A', '+short').empty?

    if service == 'open'
      2.times do
        begin
          output, error, code = update.call(service, "add #{marker}. 60 A 192.0.2.77")
          raise "Native dynamic add failed: #{output} #{error}" unless code.zero?
          raise 'Native dynamic add readback differs' unless dig.call(service, marker, 'A', '+short').strip == '192.0.2.77'
        ensure
          output, error, code = update.call(service, "delete #{marker}. A")
          raise "Native dynamic delete failed: #{output} #{error}" unless code.zero?
        end
        raise 'Native dynamic record remains' unless dig.call(service, marker, 'A', '+short').empty?
      end
    else
      output, error, code = update.call(service, "add #{marker}. 60 A 192.0.2.77")
      raise "Native dynamic update was not refused: #{output} #{error}" unless code != 0 && (output + error).include?('REFUSED')
      raise 'Native denied update changed the zone' unless dig.call(service, marker, 'A', '+short').empty?
    end

    packet = dig.call(service, 'module-target.test', 'TXT', '+stats')
    bytes = packet[/MSG SIZE\s+rcvd:\s+(\d+)/, 1]
    raise 'Native message length is missing' unless bytes

    [service, { version: version.strip, records: records, txt_message_bytes: Integer(bytes, 10) }]
  end
  puts JSON.generate(profiles: profiles, commands: commands)
ensure
  File.write(File.join(runtime.fetch('artifacts'), 'native-dns-commands.json'), JSON.pretty_generate(commands))
end
