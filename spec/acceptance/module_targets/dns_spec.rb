require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Authoritative DNS module targets' do
  include_context 'module target'

  let_it_be(:native_dns) do
    argv = [RbConfig.ruby, File.expand_path('test/module_targets/dns/native_probe.rb')]
    output, error, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-dns-preflight.json'), output)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-dns-preflight-command.json'), JSON.pretty_generate(argv: argv, error: error, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), error
    JSON.parse(output).fetch('profiles')
  end

  let_it_be(:network_addresses) do
    identifiers, status = Open3.capture2(*target_runtime.fetch('compose'), 'ps', '--quiet')
    expect(status.success?).to be(true)
    output, status = Open3.capture2('docker', 'inspect', *identifiers.split)
    expect(status.success?).to be(true)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-network-inspect.json'), output)
    JSON.parse(output).to_h do |container|
      network = container.fetch('NetworkSettings').fetch('Networks').values.fetch(0)
      service = container.fetch('Config').fetch('Labels').fetch('com.docker.compose.service')
      expect(network.fetch('GlobalIPv6Address')).not_to be_empty
      [service, { 'ipv4' => network.fetch('IPAddress'), 'ipv6' => network.fetch('GlobalIPv6Address') }]
    end
  end

  let_it_be(:native_packets) do
    %w[ipv4 ipv6].to_h do |family|
      script = File.read('test/module_targets/dns/native_packet_probe.rb')
      capture = JSON.parse(target_exec('framework', 'ruby', '-e', script, network_addresses.fetch('open').fetch(family)))
      expect(capture.fetch('family')).to eq(family)
      expect(capture.fetch('response_dns_bytes')).to eq(native_dns.fetch('open').fetch('txt_message_bytes'))
      File.write(File.join(target_runtime.fetch('artifacts'), "native-#{family}-wire.json"), JSON.pretty_generate(capture))
      [family, capture]
    end
  end

  before(:all) do
    native_dns
    native_packets
    # Independent native queries cross the bridge over IPv6 as well as loopback.
    %w[+tcp +notcp].each do |transport|
      output = target_exec('closed', 'dig', '+time=2', '+tries=1', '-6', "@#{network_addresses.fetch('open').fetch('ipv6')}", 'module-target.test', 'A', transport, '+short')
      expect(output.strip).to eq('192.0.2.10')
    end
  end

  it 'enumerates real IPv4 UDP zone data and specialist SRV records' do
    output = run_enum('open', 'ENUM_AXFR' => true, 'ENUM_A' => true, 'ENUM_MX' => true, 'ENUM_NS' => true, 'ENUM_SOA' => true, 'ENUM_TXT' => true, 'ENUM_SRV' => true)
    expect(output).to include('module-target.test Zone Transfer:', '192.0.2.10', 'module-target-native-dns-proof')
    expect(output).to include('module-target.test MX: mail.module-target.test', 'module-target.test NS: ns.module-target.test', 'module-target.test SOA: ns.module-target.test')
    expect(output).to include('_ldap._tcp.module-target.test SRV:', ':port=>389', ':priority=>0')
  end

  it 'enumerates ordinary records over IPv4 TCP' do
    output = run_enum('open', 'TCP_DNS' => true, 'ENUM_MX' => true, 'ENUM_NS' => true, 'ENUM_SOA' => true, 'ENUM_TXT' => true)
    expect(output).to include('module-target-native-dns-proof', 'MX: mail.module-target.test', 'NS: ns.module-target.test', 'SOA: ns.module-target.test')
  end

  it 'distinguishes an actual CNAME from a missing name on successive runs' do
    output = run_enum('open', 'DOMAIN' => 'www.module-target.test', 'ENUM_CNAME' => true)
    expect(output).to include('www.module-target.test CNAME: module-target.test')
    output = run_enum('open', 'DOMAIN' => 'missing.module-target.test', 'ENUM_CNAME' => true)
    expect(output).not_to include(' CNAME: ')
  end

  it 'does not print a zone transfer when the native server refuses it' do
    original = query_log('closed')
    output = run_enum('closed', { 'ENUM_AXFR' => true }, allow_errors: true)
    expect(output).to include('Attempting DNS AXFR for module-target.test')
    expect(output).not_to include('Zone Transfer:', 'module-target-native-dns-proof')
    fresh = query_log('closed').delete_prefix(original)
    expect(fresh.lines.any? { |line| line.include?(network_addresses.fetch('framework').fetch('ipv4')) && line.include?('module-target.test IN AXFR') }).to be(true), fresh
  end

  it 'brute forces only a short controlled wordlist' do
    output = run_enum('open', 'ENUM_BRT' => true, 'WORDLIST' => 'test/module_targets/dns/wordlist.txt', 'THREADS' => 2)
    expect(output).to include('www.module-target.test A: 192.0.2.10', 'mail.module-target.test A: 192.0.2.25')
    expect(output).not_to include('missing.module-target.test A:')
  end

  it 'stops wildcard brute force and permits it when explicitly requested' do
    original = query_log('open')
    options = { 'DOMAIN' => 'wild.module-target.test', 'ENUM_BRT' => true, 'WORDLIST' => 'test/module_targets/dns/wordlist.txt', 'STOP_WLDCRD' => true }
    output = run_enum('open', options)
    expect(output).to include('dns wildcard is enable OR fake dns server')
    fresh = query_log('open').delete_prefix(original)
    %w[www mail missing].each { |name| expect(fresh).not_to include("#{name}.wild.module-target.test IN A") }
    output = run_enum('open', options.merge('STOP_WLDCRD' => false))
    %w[www mail missing].each { |name| expect(output).to include("#{name}.wild.module-target.test A: 192.0.2.99") }
  end

  it 'enumerates a real PTR and omits a missing PTR in a two-address range' do
    output = run_enum('open', 'ENUM_RVL' => true, 'IPRANGE' => '192.0.2.10/31', 'THREADS' => 2, 'DnsClientRVLExistingOnly' => false)
    expect(output).to include('192.0.2.10: PTR: module-target.test')
    expect(output).not_to include('192.0.2.11: PTR:')
  end

  [false, true].each do |tcp|
    it "enumerates real records over IPv6 #{tcp ? 'TCP' : 'UDP'}" do
      output = run_enum('open', 'NS' => network_addresses.fetch('open').fetch('ipv6'), 'TCP_DNS' => tcp, 'ENUM_MX' => true, 'ENUM_NS' => true, 'ENUM_TXT' => true)
      expect(output).to include('module-target-native-dns-proof', 'MX: mail.module-target.test', 'NS: ns.module-target.test')
    end
  end

  {
    'A' => ['IP', '192.0.2.77', '192.0.2.78'],
    'AAAA' => ['IP', '2001:db8::77', '2001:db8::78'],
    'CNAME' => ['VALUE', 'mail.module-target.test.', 'ldap.module-target.test.'],
    'TXT' => ['VALUE', 'module-target-first', 'module-target-second']
  }.each do |type, (option, first, second)|
    it "adds, updates and deletes #{type} twice with exact native readback" do
      exercise_updates(type, option, first, second)
    end

    it "does not add #{type} through denied update policy" do
      name = "module-denied-#{type.downcase}"
      expect(native_record('closed', name, type)).to be_empty
      output = run_update('closed', 'ADD', type, name, option => first)
      expect(output).to include("Cannot add #{name}.module-target.test")
      expect(output).not_to include('has been added!')
      expect(native_record('closed', name, type)).to be_empty
    end
  end

  it 'refuses changes and deletion of an existing protected record' do
    expect(native_record('closed', 'mail', 'A')).to eq(['192.0.2.25'])
    %w[UPDATE DELETE].each do |action|
      output = run_update('closed', action, 'A', 'mail', 'IP' => '192.0.2.88')
      expect(output).to include('Cannot delete mail.module-target.test')
      expect(output).not_to include('has been deleted!', 'has been added!')
      expect(native_record('closed', 'mail', 'A')).to eq(['192.0.2.25'])
    end
  end

  %w[ipv4 ipv6].each do |family|
    it "performs forced update actions twice with an explicit #{family} source" do
      exercise_updates('A', 'IP', '192.0.2.81', '192.0.2.82', family: family, source: network_addresses.fetch('framework').fetch(family))
    end

    it "measures one unspoofed #{family} response against actual captured wire lengths" do
      packet = native_packets.fetch(family)
      output = run_amp('module-target.test', family)
      multiplier = (packet.fetch('response_frame_bytes').to_f / packet.fetch('request_frame_bytes')).round(2)
      expect(output).to include("Response is #{packet.fetch('response_frame_bytes')} bytes [#{multiplier}x Amplification]")
    end

    it "reports native recursion refusal over #{family} without an amplification result" do
      output = run_amp('outside.invalid', family)
      expect(output).to include('Recursion not allowed')
      expect(output).not_to include('x Amplification]')
    end
  end

  it 'accounts for a mixed IPv4/IPv6 batch using each actual response family' do
    hosts = File.join(target_runtime.fetch('artifacts'), 'mixed-rhosts.txt')
    File.write(hosts, network_addresses.fetch('open').values_at('ipv4', 'ipv6').join("\n") + "\n")
    output = run_target_module('auxiliary/scanner/dns/dns_amp', 'open', {
      'RHOSTS' => "file:#{hosts}", 'DOMAINNAME' => 'module-target.test', 'QUERYTYPE' => 'TXT',
      'NUM_REQUESTS' => 1, 'ScannerRecvWindow' => 1, 'THREADS' => 1
    })
    native_packets.each_value do |packet|
      multiplier = (packet.fetch('response_frame_bytes').to_f / packet.fetch('request_frame_bytes')).round(2)
      expect(output).to include("Response is #{packet.fetch('response_frame_bytes')} bytes [#{multiplier}x Amplification]")
    end
  end

  %w[ipv4 ipv6].each do |family|
    it "measures a fully qualified trailing-dot query over #{family}" do
      script = File.read('test/module_targets/dns/native_packet_probe.rb')
      packet = JSON.parse(target_exec('framework', 'ruby', '-e', script, network_addresses.fetch('open').fetch(family), 'module-target.test.'))
      File.write(File.join(target_runtime.fetch('artifacts'), "native-fqdn-#{family}-wire.json"), JSON.pretty_generate(packet))
      output = run_amp('module-target.test.', family)
      multiplier = (packet.fetch('response_frame_bytes').to_f / packet.fetch('request_frame_bytes')).round(2)
      expect(output).to include("Response is #{packet.fetch('response_frame_bytes')} bytes [#{multiplier}x Amplification]")
    end
  end

  it 'uses actual IPv4 framing for an IPv4-mapped IPv6 endpoint' do
    address = "::ffff:#{network_addresses.fetch('open').fetch('ipv4')}"
    script = File.read('test/module_targets/dns/native_packet_probe.rb')
    packet = JSON.parse(target_exec('framework', 'ruby', '-e', script, address))
    expect(packet.fetch('family')).to eq('ipv4')
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-mapped-wire.json'), JSON.pretty_generate(packet))
    output = run_target_module('auxiliary/scanner/dns/dns_amp', 'open', {
      'RHOSTS' => address, 'DOMAINNAME' => 'module-target.test', 'QUERYTYPE' => 'TXT',
      'NUM_REQUESTS' => 1, 'ScannerRecvWindow' => 1, 'THREADS' => 1
    })
    multiplier = (packet.fetch('response_frame_bytes').to_f / packet.fetch('request_frame_bytes')).round(2)
    expect(output).to include("Response is #{packet.fetch('response_frame_bytes')} bytes [#{multiplier}x Amplification]")
  end

  def run_enum(service, options = {}, allow_errors: false, **datastore_options)
    defaults = %w[AXFR BRT A CNAME MX NS SOA TXT RVL TLD SRV].to_h { |name| ["ENUM_#{name}", false] }
    defaults.merge!('DOMAIN' => 'module-target.test', 'NS' => network_addresses.fetch(service).fetch('ipv4'), 'TIMEOUT' => 2, 'RETRY' => 1, 'RETRY_INTERVAL' => 1, 'RPORT' => 53)
    run_target_module('auxiliary/gather/enum_dns', service, defaults.merge(options).merge(datastore_options), allow_errors: allow_errors, endpoint_options: {})
  end

  def run_update(service, action, type, name, options)
    values = { 'RHOST' => network_addresses.fetch(service).fetch('ipv4'), 'DOMAIN' => 'module-target.test', 'HOSTNAME' => name, 'TYPE' => type, 'ACTION' => action, 'CHOST' => nil }.merge(options)
    run_target_module('auxiliary/admin/dns/dyn_dns_update', service, values, allow_errors: true, endpoint_options: {})
  end

  def run_amp(domain, family)
    # Omit SRCIP: an explicit blank value still selects the spoofed branch.
    run_target_module('auxiliary/scanner/dns/dns_amp', 'open', {
      'RHOSTS' => network_addresses.fetch('open').fetch(family), 'DOMAINNAME' => domain, 'QUERYTYPE' => 'TXT',
      'NUM_REQUESTS' => 1, 'ScannerRecvWindow' => 1, 'THREADS' => 1
    })
  end

  def native_record(service, name, type)
    lines = target_exec(service, 'dig', '+time=2', '+tries=1', '+short', '@127.0.0.1', "#{name}.module-target.test", type).lines.map(&:strip)
    type == 'TXT' ? lines.map { |line| JSON.parse(line) } : lines
  end

  def query_log(service)
    output, status = Open3.capture2(*target_runtime.fetch('compose'), 'logs', '--no-color', service)
    expect(status.success?).to be(true)
    output
  end

  def exercise_updates(type, option, first, second, family: 'ipv4', source: nil)
    name = "module-#{type.downcase}-#{source ? family : 'default'}"
    values = { option => first, 'RHOST' => network_addresses.fetch('open').fetch(family), 'CHOST' => source }
    2.times do
      expect(native_record('open', name, type)).to be_empty
      begin
        output = run_update('open', 'ADD', type, name, values)
        expect(output).to include('has been added!')
        expect(native_record('open', name, type)).to eq([first])
        duplicate = run_update('open', 'ADD', type, name, values)
        expect(duplicate).to include(source ? "Cannot add #{name}.module-target.test" : 'Record already exists')
        expect(duplicate).not_to include('has been added!')
        expect(native_record('open', name, type)).to eq([first])
        output = run_update('open', 'UPDATE', type, name, values.merge(option => second))
        expect(output).to include('has been added!')
        expect(native_record('open', name, type)).to eq([second])
        output = run_update('open', 'DELETE', type, name, values.merge(option => second))
        expect(output).to include('has been deleted!')
        expect(native_record('open', name, type)).to be_empty
        absent = run_update('open', 'DELETE', type, name, values)
        expect(absent).to include(source ? "Cannot delete #{name}.module-target.test" : 'Record does not exist, not deleting')
        expect(absent).not_to include('has been deleted!')
        expect(native_record('open', name, type)).to be_empty
      ensure
        # Emergency fixture cleanup cannot make a failed module deletion pass.
        script = "server 127.0.0.1 53\nzone module-target.test.\nupdate delete #{name}.module-target.test. #{type}\nsend\n"
        target_exec('open', 'sh', '-c', 'printf "%s" "$1" | nsupdate -t 3 -u 1', 'native-cleanup', script)
      end
    end
  end
end
