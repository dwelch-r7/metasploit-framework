require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'DNS amplification packet accounting' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/dns/dns_amp') }

  # Unmodified native DNS replies and Ethernet lengths from BIND 9.20.30,
  # captured by an independent stdlib resolver/AF_PACKET probe, November 9,
  # 2026. The native probe uses the scanner's fixed DNS ID (0x098d).
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/dns/amp_wire_packets.json'))) }

  before do
    mod.datastore['DOMAINNAME'] = 'module-target.test'
    mod.datastore['QUERYTYPE'] = 'TXT'
    mod.datastore['RPORT'] = 53
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_vuln)
    mod.setup
  end

  { 'ipv4' => '192.0.2.53', 'ipv6' => '2001:db8::53' }.each do |family, host|
    context "with the native #{family} packet" do
      let(:capture) { captures.fetch(family) }
      let(:response) { Base64.strict_decode64(capture.fetch('response_dns_base64')) }
      let(:multiplier) { (capture.fetch('response_frame_bytes').to_f / capture.fetch('request_frame_bytes')).round(2) }
      let(:authority) { family == 'ipv6' ? '[2001:db8::53]:53' : '192.0.2.53:53' }

      it 'reports the captured outgoing Ethernet size' do
        mod.scanner_prescan([host])

        expect(mod).to have_received(:print_status).with(include("Sending #{capture.fetch('request_frame_bytes')} bytes to each host"))
      end

      it 'reports the captured response size and amplification ratio' do
        mod.scanner_process(response, host, 53)

        expect(mod).to have_received(:print_good).with(include("Response is #{capture.fetch('response_frame_bytes')} bytes [#{multiplier}x Amplification]"))
      end

      it 'formats the service authority unambiguously' do
        mod.scanner_process(response, host, 53)

        expect(mod).to have_received(:print_good).with(start_with("#{authority} - "))
      end

      it 'retains DNS-payload bytes and the corrected ratio in vulnerability proof' do
        mod.scanner_process(response, host, 53)

        expect(mod).to have_received(:report_vuln).with(hash_including(
          host: host, port: 53, proto: 'udp', info: "DNS amplification -  #{capture.fetch('response_dns_bytes')} bytes [#{multiplier}x Amplification]"
        ))
      end
    end
  end

  it 'describes both packet sizes in a mixed address-family batch' do
    mod.scanner_prescan(['192.0.2.53', '2001:db8::53'])

    expect(mod).to have_received(:print_status).with(include('Sending 78 bytes to each IPv4 host'))
    expect(mod).to have_received(:print_status).with(include('Sending 98 bytes to each IPv6 host'))
  end

  it 'counts the actual encoded query when the domain has a trailing root dot' do
    mod.datastore['DOMAINNAME'] = 'module-target.test.'
    mod.setup
    mod.scanner_prescan(['192.0.2.53'])

    expect(mod).to have_received(:print_status).with(include('Sending 78 bytes to each host'))
  end

  it 'uses IPv4 wire overhead for an IPv4-mapped IPv6 address' do
    mod.scanner_prescan(['::ffff:192.0.2.53'])

    expect(mod).to have_received(:print_status).with(include('Sending 78 bytes to each host'))
  end

  it 'keeps the existing spoofed IPv4 dispatch without sending traffic' do
    mod.datastore['SRCIP'] = '192.0.2.99'
    mod.datastore['NUM_REQUESTS'] = 1
    allow(mod).to receive(:scanner_spoof_send)
    allow(mod).to receive(:scanner_send)
    mod.scan_host('192.0.2.53')

    expect(mod).to have_received(:scanner_spoof_send).with(mod.instance_variable_get(:@msearch_probe), '192.0.2.53', 53, '192.0.2.99', 1)
    expect(mod).not_to have_received(:scanner_send)
  end

  it 'ignores a reply for a different DNS transaction' do
    response = Base64.strict_decode64(captures.fetch('ipv4').fetch('response_dns_base64'))
    response[0, 2] = "\x12\x34"
    mod.scanner_process(response, '192.0.2.53', 53)

    expect(mod).not_to have_received(:report_vuln)
    expect(mod).not_to have_received(:print_good)
  end
end
