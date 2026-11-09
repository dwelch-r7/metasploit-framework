require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'NTP READVAR reply validation' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/ntp/ntp_readvar') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/ntp/readvar_packets.json'))).fetch('captures') }
  let(:capture) { captures.fetch('2') }
  let(:response) { Base64.strict_decode64(capture.fetch('response_base64')) }
  let(:host) { '192.0.2.53' }
  let(:port) { 123 }

  before do
    mod.datastore['RPORT'] = port
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:report_service)
    allow(mod).to receive(:report_vuln)
    mod.scanner_prescan([host])
    # The independent native probe uses sequence 23. Match its actual request
    # rather than changing the captured response to the module's default 0.
    mod.instance_variable_set(:@probe, Rex::Proto::NTP::NTPControl.new.read(Base64.strict_decode64(capture.fetch('request_base64'))))
  end

  %w[2 3 4].each do |version|
    context "with the genuine version #{version} reply" do
      let(:capture) { captures.fetch(version) }

      it 'reports the native properties without padding bytes' do
        mod.scanner_process(response, host, port)
        mod.scanner_postscan([host])

        expected = capture.fetch('properties').values
        expect(mod).to have_received(:report_service).with(hash_including(
          host: host, port: port, proto: 'udp', name: 'ntp', info: satisfy { |info| expected.all? { |value| info.include?(value) } && !info.include?('\\x00') }
        ))
      end

      it 'retains the complete native datagram length for amplification accounting' do
        mod.scanner_process(response, host, port)
        mod.scanner_postscan([host])

        request_size = Base64.strict_decode64(capture.fetch('request_base64')).bytesize
        response_size = capture.fetch('response_bytes')
        expect(mod).to have_received(:print_good).with(include("a #{response_size / request_size}x, #{response_size - request_size}-byte bandwidth amplification"))
      end
    end
  end

  context 'with the genuine unrelated DNS response' do
    let(:capture) { captures.fetch('dns') }
    let(:port) { 53 }

    it 'does not report a parsed DNS error as an NTP service' do
      mod.scanner_process(response, host, port)
      mod.scanner_postscan([host])

      expect(mod).not_to have_received(:report_service)
    end
  end

  {
    'an empty datagram' => ->(_bytes) { ''.b },
    'a one-byte header' => ->(bytes) { bytes.byteslice(0, 1) },
    'an eleven-byte header' => ->(bytes) { bytes.byteslice(0, 11) },
    'a different mode' => ->(bytes) { bytes.dup.tap { |value| value.setbyte(0, (value.getbyte(0) & 0xf8) | 4) } },
    'a different version' => ->(bytes) { bytes.dup.tap { |value| value.setbyte(0, (value.getbyte(0) & 0xc7) | (3 << 3)) } },
    'an echoed request' => ->(bytes) { bytes.dup.tap { |value| value.setbyte(1, value.getbyte(1) & 0x7f) } },
    'an error response' => ->(bytes) { bytes.dup.tap { |value| value.setbyte(1, value.getbyte(1) | 0x40) } },
    'another control operation' => ->(bytes) { bytes.dup.tap { |value| value.setbyte(1, (value.getbyte(1) & 0xe0) | 1) } },
    'a different transaction sequence' => ->(bytes) { bytes.dup.tap { |value| value[2, 2] = [24].pack('n') } },
    'a count larger than the available data' => ->(bytes) { bytes.dup.tap { |value| value[10, 2] = [bytes.bytesize - 11].pack('n') } }
  }.each do |description, mutation|
    it "ignores #{description} without reporting or raising" do
      mod.scanner_process(mutation.call(response), host, port)
      mod.scanner_postscan([host])

      expect(mod).not_to have_received(:report_service)
    end
  end

  it 'retains valid data after an unrelated packet from the same host' do
    mod.scanner_process(Base64.strict_decode64(captures.fetch('dns').fetch('response_base64')), host, port)
    mod.scanner_process(response, host, port)
    mod.scanner_postscan([host])

    expect(mod.results.fetch(host).size).to eq(1)
  end

  it 'accepts a matching empty successful response without claiming amplification' do
    bytes = response.byteslice(0, 12).dup
    bytes[10, 2] = [0].pack('n')
    mod.scanner_process(bytes, host, port)
    mod.scanner_postscan([host])

    expect(mod).not_to have_received(:report_vuln)
  end

  it 'accepts a matching fragment without requiring its offset to be zero' do
    bytes = response.dup
    bytes[8, 2] = [468].pack('n')
    mod.scanner_process(bytes, host, port)

    expect(mod.results.fetch(host).size).to eq(1)
  end

  it 'allows a selected-peer association identifier in a system READVAR response' do
    bytes = response.dup
    bytes[6, 2] = [1].pack('n')
    mod.scanner_process(bytes, host, port)

    expect(mod.results.fetch(host).size).to eq(1)
  end
end
