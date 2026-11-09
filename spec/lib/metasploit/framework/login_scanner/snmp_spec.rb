require 'spec_helper'
require 'metasploit/framework/login_scanner/snmp'
require 'base64'
require 'json'

RSpec.describe Metasploit::Framework::LoginScanner::SNMP do
  let(:public) { 'public' }
  let(:private) { nil }

  let(:pub_comm) {
    Metasploit::Framework::Credential.new(
        paired: false,
        public: public,
        private: private
    )
  }

  let(:invalid_detail) {
    Metasploit::Framework::Credential.new(
        paired: true,
        public: nil,
        private: nil
    )
  }

  let(:detail_group) {
    [ pub_comm ]
  }

  subject(:snmp_scanner) {
    described_class.new
  }

  describe '#recv_wrapper' do
    let(:socket) { instance_double(TCPSocket) }
    let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'metasploit/framework/login_scanner/snmp/tcp_responses.json'))) }
    let(:first_response) { Base64.strict_decode64(captures.fetch('short').first) }
    let(:second_response) { Base64.strict_decode64(captures.fetch('short').last) }
    let(:long_response) { Base64.strict_decode64(captures.fetch('long').first) }

    before do
      snmp_scanner.protocol = 'tcp'
      snmp_scanner.host = '192.0.2.1'
      snmp_scanner.port = 161
      allow(IO).to receive(:select).and_return([[socket]])
    end

    it 'returns a complete native response' do
      allow(socket).to receive(:recv_nonblock).with(65535).and_return(first_response)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to eq([first_response, '192.0.2.1', 161])
    end

    it 'separates coalesced replies using their BER lengths' do
      expect(socket).to receive(:recv_nonblock).once.with(65535).and_return(first_response + second_response)

      responses = [snmp_scanner.recv_wrapper(socket, 65535, 1), snmp_scanner.recv_wrapper(socket, 65535, 1)]

      expect(responses.map(&:first)).to eq([first_response, second_response])
    end

    it 'reassembles a split short-form header' do
      allow(socket).to receive(:recv_nonblock).and_return(first_response.byteslice(0, 1), first_response.byteslice(1..))

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1).first).to eq(first_response)
    end

    it 'reassembles a split long-form header from a native response' do
      allow(socket).to receive(:recv_nonblock).and_return(long_response.byteslice(0, 2), long_response.byteslice(2, 1), long_response.byteslice(3..))

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1).first).to eq(long_response)
    end

    it 'reassembles a split response body' do
      allow(socket).to receive(:recv_nonblock).and_return(first_response.byteslice(0, 20), first_response.byteslice(20..))

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1).first).to eq(first_response)
    end

    it 'accepts a complete short header before any body bytes arrive' do
      allow(socket).to receive(:recv_nonblock).and_return(first_response.byteslice(0, 2), first_response.byteslice(2..))

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1).first).to eq(first_response)
    end

    it 'retains a partial second reply after delivering the first' do
      allow(socket).to receive(:recv_nonblock).and_return(first_response + second_response.byteslice(0, 10), second_response.byteslice(10..))

      responses = [snmp_scanner.recv_wrapper(socket, 65535, 1), snmp_scanner.recv_wrapper(socket, 65535, 1)]

      expect(responses.map(&:first)).to eq([first_response, second_response])
    end

    it 'preserves an incomplete reply across a receive timeout' do
      allow(IO).to receive(:select).and_return([[socket]], nil, [[socket]])
      allow(socket).to receive(:recv_nonblock).and_return(first_response.byteslice(0, 20), first_response.byteslice(20..))

      responses = [snmp_scanner.recv_wrapper(socket, 65535, 1), snmp_scanner.recv_wrapper(socket, 65535, 1)]

      expect(responses).to eq([nil, [first_response, '192.0.2.1', 161]])
    end

    it 'returns nil for a receive timeout without data' do
      allow(IO).to receive(:select).and_return(nil)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'returns nil when the peer closes the stream' do
      allow(socket).to receive(:recv_nonblock).and_return(''.b)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'rejects indefinite-length framing unsupported by SNMP' do
      allow(socket).to receive(:recv_nonblock).and_return("\x30\x80".b)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'rejects the reserved BER length octet' do
      allow(socket).to receive(:recv_nonblock).and_return("\x30\xff".b)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'rejects an unexpected outer tag' do
      allow(socket).to receive(:recv_nonblock).and_return("\x04\x00".b)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'bounds incomplete message buffering by the maximum receive size' do
      expect(socket).to receive(:recv_nonblock).once.with(32).and_return(long_response.byteslice(0, 32))

      expect(snmp_scanner.recv_wrapper(socket, 32, 1)).to be_nil
    end

    it 'rejects an advertised length exceeding native integer limits' do
      allow(socket).to receive(:recv_nonblock).and_return("\x30\x89\xff\xff\xff\xff\xff\xff\xff\xff\xff".b)

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'does not restart the receive timeout after each fragment' do
      allow(Rex::Stopwatch).to receive(:elapsed_time).and_wrap_original do |_original, &block|
        [block.call, 1.1]
      end
      expect(socket).to receive(:recv_nonblock).once.and_return(first_response.byteslice(0, 20))

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1)).to be_nil
    end

    it 'starts a new connection without incomplete data from the old one' do
      old_socket = instance_double(TCPSocket, close: nil)
      snmp_scanner.sock = old_socket
      allow(IO).to receive(:select).and_return([[old_socket]], nil, [[socket]])
      allow(old_socket).to receive(:recv_nonblock).and_return(first_response.byteslice(0, 20))
      allow(socket).to receive(:recv_nonblock).and_return(second_response)
      allow(Rex::Socket).to receive(:create).and_return(socket)
      snmp_scanner.recv_wrapper(old_socket, 65535, 1)
      snmp_scanner.configure_socket

      expect(snmp_scanner.recv_wrapper(socket, 65535, 1).first).to eq(second_response)
    end

    it 'keeps UDP datagrams intact' do
      snmp_scanner.protocol = 'udp'
      address = ['AF_INET', 161, '192.0.2.1', '192.0.2.1']
      udp_socket = double('UDP socket', timed_recvfrom: [first_response, address])

      expect(snmp_scanner.recv_wrapper(udp_socket, 65535, 1)).to eq([first_response, '192.0.2.1', 161])
    end

    it 'queues both valid versions from an actual coalesced response' do
      snmp_scanner.sock = socket
      snmp_scanner.queued_results = []
      allow(IO).to receive(:select).and_return([[socket]], nil)
      allow(socket).to receive(:recv_nonblock).and_return(first_response + second_response)
      snmp_scanner.process_responses

      expect(snmp_scanner.queued_results.map { |result| result.slice(:community, :snmp_version, :proof) }).to eq([
        { community: 'public', snmp_version: '2c', proof: 'Linux module-target-net-snmp' },
        { community: 'public', snmp_version: '1', proof: 'Linux module-target-net-snmp' }
      ])
    end
  end
end
