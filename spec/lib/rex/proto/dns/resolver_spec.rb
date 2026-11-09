# frozen_string_literal: true

require 'spec_helper'
require 'rex'
require 'rex/proto/dns/resolver'
require 'rex/socket/udp'
require 'base64'
require 'stringio'

RSpec.describe Rex::Proto::DNS::Resolver do
  subject(:resolver) { described_class.new(config_file: nil, nameservers: [], log_file: File::NULL) }

  let(:udp_answer) { ['answer', ['AF_INET', 53, '192.0.2.53', '192.0.2.53']] }

  let(:socket) do
    double(
      'Rex::Socket::Udp',
      close: nil,
      closed?: false,
      timed_recvfrom: udp_answer,
      write: nil
    )
  end

  describe '#send_udp' do
    before do
      allow(Rex::Socket::Udp).to receive(:create).and_return(socket)
    end

    it 'closes the UDP socket after receiving an answer' do
      expect(socket).to receive(:close)

      answer = resolver.send_udp(nil, 'query', [['192.0.2.53', {}]])

      expect(answer).to eq(udp_answer)
    end

    it 'closes the UDP socket after a timeout' do
      allow(socket).to receive(:timed_recvfrom).and_raise(Timeout::Error)
      expect(socket).to receive(:close)

      expect(resolver.send_udp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
    end
  end
  # Native one-message transfer contains both opening and closing SOAs. Stream
  # fragmentation/EOF variants below are synthetic boundaries of that capture.
  let(:axfr_capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/proto/dns/bind_9_20_30_axfr.json'))) }
  let(:axfr_body) { Base64.strict_decode64(axfr_capture.fetch('frames').first.fetch('body_base64')) }
  let(:axfr_frame) { [axfr_body.bytesize].pack('n') + axfr_body }
  let(:tcp_data) { axfr_frame }
  let(:maximum_read) { 65_535 }
  let(:tcp_stream) { StringIO.new(tcp_data) }
  let(:tcp_socket) { double('Rex::Socket::Tcp', write: nil, close: nil) }

  def stub_tcp_stream
    allow(Rex::Socket::Tcp).to receive(:create).and_return(tcp_socket)
    allow(tcp_socket).to receive(:recv) { |length| tcp_stream.read([length, maximum_read].min) }
    allow(tcp_socket).to receive(:recvfrom) { |length| [tcp_stream.read([length, maximum_read].min), []] }
  end

  describe '#axfr' do
    before do
      resolver.nameservers = ['192.0.2.53']
      stub_tcp_stream
    end

    it 'recognizes both SOAs in a native single-message zone transfer' do
      expect(resolver.axfr('module-target.test').flat_map(&:answer).length).to eq(13)
    end

    it 'stops at the closing SOA instead of waiting for persistent TCP to close' do
      resolver.axfr('module-target.test')

      expect(tcp_socket).to have_received(:recv).with(2).once
    end

    it 'preserves the array of Net::DNS packets return contract' do
      expect(resolver.axfr('module-target.test')).to all(be_a(Net::DNS::Packet))
    end

    context 'when the final message contains data before its closing SOA' do
      let(:tcp_data) do
        records = Dnsruby::Message.decode(axfr_body).answer
        framed_answers(records.first(1)) + framed_answers(records.drop(1))
      end

      it 'retains all records across both DNS messages' do
        expect(resolver.axfr('module-target.test').flat_map(&:answer).length).to eq(13)
      end
    end

    context 'when the server sends a closing-only message' do
      let(:tcp_data) do
        records = Dnsruby::Message.decode(axfr_body).answer
        framed_answers(records[0...-1]) + framed_answers(records.last(1))
      end

      it 'preserves the legacy exclusion of that closing-only packet' do
        expect(resolver.axfr('module-target.test').length).to eq(1)
      end
    end

    context 'when the server refuses the transfer' do
      let(:tcp_data) do
        frame = axfr_capture.fetch('refused_frame')
        Base64.strict_decode64(frame.fetch('prefix_base64')) + Base64.strict_decode64(frame.fetch('body_base64'))
      end

      it 'retains the existing nil refusal result' do
        expect(resolver.axfr('module-target.test')).to be_nil
      end
    end

    context 'when the server closes without a transfer' do
      let(:tcp_data) { '' }

      it 'reports no response rather than a parser exception' do
        expect { resolver.axfr('module-target.test') }.to raise_error(NoResponseError)
      end
    end

    it 'closes its owned socket after a complete transfer' do
      expect(tcp_socket).to receive(:close)

      resolver.axfr('module-target.test')
    end
  end

  describe '#send_tcp' do
    before { stub_tcp_stream }

    it 'returns a complete native frame and sender metadata for an ordinary query' do
      expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to eq([axfr_body, ['', 53, '192.0.2.53', '192.0.2.53']])
    end

    context 'when the length prefix and body arrive one byte at a time' do
      let(:maximum_read) { 1 }

      it 'reassembles the complete native DNS message' do
        expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])&.first).to eq(axfr_body)
      end
    end

    context 'when multiple framed messages arrive on the connection' do
      let(:tcp_data) { axfr_frame + axfr_frame }

      it 'yields each complete frame and handles a clean nil EOF' do
        messages = []
        resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]]) { |answer| messages << answer.first }

        expect(messages).to eq([axfr_body, axfr_body])
      end
    end

    context 'when the peer closes before sending a prefix' do
      let(:tcp_data) { '' }

      it 'returns the existing failure sentinel' do
        expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
      end
    end

    context 'when the peer sends only part of the length prefix' do
      let(:tcp_data) { axfr_frame.byteslice(0, 1) }

      it 'does not decode an incomplete DNS message' do
        expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
      end
    end

    context 'when the peer sends only part of the message body' do
      let(:tcp_data) { axfr_frame.byteslice(0, 40) }

      it 'does not expose a partial message as a response' do
        expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
      end
    end

    context 'when the peer announces an empty message' do
      let(:tcp_data) { "\x00\x00" }

      it 'does not throw an uncaught nameserver control symbol' do
        expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
      end
    end

    it 'does not swallow an IO error raised by its response consumer' do
      expect do
        resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]]) { raise IOError, 'Consumer failed to persist the response' }
      end.to raise_error(IOError, 'Consumer failed to persist the response')
    end

    it 'closes its socket after a read timeout' do
      allow(tcp_socket).to receive(:recv).and_raise(Timeout::Error)
      expect(tcp_socket).to receive(:close)

      expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
    end

    it 'closes its socket after a connection reset' do
      allow(tcp_socket).to receive(:recv).and_raise(Errno::ECONNRESET)
      expect(tcp_socket).to receive(:close)

      expect(resolver.send_tcp(nil, 'query', [['192.0.2.53', {}]])).to be_nil
    end
  end

  def framed_answers(records)
    packet = Dnsruby::Message.decode(axfr_body)
    packet.answer.replace(records)
    packet.update_counts
    body = packet.encode(true)
    [body.bytesize].pack('n') + body
  end
end
