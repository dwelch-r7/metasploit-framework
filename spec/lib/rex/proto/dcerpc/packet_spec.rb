require 'spec_helper'
require 'timeout'
require 'rex/proto/dcerpc/uuid'
require 'rex/proto/dcerpc/packet'

RSpec.describe Rex::Proto::DCERPC::Packet do
  let(:uuid) { '12345778-1234-abcd-ef00-0123456789ac' }

  describe '.make_bind' do
    # Captured from the original builder and checked against its DCE/RPC fields:
    # 72-byte bind PDU, SAMR 1.0, NDR transfer syntax 2.0, little endian UUIDs.
    let(:wire_hex) { '05000b03100000004800000000000000d016d016000000000100000000000100785734123412cdabef000123456789ac01000000045d888aeb1cc9119fe808002b10486002000000' }

    it 'encodes the expected wire fields through the UUID helper' do
      expect(described_class.make_bind(uuid, '1.0')).to eq([[wire_hex].pack('H*'), 0])
    end

    it 'accepts a numeric version' do
      expect(described_class.make_bind(uuid, 1.0)).to eq(described_class.make_bind(uuid, '1.0'))
    end

    it 'accepts a textual transfer syntax as well as the default binary UUID' do
      expect(described_class.make_bind(uuid, '1.0', '8a885d04-1ceb-11c9-9fe8-08002b104860')).to eq(described_class.make_bind(uuid, '1.0'))
    end

    it 'rejects an invalid interface UUID' do
      expect { described_class.make_bind('invalid', '1.0') }.to raise_error(ArgumentError)
    end
  end

  describe '.make_bind_fake_multi' do
    it 'encodes the real interface between deterministic fake contexts' do
      allow(Rex::Text).to receive(:rand_text).with(16).and_return('x' * 16)
      allow(described_class).to receive(:rand).and_return(1)
      packet, context = described_class.make_bind_fake_multi(uuid, '1.0', 1, 1)
      expect([packet.bytesize, packet.unpack1('v', offset: 8), context, packet.byteslice(76, 16)]).to eq([160, 160, 1, Rex::Proto::DCERPC::UUID.uuid_pack(uuid)])
    end
  end

  describe '.make_alter_context' do
    it 'uses an alter-context header with the same interface and syntax fields' do
      bind = described_class.make_bind(uuid, '1.0').first
      expected = bind.dup
      expected.setbyte(2, 14)
      expect(described_class.make_alter_context(uuid, '1.0')).to eq(expected)
    end
  end

  describe '.make_request' do
    it 'encodes a complete request with its context and operation number' do
      expect(described_class.make_request(7, 'abc', 3, 2)).to eq([['05000003100000001b000000000000000300000002000700616263'].pack('H*')])
    end

    it 'emits an empty request with both fragment flags' do
      packet = described_class.make_request.first
      expect([packet.bytesize, packet.getbyte(3)]).to eq([24, 3])
    end

    it 'sets first, middle and last flags while preserving the payload' do
      packets = described_class.make_request(7, 'abcdefg', 3, 2)
      expect([packets.map { |packet| packet.getbyte(3) }, packets.map { |packet| packet.byteslice(24..) }.join]).to eq([[1, 0, 2], 'abcdefg'])
    end

    it 'caps fragments at 4000 payload bytes' do
      expect(described_class.make_request(7, 'x' * 4001, 5000).map(&:bytesize)).to eq([4024, 25])
    end

    it 'includes a binary object UUID and sets the object flag' do
      packet = described_class.make_request(7, 'abc', 3, 2, uuid).first
      expect([packet.getbyte(3), packet.byteslice(24, 16), packet.byteslice(40..)]).to eq([0x83, Rex::Proto::DCERPC::UUID.uuid_pack(uuid), 'abc'])
    end

    it 'counts multibyte input as wire bytes' do
      packets = described_class.make_request(7, "\u00e9" * 2, 3)
      expect([packets.map(&:bytesize), packets.map { |packet| packet.byteslice(24..) }.join]).to eq([[27, 25], ("\u00e9" * 2).b])
    end

    it 'uses the byte length when the fragment size is omitted' do
      expect(described_class.make_request(7, "\u00e9" * 2).map(&:bytesize)).to eq([28])
    end

    it 'preserves arbitrary binary payload bytes' do
      payload = "\x00\xff\x80\x7f".b
      expect(described_class.make_request(7, payload, 2).map { |packet| packet.byteslice(24..) }.join).to eq(payload)
    end

    it 'keeps an exact 4000-byte payload in one fragment' do
      expect(described_class.make_request(7, 'x' * 4000).map(&:bytesize)).to eq([4024])
    end

    it 'continues to allow an empty request with a zero fragment size' do
      expect(described_class.make_request(7, '', 0).map(&:bytesize)).to eq([24])
    end

    it 'rejects a zero fragment size for nonempty data instead of looping' do
      expect { Timeout.timeout(1) { described_class.make_request(7, 'abc', 0) } }.to raise_error(ArgumentError)
    end

    it 'rejects a negative fragment size for nonempty data' do
      expect { Timeout.timeout(1) { described_class.make_request(7, 'abc', -1) } }.to raise_error(ArgumentError)
    end
  end

  describe '.make_request_chunk' do
    it 'counts a directly supplied multibyte payload as bytes' do
      packet = described_class.make_request_chunk(3, 7, "\u00e9")
      expect([packet.bytesize, packet.unpack1('v', offset: 8), packet.byteslice(24..)]).to eq([26, 26, "\u00e9".b])
    end
  end
end
