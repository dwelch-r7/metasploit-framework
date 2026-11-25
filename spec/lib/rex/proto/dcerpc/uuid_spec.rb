# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/dcerpc/uuid'

RSpec.describe Rex::Proto::DCERPC::UUID do
  # The first three UUID fields use little endian order on the DCE/RPC wire.
  let(:uuid) { '00112233-4455-6677-8899-aabbccddeeff' }
  let(:packed_uuid) { "\x33\x22\x11\x00\x55\x44\x77\x66\x88\x99\xaa\xbb\xcc\xdd\xee\xff".b }

  describe '.uuid_unpack' do
    it 'decodes the wire representation' do
      expect(described_class.uuid_unpack(packed_uuid)).to eq(uuid)
    end

    it 'interprets a multibyte string as sixteen bytes' do
      expect(described_class.uuid_unpack("\u00e9" * 8)).to eq('a9c3a9c3-a9c3-a9c3-c3a9-c3a9c3a9c3a9')
    end

    it 'rejects sixteen characters that occupy more than sixteen bytes' do
      expect { described_class.uuid_unpack("\u00e9" * 16) }.to raise_error(ArgumentError)
    end

    it 'rejects a short wire representation' do
      expect { described_class.uuid_unpack(packed_uuid.byteslice(0, 15)) }.to raise_error(ArgumentError)
    end

    it 'rejects a long wire representation' do
      expect { described_class.uuid_unpack(packed_uuid + "\x00") }.to raise_error(ArgumentError)
    end
  end

  describe '.uuid_pack' do
    it 'encodes the text representation' do
      expect(described_class.uuid_pack(uuid)).to eq(packed_uuid)
    end

    it 'round trips a UUID' do
      expect(described_class.uuid_unpack(described_class.uuid_pack(uuid))).to eq(uuid)
    end

    it 'rejects malformed text' do
      expect { described_class.uuid_pack('invalid') }.to raise_error(ArgumentError)
    end
  end

  describe '.uuid_by_name' do
    it 'returns a known service UUID' do
      expect(described_class.uuid_by_name('SAMR')).to eq('12345778-1234-abcd-ef00-0123456789ac')
    end

    it 'returns nil for an unknown service' do
      expect(described_class.uuid_by_name('unknown')).to be_nil
    end
  end

  describe '.vers_by_name' do
    it 'returns nil for an unknown service' do
      expect(described_class.vers_by_name('unknown')).to be_nil
    end
  end

  describe '.vers_to_nums' do
    it 'splits a text version' do
      expect(described_class.vers_to_nums('2.5')).to eq([2, 5])
    end

    it 'splits a numeric version' do
      expect(described_class.vers_to_nums(2)).to eq([2, 0])
    end
  end
end
