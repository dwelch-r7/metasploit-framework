require 'spec_helper'
require 'rex/proto/redis/base'

RSpec.describe Rex::Proto::Redis::Base do
  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/redis/protocol_6_0_11.json', __dir__)
    JSON.parse(File.read(path))
  end

  describe '.serialize_command' do
    [0, 1, 2].each do |index|
      it "matches actual stock redis-cli AUTH packet #{index + 1}" do
        capture = captures.fetch('requests').fetch(index)
        arguments = ['AUTH', capture.fetch('username'), capture.fetch('password')].compact

        expect(described_class.serialize_command(arguments)).to eq(Base64.strict_decode64(capture.fetch('packets_base64').first))
      end
    end

    it 'matches the independently captured stock PING request' do
      capture = captures.fetch('requests').first

      expect(described_class.serialize_command(['PING'])).to eq(Base64.strict_decode64(capture.fetch('packets_base64').last))
    end

    it 'combines UTF-8 and binary operands without changing their bytes' do
      password = captures.fetch('requests').fetch(1).fetch('password')
      binary = "\x00\xff\r\n\t".b
      expected = "*3\r\n$3\r\nSET\r\n$12\r\n".b + password.b + "\r\n$5\r\n".b + binary + "\r\n".b

      expect(described_class.serialize_command(['SET', password, binary])).to eq(expected)
    end

    it 'returns a binary-encoded packet' do
      expect(described_class.serialize_command(['PING']).encoding).to eq(Encoding::BINARY)
    end

    it 'retains a zero-length operand as a bulk string' do
      expect(described_class.serialize_command([''])).to eq("*1\r\n$0\r\n\r\n".b)
    end

    it 'does not mutate frozen operands or their encodings' do
      password = captures.fetch('requests').fetch(1).fetch('password').freeze
      binary = "\x00\xff".b.freeze
      arguments = ['SET'.freeze, password, binary].freeze
      original = arguments.map { |value| [value.dup, value.encoding] }
      described_class.serialize_command(arguments)

      expect(arguments.map { |value| [value, value.encoding] }).to eq(original)
    end

    it 'returns nil for no argument list' do
      expect(described_class.serialize_command(nil)).to be_nil
    end

    it 'returns nil for an empty argument list' do
      expect(described_class.serialize_command([])).to be_nil
    end
  end
end
