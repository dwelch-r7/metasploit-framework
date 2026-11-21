require 'spec_helper'
require 'rex/text'

RSpec.describe Msf::Auxiliary::Redis do
  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/redis/protocol_6_0_11.json', __dir__)
    JSON.parse(File.read(path))
  end
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Redis)
    mod
  end

  describe '#redis_proto' do
    it 'matches stock redis-cli UTF-8 authentication bytes' do
      capture = captures.fetch('requests').fetch(1)

      expect(subject.send(:redis_proto, ['AUTH', capture.fetch('password')])).to eq(Base64.strict_decode64(capture.fetch('packets_base64').first))
    end

    it 'keeps the nil argument-list sentinel' do
      expect(subject.send(:redis_proto, nil)).to be_nil
    end

    it 'keeps the empty argument-list sentinel' do
      expect(subject.send(:redis_proto, [])).to be_nil
    end
  end

  describe '#send_redis_command' do
    let(:response) { Base64.strict_decode64(captures.fetch('responses').fetch('tail')) }
    let(:socket) { double('Redis socket', put: nil, get: response) }

    before { allow(subject).to receive(:sock).and_return(socket) }

    it 'removes only the final protocol CRLF from the captured bulk response' do
      expect(subject.send(:send_redis_command, 'GET', 'tail')).to eq(response.delete_suffix("\r\n"))
    end

    it 'retains all whitespace bytes in the real stored value' do
      value = subject.parse_redis_response(subject.send(:send_redis_command, 'GET', 'tail'))

      expect(value).to eq("leading and trailing \r\n\t ".b)
    end

    it 'preserves leading and trailing NUL bytes in a bulk payload' do
      allow(socket).to receive(:get).and_return("$3\r\n\x00x\x00\r\n".b)

      expect(subject.parse_redis_response(subject.send(:send_redis_command, 'GET', 'binary'))).to eq("\x00x\x00".b)
    end

    it 'retains the established +OK normalization' do
      allow(socket).to receive(:get).and_return("+OK\r\n")

      expect(subject.send(:send_redis_command, 'SET', 'key', 'value')).to eq('+OK')
    end

    it 'retains the established integer reply normalization' do
      allow(socket).to receive(:get).and_return(":1\r\n")

      expect(subject.send(:send_redis_command, 'SETNX', 'key', 'value')).to eq(':1')
    end

    it 'retains bytes in a response without a final CRLF' do
      allow(socket).to receive(:get).and_return("$2\r\nx ".b)

      expect(subject.send(:send_redis_command, 'GET', 'tail')).to eq("$2\r\nx ".b)
    end

    it 'does not mutate the received string' do
      response.freeze
      subject.send(:send_redis_command, 'GET', 'tail')

      expect(response).to eq(Base64.strict_decode64(captures.fetch('responses').fetch('tail')))
    end

    it 'keeps the nil response sentinel' do
      allow(socket).to receive(:get).and_return(nil)

      expect(subject.send(:send_redis_command, 'GET', 'missing')).to be_nil
    end
  end

  describe '#redis_command' do
    let(:socket) { double('Redis socket', put: nil, get: "+OK\r\n") }
    let(:key) { "champ\u2603".freeze }
    let(:value) { "\x00\xff".b.freeze }

    before { allow(subject).to receive(:sock).and_return(socket) }

    it 'logs and sends mixed UTF-8/binary operands through the real wrapper' do
      expected = "*3\r\n$3\r\nSET\r\n$8\r\n".b + key.b + "\r\n$2\r\n".b + value + "\r\n".b
      result = subject.redis_command('SET', key, value)

      expect(result).to eq('+OK')
      expect(socket).to have_received(:put).with(expected)
    end

    it 'retains frozen operand contents and encodings while logging' do
      original = [key.dup, key.encoding, value.dup, value.encoding]
      subject.redis_command('SET', key, value)

      expect([key, key.encoding, value, value.encoding]).to eq(original)
    end
  end

  describe '.parse_redis_response' do
    it 'parses the captured empty bulk value' do
      response = Base64.strict_decode64(captures.fetch('responses').fetch('empty'))

      expect(subject.parse_redis_response(response)).to eq(''.b)
    end

    it 'parses the captured hash array without consuming data after its empty value' do
      response = Base64.strict_decode64(captures.fetch('responses').fetch('hash'))

      expect(subject.parse_redis_response(response)).to eq(["champ\u2603".b, ''.b, 'other'.b, "\u00e9".b])
    end

    it 'uses byte offsets when the caller explicitly supplies UTF-8 response encoding' do
      response = Base64.strict_decode64(captures.fetch('responses').fetch('hash')).force_encoding(Encoding::UTF_8)

      expect(subject.parse_redis_response(response)).to eq(["champ\u2603".b, ''.b, 'other'.b, "\u00e9".b])
    end

    it 'preserves the original response bytes and encoding' do
      response = Base64.strict_decode64(captures.fetch('responses').fetch('hash')).force_encoding(Encoding::UTF_8)
      original = [response.dup, response.encoding]
      subject.parse_redis_response(response)

      expect([response, response.encoding]).to eq(original)
    end

    it 'retains null bulk strings as nil' do
      expect(subject.parse_redis_response("$-1\r\n")).to be_nil
    end

    it 'retains the existing partial result for a truncated bulk response' do
      expect(subject.parse_redis_response("$4\r\nab")).to eq('ab')
    end

    it 'retains the existing malformed-header error' do
      expect { subject.parse_redis_response("$invalid\r\n") }.to raise_error(RuntimeError, 'RESP parsing error in bulk string')
    end

    context "given a simple string" do
      it "returns that string" do
        expect(subject.parse_redis_response("+test")).to eql("test")
      end
    end

    context "given a bulk string" do
      it "returns that string" do
        expect(subject.parse_redis_response("$10\r\ntest\r\ntest\r\nother junk")).to eql("test\r\ntest")
      end
    end

    context "given an array" do
      it "correctly parses it" do
        expect(subject.parse_redis_response("*3\r\n$3\r\nOne\r\n+Two\r\n$5\r\nThree")).to eql(["One","Two","Three"])
      end
    end

    context "given a nested array" do
      it "correctly parses it" do
        expect(subject.parse_redis_response("*2\r\n$1\r\n0\r\n*1\r\n$4\r\ntest\r\njunk")).to eql(["0",["test"]])
      end
    end
  end
end
