require 'spec_helper'
require 'rex/proto/erlang'
require 'json'
require 'base64'

RSpec.describe Rex::Proto::Erlang::ExternalTerm do
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'rex/proto/erlang/rpc_replies.json'))).fetch('cases') }
  let(:pid) { described_class::Pid.new(node: 'native_probe@client', id: 3, serial: 0, creation: 0) }

  6.times do |index|
    it "decodes the actual broker reply destination PID in capture #{index}" do
      frame = [captures.fetch(index).fetch('frames_hex').fetch(0)].pack('H*')
      decoded = described_class.decode(frame.byteslice(5..))

      expect(decoded.fetch(:term)).to eq(described_class::Tuple.new(elements: [2, described_class::Atom.new(value: ''), pid]))
    end

    it "decodes the actual broker RPC result in capture #{index}" do
      capture = captures.fetch(index)
      frame = [capture.fetch('frames_hex').fetch(0)].pack('H*')
      control = described_class.decode(frame.byteslice(5..))
      reply = described_class.decode(control.fetch(:remaining))
      expected = case capture.fetch('command')
                 when 'true' then []
                 when 'printf native-rpc-reply' then 'native-rpc-reply'
                 else [9731]
                 end

      expect(reply).to eq(term: described_class::Tuple.new(elements: [described_class::Atom.new(value: 'rex'), expected]), remaining: ''.b)
    end

    it "decodes the actually transmitted legacy PID form in request #{index}" do
      frame = Base64.strict_decode64(captures.fetch(index).fetch('request_base64'))
      control = described_class.decode(frame.byteslice(5..))

      expect(control.fetch(:term).elements.fetch(1)).to eq(pid)
    end
  end

  {
    'Latin-1 atom' => ["\x83\x64\x00\x01\xe9".b, 'é'],
    'small Latin-1 atom' => ["\x83\x73\x01a".b, 'a'],
    'UTF-8 atom' => ["\x83\x76\x00\x02\xc3\xa9".b, 'é']
  }.each do |label, (wire, value)|
    it "decodes the derived #{label} form without interning symbols" do
      expect(described_class.decode(wire).fetch(:term)).to eq(described_class::Atom.new(value: value))
    end
  end

  it 'decodes the derived signed integer minimum' do
    expect(described_class.decode("\x83\x62\x80\x00\x00\x00".b).fetch(:term)).to eq(-2_147_483_648)
  end

  it 'decodes a derived empty large tuple' do
    expect(described_class.decode("\x83\x69\x00\x00\x00\x00".b).fetch(:term)).to eq(described_class::Tuple.new(elements: []))
  end

  it 'decodes a derived empty proper list' do
    expect(described_class.decode("\x83\x6c\x00\x00\x00\x00\x6a".b).fetch(:term)).to eq([])
  end

  it 'decodes a derived proper list with an optimized byte-string tail' do
    wire = "\x83\x6c\x00\x00\x00\x01\x61\x01\x6b\x00\x02ab".b

    expect(described_class.decode(wire).fetch(:term)).to eq([1, 97, 98])
  end

  {
    'version marker' => "\x00\x6a".b,
    'truncated string' => "\x83\x6b\x00\x10x".b,
    'oversized list count' => "\x83\x6c\xff\xff\xff\xff\x6a".b,
    'oversized tuple count' => "\x83\x69\xff\xff\xff\xff".b,
    'invalid UTF-8 atom' => "\x83\x77\x01\xff".b,
    'oversized atom' => "\x83\x64\x01\x00".b + ('a' * 256),
    'improper list' => "\x83\x6c\x00\x00\x00\x01\x61\x01\x61\x02".b,
    'non-atom PID node' => "\x83\x67\x61\x01".b + ("\x00" * 9),
    'truncated PID' => "\x83\x58\x77\x01a\x00\x00".b,
    'unsupported binary' => "\x83\x6d\x00\x00\x00\x00".b
  }.each do |label, wire|
    it "rejects the derived #{label} with a specific decoder error" do
      expect { described_class.decode(wire) }.to raise_error(Rex::Proto::Erlang::DecodeError)
    end
  end

  it 'rejects a non-string API input' do
    expect { described_class.decode(nil) }.to raise_error(ArgumentError, /String/)
  end

  it 'rejects the derived oversized input before interpreting it' do
    expect { described_class.decode('a' * (described_class::MAX_BYTES + 1)) }.to raise_error(Rex::Proto::Erlang::DecodeError, /size/)
  end

  it 'rejects derived excessive nesting' do
    wire = "\x83".b + ("\x68\x01".b * (described_class::MAX_DEPTH + 1)) + "\x6a".b

    expect { described_class.decode(wire) }.to raise_error(Rex::Proto::Erlang::DecodeError, /depth/)
  end

  it 'rejects the derived term budget overflow without unbounded allocation' do
    wire = "\x83\x69".b + [described_class::MAX_TERMS].pack('N') + ("\x6a".b * described_class::MAX_TERMS)

    expect { described_class.decode(wire) }.to raise_error(Rex::Proto::Erlang::DecodeError, /term limit/)
  end

  it 'keeps the input bytes and encoding unchanged' do
    wire = "\x83\x6a".b.freeze
    described_class.decode(wire)

    expect(wire).to eq("\x83\x6a".b)
  end

  it 'uses Ruby encodings when the existing Rex::Encoding namespace is loaded' do
    stub_const('Rex::Encoding', Module.new)

    expect(described_class.decode("\x83\x77\x01a".b).fetch(:term)).to eq(described_class::Atom.new(value: 'a'))
  end
end
