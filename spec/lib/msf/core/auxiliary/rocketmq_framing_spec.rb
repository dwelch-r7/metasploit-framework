require 'spec_helper'
require 'base64'

RSpec.describe Msf::Auxiliary::Rocketmq do
  subject(:mod) do
    Msf::Auxiliary.new.tap { |instance| instance.extend(described_class) }
  end

  let(:captures) do
    path = File.expand_path('../../../../file_fixtures/rocketmq/captured_responses.json', __dir__)
    JSON.parse(File.binread(path)).fetch('responses')
  end
  let(:route) { Base64.strict_decode64(captures.fetch('nameserver_5_1_1').fetch('base64')) }
  let(:unsupported) { Base64.strict_decode64(captures.fetch('broker_unsupported').fetch('base64')) }

  describe '#parse_rocketmq_data' do
    it 'preserves the captured 4.9.4 NameServer version and brokers' do
      capture = captures.fetch('nameserver_4_9_4')

      expect(mod.parse_rocketmq_data(Base64.strict_decode64(capture.fetch('base64')))).to eq(
        'version' => 'V4.9.4', 'brokerDatas' => capture.fetch('body').fetch('brokerDatas')
      )
    end

    it 'preserves the captured 5.1.1 NameServer version and brokers' do
      expect(mod.parse_rocketmq_data(route)).to eq(
        'version' => 'V5.1.1', 'brokerDatas' => captures.fetch('nameserver_5_1_1').fetch('body').fetch('brokerDatas')
      )
    end

    it 'reads the genuine 138-byte Broker error header without a body' do
      expect(mod.parse_rocketmq_data(unsupported)).to eq('version' => 'V5.1.1')
    end

    it('rejects a missing response') { expect(mod.parse_rocketmq_data(nil)).to be_nil }
    it('rejects an empty response') { expect(mod.parse_rocketmq_data('')).to be_nil }
    it('rejects a truncated length field') { expect(mod.parse_rocketmq_data(unsupported.byteslice(0, 3))).to be_nil }
    it('rejects a truncated header') { expect(mod.parse_rocketmq_data(unsupported.byteslice(0, unsupported.bytesize - 1))).to be_nil }

    it 'rejects an unsupported serialization type' do
      response = unsupported.dup
      response.setbyte(0, 1)

      expect(mod.parse_rocketmq_data(response)).to be_nil
    end

    it 'rejects a zero-length header' do
      expect(mod.parse_rocketmq_data([0].pack('N') + unsupported.byteslice(4..))).to be_nil
    end

    it 'rejects invalid header JSON' do
      response = unsupported.dup
      response.setbyte(4, '!'.ord)

      expect(mod.parse_rocketmq_data(response)).to be_nil
    end

    it 'rejects invalid body JSON' do
      expect(mod.parse_rocketmq_data(route.byteslice(0, route.bytesize - 1))).to be_nil
    end

    it 'rejects a header containing a JSON array' do
      expect(mod.parse_rocketmq_data([2].pack('N') + '[]')).to be_nil
    end

    it 'rejects a body containing a JSON array' do
      expect(mod.parse_rocketmq_data(unsupported + '[]')).to be_nil
    end

    it 'rejects a malformed broker list' do
      expect(mod.parse_rocketmq_data(unsupported + '{"brokerDatas":{}}')).to be_nil
    end

    it 'rejects a noninteger version' do
      header = captures.fetch('broker_unsupported').fetch('header').merge('version' => '435').to_json

      expect(mod.parse_rocketmq_data([header.bytesize].pack('N') + header)).to be_nil
    end

    it 'rejects a negative version instead of indexing from the end of the version table' do
      header = captures.fetch('broker_unsupported').fetch('header').merge('version' => -1).to_json

      expect(mod.parse_rocketmq_data([header.bytesize].pack('N') + header)).to be_nil
    end

    it 'rejects a version outside the protocol Java integer range' do
      header = captures.fetch('broker_unsupported').fetch('header').merge('version' => 2**100).to_json

      expect(mod.parse_rocketmq_data([header.bytesize].pack('N') + header)).to be_nil
    end

    it 'preserves braces inside JSON strings rather than splitting them as separate objects' do
      body = captures.fetch('nameserver_5_1_1').fetch('body')
      body.fetch('brokerDatas').first['brokerName'] = 'module-target-5.1.1}{suffix'
      header_size = route.unpack1('N')
      response = route.byteslice(0, 4 + header_size) + body.to_json

      expect(mod.parse_rocketmq_data(response).fetch('brokerDatas').first.fetch('brokerName')).to eq('module-target-5.1.1}{suffix')
    end
  end

  describe '#send_version_request' do
    it 'keeps a refused connection concise while retaining the exception in the error log' do
      error = Rex::ConnectionRefused.new('Connection refused')
      error.set_backtrace(['/private/module-target-source.rb:12:in connect'])
      allow(mod).to receive(:connect).and_raise(error)
      allow(mod).to receive(:disconnect)
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:elog)

      expect(mod.send_version_request).to be_nil
      expect(mod).to have_received(:print_error).with("Unable to connect: #{error.class} #{error.message}")
      expect(mod).to have_received(:elog).with('Error sending the rocketmq version request', error: error)
      expect(mod).to have_received(:disconnect)
    end
  end
end
