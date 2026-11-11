require 'msfenv'
require 'msf/base'
require 'base64'

RSpec.describe 'RocketMQ response contracts' do
  let(:captures) do
    path = File.expand_path('../../../file_fixtures/rocketmq/captured_responses.json', __dir__)
    JSON.parse(File.binread(path)).fetch('responses')
  end
  let(:response) { Base64.strict_decode64(captures.fetch('broker_unsupported').fetch('base64')).byteslice(0, 8) }

  def load_owner(path)
    namespace = Module.new
    namespace.const_set(:ExcellentRanking, Msf::ExcellentRanking)
    namespace.const_set(:Exploit, Msf::Exploit)
    filename = File.expand_path("../../../../modules/#{path}.rb", __dir__)
    namespace.module_eval(File.binread(filename), filename)
    namespace.const_get(:MetasploitModule).allocate
  end

  context 'with the scanner' do
    subject(:mod) { load_owner('auxiliary/scanner/misc/rocketmq_version') }

    it 'reports an unusable response without dereferencing a nil parser result' do
      allow(mod).to receive(:send_version_request).and_return(response)
      allow(mod).to receive(:print_error)
      allow(mod).to receive(:vprint_error)

      mod.run_host('192.0.2.10')

      expect(mod).to have_received(:print_error).with('Invalid or no response received')
    end
  end

  context 'with the exploit' do
    subject(:mod) { load_owner('exploits/multi/http/apache_rocketmq_update_config') }

    it 'returns a reason-bearing Unknown result for an unusable response' do
      allow(mod).to receive(:send_version_request).and_return(response)
      allow(mod).to receive(:vprint_error)

      result = mod.check

      expect(result).to eq(Msf::Exploit::CheckCode::Unknown)
      expect(result.reason).to eq('RocketMQ did not respond to the request for version information')
    end

    it 'fails before broker discovery when the direct exploit entry receives an unusable reply' do
      allow(mod).to receive(:send_version_request).and_return(response)
      allow(mod).to receive(:vprint_error)
      allow(mod).to receive(:fail_with).and_raise(Msf::Exploit::Failed.new('invalid response'))

      # Exercise the module method reached after AutoCheck passes or is disabled.
      expect { mod.method(:exploit).super_method.call }.to raise_error(Msf::Exploit::Failed, 'invalid response')
      expect(mod).to have_received(:fail_with).with(Msf::Module::Failure::UnexpectedReply, 'Unable to parse RocketMQ version information')
    end
  end
end
