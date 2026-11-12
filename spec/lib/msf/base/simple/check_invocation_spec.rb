require 'spec_helper'

[Msf::Simple::Exploit, Msf::Simple::Auxiliary].each do |wrapper|
  RSpec.describe wrapper, '.check_simple invocation tracking' do
    let(:framework) { Msf::Framework.new }
    let(:module_class) do
      parent = described_class == Msf::Simple::Exploit ? Msf::Exploit : Msf::Auxiliary
      Class.new(parent) do
        def check
          Msf::Exploit::CheckCode::Safe('Test target')
        end
      end
    end
    let(:mod) { module_class.new }
    let(:listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
    let(:contexts) { [] }

    before do
      module_class.framework = framework
      allow(mod).to receive(:refname).and_return('test/check')
      allow(Rex::Text).to receive(:rand_text_alphanumeric).with(24).and_return('first-check', 'second-check')
      allow(framework.jobs).to receive(:start_bg_job) do |_name, context, _run, _cleanup|
        contexts << context
        contexts.length
      end
    end

    it 'assigns the current invocation ID before foreground setup' do
      observed_ids = []
      allow(mod).to receive(:setup) { observed_ids << mod.run_uuid }
      allow(mod).to receive(:cleanup)

      described_class.check_simple(mod, 'JobListener' => listener)
      described_class.check_simple(mod, 'JobListener' => listener)

      expect(observed_ids).to eq(['first-check', 'second-check'])
    end

    it 'isolates overlapping background checks and preserves caller job handles' do
      first = described_class.check_simple(mod, 'RunAsJob' => true, 'JobListener' => listener)
      second = described_class.check_simple(mod, 'RunAsJob' => true, 'JobListener' => listener)

      expect(first).to eq(['first-check', 1])
      expect(second).to eq(['second-check', 2])
      expect(mod.job_id).to eq(2)
      expect(contexts.map { |context| context[0].run_uuid }).to eq(['first-check', 'second-check'])
      expect(contexts.map(&:first)).not_to include(mod)
      expect(contexts[0][0]).not_to equal(contexts[1][0])
      expect(contexts[0][0].job_id).to eq(1)
      expect(contexts[1][0].job_id).to eq(2)
    end
  end
end
