require 'spec_helper'

RSpec.describe Msf::FrameworkEventSubscriber do
  let(:database) { double('Database', active: true, find_workspace: 'test', report_event: nil) }
  let(:framework) { double('Framework', db: database) }
  let(:mod) { Msf::Module.new }
  subject(:subscriber) { described_class.new(framework) }

  before do
    allow(mod).to receive(:workspace).and_return('test')
    allow(mod).to receive(:fullname).and_return('auxiliary/test')
  end

  it 'adds the existing invocation ID without replacing the module UUID' do
    mod.run_uuid = 'current-invocation'
    subscriber.on_module_complete(mod)
    expect(database).to have_received(:report_event).with(hash_including(
      name: 'module_complete',
      info: { module_name: 'auxiliary/test', module_uuid: mod.uuid, run_uuid: 'current-invocation' }
    ))
  end

  it 'omits an unavailable invocation ID' do
    subscriber.on_module_complete(mod)
    expect(database).to have_received(:report_event).with(hash_including(
      info: { module_name: 'auxiliary/test', module_uuid: mod.uuid }
    ))
  end
end
