require 'rspec'

RSpec.describe 'ZooKeeper information socket closure' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/zookeeper_info_disclosure') }

  let(:socket) { double('closed native TCP stream') }

  before do
    allow(mod).to receive(:connect)
    allow(mod).to receive(:disconnect)
    allow(mod).to receive_messages(sock: socket, rhost: '192.0.2.1', rport: 2181)
    allow(socket).to receive(:put).with('ruok')
    # Both Rex stream APIs can raise EOFError when a peer closes before data.
    # This is an explicit synthetic transport boundary, not a server capture.
    allow(socket).to receive(:get_once).and_raise(EOFError)
    allow(socket).to receive(:get).and_raise(EOFError)
  end

  it 'handles peer closure without a runtime exception or loot and disconnects' do
    expect(mod).not_to receive(:store_loot)
    expect(mod).to receive(:disconnect)

    expect { mod.run_host('192.0.2.1') }.not_to raise_error
  end

  it 'retains the native service port as its default' do
    expect(mod.datastore['RPORT']).to eq(2181)
  end
end
