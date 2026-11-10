require 'spec_helper'
require 'tmpdir'

RSpec.describe 'SIP capture listener startup' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:modules_path) { ENV.fetch('SIP_UNIT_MODULE_ROOT', File.expand_path('../../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('sip-capture-startup-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/sip') }

  it 'preserves the existing SIP listener port default' do
    expect(mod.datastore['SRVPORT']).to eq(5060)
  end

  it 'provides the component-owned local listener address accessor' do
    mod.datastore['SRVHOST'] = '192.0.2.42'

    expect(mod.srvhost).to eq('192.0.2.42')
  end

  it 'binds the selected address and closes the owned socket after its receive loop stops' do
    mod.datastore['SRVHOST'] = '192.0.2.42'
    socket = double('owned UDP socket', close: nil)
    allow(socket).to receive(:timed_recvfrom) do
      mod.instance_variable_set(:@run, false)
      nil
    end
    allow(Rex::Socket::Udp).to receive(:create).and_return(socket)

    mod.run

    expect(Rex::Socket::Udp).to have_received(:create).with(hash_including('LocalHost' => '192.0.2.42', 'LocalPort' => 5060))
    expect(socket).to have_received(:close).once
  end

  it 'reports an exclusive bind failure without closing an uncreated socket' do
    allow(Rex::Socket::Udp).to receive(:create).and_raise(Rex::BindFailed.new)

    expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Failed to bind SIP listener/)
  end
end
