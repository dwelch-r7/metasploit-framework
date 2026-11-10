require 'spec_helper'
require 'tmpdir'

RSpec.describe 'SIP deregistration target options' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:modules_path) { ENV.fetch('SIP_UNIT_MODULE_ROOT', File.expand_path('../../../../modules', __dir__)) }
  let(:dummy_pathname) { Pathname.new(Dir.mktmpdir('sip-deregister-')) }
  let(:framework) do
    Msf::Simple::Framework.create('ConfigDirectory' => framework_config_pathname.to_s, 'DeferModuleLoads' => true, 'DisableDatabase' => true)
  end
  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'voip/sip_deregister') }

  it 'retains the scanner target option instead of removing its RHOST alias' do
    expect(mod.options.keys).to include('RHOSTS')
  end

  it 'retains the registered local port used by a bare Via default-port reply' do
    expect(mod.options['CPORT']).to be_advanced
  end
end
