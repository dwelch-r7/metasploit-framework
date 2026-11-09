require 'rspec'

RSpec.describe 'Grafana traversal scanner interface' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/grafana_plugin_traversal') }

  it 'advertises its scanner check to the public console interface' do
    expect(mod.has_check?).to be(true)
  end
end
