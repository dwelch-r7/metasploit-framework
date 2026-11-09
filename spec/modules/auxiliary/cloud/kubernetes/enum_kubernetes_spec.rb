require 'rspec'
require 'json'

RSpec.describe 'Kubernetes enumeration namespace configuration' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'cloud/kubernetes/enum_kubernetes') }

  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'kubernetes/session_config.json'))) }

  before do
    allow(mod).to receive(:session).and_return(nil)
    mod.datastore['RHOST'] = '192.0.2.10'
    mod.datastore['RPORT'] = 6443
    mod.datastore['TOKEN'] = 'public-unit-token'
  end

  {
    'auth' => :enum_auth,
    'pods' => :enum_pods,
    'secrets' => :enum_secrets
  }.each do |action, method|
    it "uses the native discovered namespace for #{action} when the option is blank" do
      mod.datastore['ACTION'] = action
      mod.datastore['NAMESPACE'] = ''
      mod.instance_variable_set(:@namespace, capture.fetch('namespace'))
      expect(mod).to receive(method).with(capture.fetch('namespace'), **(action == 'auth' ? {} : { name: nil }))

      mod.run
    end

    it "preserves the explicitly configured namespace for #{action}" do
      mod.datastore['ACTION'] = action
      mod.datastore['NAMESPACE'] = 'configured-namespace'
      expect(mod).to receive(method).with('configured-namespace', **(action == 'auth' ? {} : { name: nil }))

      mod.run
    end
  end
end
