require 'rspec'
require 'json'

RSpec.describe 'Grafana traversal release boundaries' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/grafana_plugin_traversal') }

  let(:capture) do
    JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/scanner/http/grafana_plugin_traversal/versions.json')))
  end

  before { mod.datastore['RHOST'] = '192.0.2.1' }

  it 'advertises its scanner check to the public console interface' do
    expect(mod.has_check?).to be(true)
  end

  %w[v806 v807 v817 v818 v826 v827 v830 v831].each do |profile|
    it "classifies the captured #{profile} version using native traversal evidence" do
      observed = capture.fetch('profiles').fetch(profile)
      response = Rex::Proto::Http::Response.new(200)
      response.body = observed.fetch('version_fragment')
      allow(mod).to receive(:send_request_cgi!).and_return(response)

      expect(mod.check.code).to eq(observed.fetch('vulnerable') ? 'appears' : 'safe')
    end
  end

  it 'does not identify captured ordinary Apache content as vulnerable Grafana' do
    response = Rex::Proto::Http::Response.new(200)
    response.body = capture.fetch('unrelated_body')
    allow(mod).to receive(:send_request_cgi!).and_return(response)

    expect(mod.check.code).to eq('safe')
  end

  it 'returns an explicit unknown result for a derived absent response' do
    allow(mod).to receive(:send_request_cgi!).and_return(nil)

    expect(mod.check).to have_attributes(code: 'unknown', reason: 'No response or unexpected status code from target')
  end
end
