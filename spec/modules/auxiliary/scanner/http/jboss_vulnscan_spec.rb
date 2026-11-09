require 'rspec'
require 'json'

RSpec.describe 'JBoss native default credential reporting' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/jboss_vulnscan') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/jboss_vulnscan/credentials.json'))) }
  let(:path) { '/jmx-console/HtmlAdaptor' }

  before do
    mod.datastore['RHOST'] = '192.0.2.53'
    mod.datastore['RPORT'] = 8080
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_status)
  end

  it 'keeps a native accepted credential usable without a connected database' do
    response = native_response('accepted')
    allow(mod).to receive(:send_request_cgi).and_return(response)
    allow(mod.framework.db).to receive(:active).and_return(false)
    allow(mod.framework.db).to receive(:workspace).and_return(nil)

    expect { mod.basic_auth_default_creds(path) }.not_to raise_error
    expect(mod).to have_received(:print_good).with(include('Authenticated using admin:admin at /jmx-console/HtmlAdaptor'))
  end

  it 'does not report the actual rejected credential as valid' do
    allow(mod).to receive(:send_request_cgi).and_return(native_response('rejected'))
    expect(mod).not_to receive(:add_creds)

    mod.basic_auth_default_creds(path)
  end

  it 'preserves accepted credential service and workspace fields when reporting is available' do
    allow(mod).to receive(:send_request_cgi).and_return(native_response('accepted'))
    allow(mod).to receive(:myworkspace_id).and_return(41)
    allow(mod.framework.db).to receive(:workspace).and_return(double(id: 41))
    core = double('credential core')
    expect(mod).to receive(:create_credential).with(hash_including(address: '192.0.2.53', port: 8080, protocol: 'tcp', service_name: 'jboss', workspace_id: 41, username: 'admin', private_data: 'admin', private_type: :password, origin_type: :service)).and_return(core)
    expect(mod).to receive(:create_credential_login).with(hash_including(core: core, workspace_id: 41))

    mod.basic_auth_default_creds(path)
  end

  def native_response(name)
    capture = captures.fetch('responses').fetch(name)
    response = Rex::Proto::Http::Response.new(capture.fetch('code'))
    capture.fetch('headers').each { |key, values| response.headers[key] = values.join(', ') }
    response
  end
end
