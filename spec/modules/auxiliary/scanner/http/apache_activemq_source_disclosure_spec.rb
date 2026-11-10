require 'rspec'
require 'base64'
require 'json'

RSpec.describe 'ActiveMQ stock JSP source retrieval' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/apache_activemq_source_disclosure') }

  let(:native) do
    path = File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/scanner/http/apache_activemq_source_disclosure/native_responses.json')
    JSON.parse(File.read(path)).fetch('native')
  end

  before do
    mod.datastore['RHOST'] = '192.0.2.10'
    mod.datastore['RPORT'] = 8161
    mod.datastore['TARGETURI'] = '/admin/index.jsp'
    allow(mod).to receive(:store_loot).and_return('/tmp/module-target-source.jsp')
  end

  def captured_response(name)
    row = native.fetch(name)
    Rex::Proto::Http::Response.new(row.fetch('code')).tap { |reply| reply.body = Base64.strict_decode64(row.fetch('body_base64')) }
  end

  { '/admin/index.jsp' => '//admin/index.jsp', 'admin/topics.jsp' => '//admin/topics.jsp' }.each do |path, expected|
    it "preserves the exploit's double slash for normal path #{path}" do
      mod.datastore['TARGETURI'] = path
      allow(mod).to receive(:send_request_cgi).and_return(captured_response('raw_index.jsp'))

      mod.run_host('192.0.2.10')

      expect(mod).to have_received(:send_request_cgi).with(hash_including('method' => 'GET', 'uri' => expected))
    end
  end

  %w[index.jsp queues.jsp topics.jsp].each do |page|
    it "stores the exact native #{page} source bytes" do
      mod.datastore['TARGETURI'] = "/admin/#{page}"
      reply = captured_response("raw_#{page}")
      allow(mod).to receive(:send_request_cgi).and_return(reply)

      mod.run_host('192.0.2.10')

      expect(mod).to have_received(:store_loot).with('apache.activemq', 'text/plain', '192.0.2.10', reply.body, page)
    end
  end

  %w[rendered_affected rendered_fixed static_affected unrelated_html fixed_missing].each do |name|
    it "does not call the actual #{name} response JSP source" do
      allow(mod).to receive(:send_request_cgi).and_return(captured_response(name))

      mod.run_host('192.0.2.10')

      expect(mod).not_to have_received(:store_loot)
    end
  end

  it 'does not store a derived empty HTTP200 body' do
    allow(mod).to receive(:send_request_cgi).and_return(Rex::Proto::Http::Response.new(200))

    mod.run_host('192.0.2.10')

    expect(mod).not_to have_received(:store_loot)
  end

  it 'handles a derived absent body without inventing source or raising' do
    allow(mod).to receive(:send_request_cgi).and_return(double('Response with absent body', code: 200, body: nil))

    mod.run_host('192.0.2.10')

    expect(mod).not_to have_received(:store_loot)
  end

  it 'does not store derived HTML that only displays escaped JSP syntax' do
    reply = Rex::Proto::Http::Response.new(200)
    reply.body = '<html>&lt;%@ page import="java.io.*" %&gt;</html>'
    allow(mod).to receive(:send_request_cgi).and_return(reply)

    mod.run_host('192.0.2.10')

    expect(mod).not_to have_received(:store_loot)
  end

  it 'does not store derived HTTP500 even when an error mentions JSP code' do
    reply = captured_response('raw_index.jsp')
    reply.code = 500
    allow(mod).to receive(:send_request_cgi).and_return(reply)

    mod.run_host('192.0.2.10')

    expect(mod).not_to have_received(:store_loot)
  end

  it 'handles an absent target response without storing source' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)

    mod.run_host('192.0.2.10')

    expect(mod).not_to have_received(:store_loot)
  end
end
