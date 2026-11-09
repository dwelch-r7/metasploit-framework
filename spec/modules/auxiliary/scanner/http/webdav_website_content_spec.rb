require 'rspec'
require 'json'

RSpec.describe 'WebDAV website content discovery' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/webdav_website_content') }

  let(:host) { '192.0.2.53' }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/webdav/apache_2_4_62_responses.json'))).fetch('captures') }
  let(:native_listing) { captures.find { |capture| capture.fetch('name') == 'depth_one' }.fetch('body') }
  let(:body) { native_listing }
  let(:code) { 207 }
  let(:response) { Rex::Proto::Http::Response.new(code).tap { |message| message.body = body } }
  let(:notes) { [] }

  before do
    mod.datastore['PATH'] = '/dav/'
    allow(mod).to receive(:send_request_cgi).and_return(response)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:report_note) { |note| notes << note }
  end

  it 'uses a bounded depth-one PROPFIND request by default' do
    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with(
      hash_including('method' => 'PROPFIND', 'uri' => '/dav/', 'headers' => { 'Depth' => '1' })
    )
  end

  it 'preserves the normal HTTP host and version settings' do
    mod.run_host(host)

    expect(mod).to have_received(:send_request_cgi).with(hash_excluding('vhost', 'version'))
  end

  %w[0 infinity].each do |depth|
    it "forwards the explicit #{depth} listing depth" do
      mod.datastore['DEPTH'] = depth
      mod.run_host(host)

      expect(mod).to have_received(:send_request_cgi).with(hash_including('headers' => { 'Depth' => depth }))
    end
  end

  it 'reports both native Apache hrefs while retaining the existing note path array' do
    mod.run_host(host)

    expect(notes.map { |note| note.fetch(:data).fetch(:path) }).to eq([['/dav/'], ['/dav/existing.txt']])
  end

  context 'with a different DAV namespace prefix derived from the capture' do
    let(:body) { native_listing.gsub('D:', 'dav:').sub('xmlns:D=', 'xmlns:dav=') }

    it 'discovers the same native resources' do
      mod.run_host(host)

      expect(notes.map { |note| note.fetch(:data).fetch(:path) }).to eq([['/dav/'], ['/dav/existing.txt']])
    end
  end

  context 'with a default DAV namespace derived from the capture' do
    let(:body) { native_listing.gsub('<D:', '<').gsub('</D:', '</').sub('xmlns:D=', 'xmlns=') }

    it 'discovers the same native resources' do
      mod.run_host(host)

      expect(notes.map { |note| note.fetch(:data).fetch(:path) }).to eq([['/dav/'], ['/dav/existing.txt']])
    end
  end

  context 'with an XML-escaped href derived from the capture' do
    let(:body) { native_listing.sub('/dav/existing.txt', '/dav/notes?first=1&amp;second=2') }

    it 'stores the decoded XML text without changing URI escaping' do
      mod.run_host(host)

      expect(notes.map { |note| note.fetch(:data).fetch(:path) }).to include(['/dav/notes?first=1&second=2'])
    end
  end

  context 'with duplicate and empty hrefs derived from the capture' do
    let(:body) do
      extra = '<D:response><D:href>/dav/existing.txt</D:href></D:response><D:response><D:href>  </D:href></D:response>'
      native_listing.sub('</D:multistatus>', "#{extra}</D:multistatus>")
    end

    it 'reports each nonempty resource once' do
      mod.run_host(host)

      expect(notes.map { |note| note.fetch(:data).fetch(:path) }).to eq([['/dav/'], ['/dav/existing.txt']])
    end
  end

  context 'with a foreign namespace derived from the capture' do
    let(:body) { native_listing.sub('xmlns:D="DAV:"', 'xmlns:D="urn:unrelated"') }

    it 'does not report an unrelated XML document' do
      mod.run_host(host)

      expect(notes).to be_empty
    end
  end

  context 'with a non-success status and a DAV-shaped body' do
    let(:code) { 403 }
    let(:body) { native_listing.gsub('D:', 'a:').sub('xmlns:D=', 'xmlns:a=') }

    it 'does not treat an error reply as a content listing' do
      mod.run_host(host)

      expect(notes).to be_empty
    end
  end

  context 'with an ordinary HTML page containing a similarly named tag' do
    let(:code) { 200 }
    let(:body) { '<html><a:href xmlns:a="DAV:">/unrelated</a:href></html>' }

    it 'does not report HTML content as WebDAV data' do
      mod.run_host(host)

      expect(notes).to be_empty
    end
  end

  context 'with truncated native XML' do
    let(:body) { native_listing.sub('</D:multistatus>', '') }

    it 'does not report recovered partial XML as a complete listing' do
      mod.run_host(host)

      expect(notes).to be_empty
    end
  end

  it 'handles an absent response without reporting content' do
    allow(mod).to receive(:send_request_cgi).and_return(nil)
    mod.run_host(host)

    expect(notes).to be_empty
  end

  it 'retains developer context for an expected connection failure' do
    error = Rex::ConnectionRefused.new
    allow(mod).to receive(:send_request_cgi).and_raise(error)
    mod.run_host(host)

    expect(mod).to have_received(:elog).with('WebDAV PROPFIND request failed', error: error)
  end
end
