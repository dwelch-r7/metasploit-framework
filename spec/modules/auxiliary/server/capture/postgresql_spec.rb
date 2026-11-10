require 'rspec'
require 'json'
require 'base64'
require 'postgres/postgres-pr/message'

RSpec.describe 'PostgreSQL capture Startup negotiation' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/postgresql') }

  let(:client) { double('native libpq client', peerhost: '192.0.2.42', peerport: 49152, put: nil, close: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/postgresql.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@state, {})
    allow(mod).to receive(:report_cred)
    mod.on_client_connect(client)
  end

  it 'requests a password for the actual sslmode disable direct Startup' do
    deliver(stream('capture_1_13_0'))

    expect(client).to have_received(:put).with("R\x00\x00\x00\x08\x00\x00\x00\x03")
  end

  it 'captures the same exact credentials after a direct Startup and password response' do
    deliver(stream('capture_1_13_0'))
    deliver(password_frame)

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture user', password: ' module-target: capture "quoted" \\ tail ', proof: 'capture database'))
  end

  it 'retains the actual optional SSLRequest refusal and plaintext fallback' do
    bytes = stream('capture_1_12_0')
    deliver(bytes.slice!(0, 8))
    length = bytes.unpack1('N')
    deliver(bytes.slice!(0, length))
    deliver(bytes)

    expect(client).to have_received(:put).with('N')
    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture user', password: ' module-target: capture "quoted" \\ tail '))
  end

  it 'does not capture credentials when the actual require client sends only SSLRequest' do
    deliver(stream('capture_1_14_0'))

    expect(mod).not_to have_received(:report_cred)
  end

  it 'reads derived reordered Startup parameters with the existing protocol parser' do
    startup = Msf::Db::PostgresPR::StartupMessage.new(3 << 16, { 'application_name' => 'module-target-capture-client', 'database' => 'capture database', 'user' => 'capture user' }).dump
    deliver(startup)
    deliver(password_frame)

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture user', proof: 'capture database'))
  end

  it 'does not request authentication or report credentials for a derived truncated Startup' do
    deliver(stream('capture_1_13_0').byteslice(0, 12))

    expect(client).not_to have_received(:put)
    expect(mod).not_to have_received(:report_cred)
  end

  it 'does not report a derived Startup without its required user parameter' do
    deliver(Msf::Db::PostgresPR::StartupMessage.new(3 << 16, { 'database' => 'capture database' }).dump)

    expect(client).not_to have_received(:put)
    expect(mod).not_to have_received(:report_cred)
  end

  it 'handles a derived malformed Startup CString without authentication or credentials' do
    expect { deliver([12, 3 << 16].pack('NN') + 'user') }.not_to raise_error

    expect(mod).not_to have_received(:report_cred)
  end

  def stream(name)
    Base64.decode64(captures.find { |row| row.fetch('case') == name }.fetch('client_stream_base64'))
  end

  def password_frame
    bytes = stream('capture_1_12_0')
    bytes.slice!(0, 8)
    bytes.slice!(0, bytes.unpack1('N'))
    bytes
  end

  def deliver(bytes)
    allow(client).to receive(:get_once).and_return(bytes.dup)
    mod.on_client_data(client)
  end
end
