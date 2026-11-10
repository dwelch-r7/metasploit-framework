require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'FTP capture argument bytes' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/ftp') }

  let(:client) { double('native FTP client', peerhost: '192.0.2.42', peerport: 49152, put: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/ftp.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@state, {})
    allow(mod).to receive(:report_cred)
    mod.on_client_connect(client)
  end

  it 'preserves the native client password including surrounding spaces, colon, quotes and backslash' do
    replay('capture_1_2_0')

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_user', password: ' module-target: capture "quoted" \\ tail ', proof: ' module-target: capture "quoted" \\ tail '))
  end

  it 'retains the ordinary native password' do
    replay('capture_1_1_0')

    expect(mod).to have_received(:report_cred).with(hash_including(password: 'module-target-capture-password'))
  end

  it 'does not report a native USER-only exchange' do
    replay('capture_1_4_0')

    expect(mod).not_to have_received(:report_cred)
  end

  it 'preserves an explicitly empty password' do
    deliver("USER capture_user\r\n")
    deliver("PASS \r\n")

    expect(mod).to have_received(:report_cred).with(hash_including(password: ''))
  end

  def replay(name)
    bytes = Base64.decode64(captures.find { |row| row.fetch('case') == name }.fetch('client_stream_base64'))
    bytes.lines.each { |line| deliver(line) }
  end

  def deliver(bytes)
    allow(client).to receive(:get_once).and_return(bytes)
    mod.on_client_data(client)
  end
end
