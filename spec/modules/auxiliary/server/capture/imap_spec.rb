require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'IMAP capture quoted LOGIN fields' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/imap') }

  let(:client) { double('native IMAP client', peerhost: '192.0.2.42', peerport: 49152, put: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/imap.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@state, {})
    allow(mod).to receive(:register_creds)
    mod.on_client_connect(client)
  end

  it 'decodes the actual quoted password without losing spaces or escaped quote/backslash bytes' do
    replay('capture_1_13_0')

    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture_user', ' module-target: capture "quoted" \\ tail ', 'imap')
  end

  it 'retains the actual atom LOGIN credentials' do
    replay('capture_1_12_0')

    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture_user', 'module-target-capture-password', 'imap')
  end

  it 'does not capture native commands without LOGIN' do
    replay('capture_1_14_0')

    expect(mod).not_to have_received(:register_creds)
  end

  it 'supports a derived quoted username and empty quoted password' do
    deliver("A002 LOGIN \"capture user\" \"\"\r\n")

    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture user', '', 'imap')
  end

  it 'does not report a derived unterminated quoted LOGIN' do
    deliver("A002 LOGIN capture_user \"unfinished\r\n")

    expect(mod).not_to have_received(:register_creds)
  end

  it 'does not report a derived LOGIN missing its password' do
    deliver("A002 LOGIN capture_user\r\n")

    expect(mod).not_to have_received(:register_creds)
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
