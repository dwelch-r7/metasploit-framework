require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'IMAP capture legal astring characters' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/imap') }

  let(:client) { double('native imaplib client', peerhost: '192.0.2.42', peerport: 49152, put: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/imap_astring.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@state, {})
    allow(mod).to receive(:register_creds)
    mod.on_client_connect(client)
  end

  it 'captures the actual bare closing-brace user and password authenticated by Dovecot' do
    deliver_login('native-imap-bare-closing-brace')

    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture}user', 'password}', 'imap')
  end

  it 'retains the actual bare closing-bracket user and password authenticated by Dovecot' do
    deliver_login('native-imap-bare-closing-bracket')

    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture]user', 'password]', 'imap')
  end

  it 'does not capture the bare opening-brace user rejected as malformed by Dovecot' do
    deliver_login('native-imap-malformed-opening-brace-user')

    expect(mod).not_to have_received(:register_creds)
  end

  it 'does not capture the bare opening-brace password rejected as malformed by Dovecot' do
    deliver_login('native-imap-malformed-opening-brace-password')

    expect(mod).not_to have_received(:register_creds)
  end

  def deliver_login(name)
    stream = Base64.decode64(captures.fetch(name).fetch('client_base64'))
    line = stream.lines.find { |item| item.match?(/\A\w+ LOGIN /) }
    allow(client).to receive(:get_once).and_return(line)
    mod.on_client_data(client)
  end
end
