require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'SMTP capture LOGIN and DATA states' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/smtp') }

  let(:client) { double('native SMTP client', peerhost: '192.0.2.42', peerport: 49152, put: nil) }
  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/smtp.json'))).fetch('captures') }

  before do
    mod.instance_variable_set(:@state, {})
    allow(mod).to receive_messages(report_cred: nil, report_note: nil)
    mod.on_client_connect(client)
  end

  it 'captures the actual initial-response LOGIN exchange accepted by native Exim' do
    replay('native-smtp-login')

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_user', password: ' module-target: capture "quoted" \\ tail '))
  end

  it 'retains the actual challenge LOGIN exchange accepted by native Exim' do
    replay('native-smtp-login-challenge')

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_user', password: ' module-target: capture "quoted" \\ tail '))
  end

  it 'retains the entire actual DATA body containing a legal RSET line' do
    bytes = data_bytes('capture_1_7_0')
    deliver("DATA\r\n")
    deliver(bytes)

    expect(mod).to have_received(:report_note).with(hash_including(data: { message: bytes.delete_suffix("\r\n.\r\n") }))
  end

  it 'retains ordinary actual DATA bytes through the dot terminator' do
    bytes = data_bytes('capture_1_6_0')
    deliver("DATA\r\n")
    deliver(bytes)

    expect(mod).to have_received(:report_note).with(hash_including(data: { message: bytes.delete_suffix("\r\n.\r\n") }))
  end

  it 'does not report an incomplete DATA transfer before its actual dot terminator' do
    bytes = data_bytes('capture_1_7_0').delete_suffix("\r\n.\r\n")
    deliver("DATA\r\n")
    deliver(bytes)

    expect(mod).not_to have_received(:report_note)
  end

  it 'keeps actual dot-stuffed body bytes until the real dot terminator' do
    bytes = data_bytes('native-smtp-dot-stuffing')
    deliver("DATA\r\n")
    deliver(bytes)

    expect(mod).to have_received(:report_note).with(hash_including(data: { message: bytes.delete_suffix("\r\n.\r\n") }))
  end

  it 'buffers the actual dot terminator split across receives' do
    bytes = data_bytes('native-smtp-dot-stuffing')
    deliver("DATA\r\n")
    deliver(bytes[0...-3])
    expect(mod).not_to have_received(:report_note)
    deliver(bytes[-3..])

    expect(mod).to have_received(:report_note).with(hash_including(data: { message: bytes.delete_suffix("\r\n.\r\n") }))
  end

  it 'does not report a truncated LOGIN initial response without a password' do
    deliver("AUTH LOGIN Y2FwdHVyZV91c2Vy\r\n")

    expect(mod).not_to have_received(:report_cred)
  end

  it 'does not capture a derived unsupported authentication scheme' do
    deliver("AUTH LOGIN-other Y2FwdHVyZV91c2Vy\r\n")

    expect(mod).not_to have_received(:report_cred)
  end

  def stream(name)
    Base64.decode64(captures.find { |row| row.fetch('case') == name }.fetch('client_stream_base64'))
  end

  def replay(name)
    stream(name).lines.each { |line| deliver(line) }
  end

  def data_bytes(name)
    body = stream(name).split(/\r\ndata\r\n/i, 2).last
    body.split("\r\n.\r\n", 2).first + "\r\n.\r\n"
  end

  def deliver(bytes)
    allow(client).to receive(:get_once).and_return(bytes)
    mod.on_client_data(client)
  end
end
