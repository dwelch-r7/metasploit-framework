require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'IMAP capture command completion' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/imap') }

  let(:messages) { [] }
  let(:client) { double('native curl client', peerhost: '192.0.2.42', peerport: 49152) }
  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/imap_completion.json'))).fetch('native').fetch('native-imap-curl-valid') }
  let(:password) { ' module-target: capture "quoted" \\ tail ' }

  before do
    mod.instance_variable_set(:@state, {})
    allow(client).to receive(:put) { |data| messages << data }
    allow(mod).to receive(:register_creds)
    mod.on_client_connect(client)
  end

  it 'sends exactly one tagged OK completion for the actual CAPABILITY command' do
    line = command('CAPABILITY')
    deliver(line)

    expect(tagged_statuses(line)).to eq(['OK'])
  end

  it 'completes the actual LOGIN with NO after capture without claiming authentication' do
    line = command('LOGIN')
    deliver(line)

    expect(tagged_statuses(line)).to eq(['NO'])
    expect(mod).to have_received(:register_creds).with('192.0.2.42', 'capture_user', password, 'imap')
  end

  it 'keeps derived literal chunk decoding and continuation prompts unchanged' do
    user = 'capture_user'
    allow(client).to receive(:get_once).and_return("A002 LOGIN {#{user.bytesize}}\r\n", "#{user} {#{password.bytesize}}\r\n", "#{password}\r\n")
    mod.on_client_data(client)

    expect(mod).to have_received(:register_creds).with('192.0.2.42', user, password, 'imap')
    expect(client).to have_received(:put).with("+ \r\n").twice
  end

  it 'keeps derived Yahoo cookie bytes and service selection unchanged' do
    first = "module-target-cookie-one\r\n"
    second = "module-target-cookie-two\r\n"
    allow(client).to receive(:get_once).and_return("A002 AUTHENTICATE XYMPKI\r\n", first, second)
    mod.on_client_data(client)

    expect(mod).to have_received(:register_creds).with('192.0.2.42', first, second, 'imap-yahoo')
    expect(client).to have_received(:put).with("+ \r\n").twice
  end

  def command(name)
    Base64.decode64(capture.fetch('client_base64')).lines.find { |line| line.match?(/\A\w+ #{name} /) || line.match?(/\A\w+ #{name}\r\n/) }
  end

  def tagged_statuses(line)
    tag = line.split.first
    messages.select { |message| message.start_with?("#{tag} ") }.map { |message| message.split[1] }
  end

  def deliver(bytes)
    allow(client).to receive(:get_once).and_return(bytes)
    mod.on_client_data(client)
  end
end
