require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'MySQL capture native challenge-response bytes' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/mysql') }

  let(:fixture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/mysql.json'))) }
  let(:client) { double('genuine MySQL client', peerhost: '192.0.2.42', peerport: 49152, put: nil, close: nil) }
  let(:challenge) { '112233445566778899aabbccddeeff1122334455' }

  before do
    mod.instance_variable_set(:@challenge, [challenge].pack('H*'))
    mod.instance_variable_set(:@state, { client => { name: '192.0.2.42:49152', ip: '192.0.2.42' } })
    allow(mod).to receive(:report_cred)
  end

  it 'retains the actual Oracle user and database fields' do
    expect(parse('dbcapture_1_1_0')).to include(username: 'capture user', database: 'capture database', errors: [])
  end

  it 'retains the actual MariaDB user and database fields' do
    expect(parse('dbcapture_1_4_0')).to include(username: 'capture user', database: 'capture database', errors: [])
  end

  it 'preserves the complete Oracle binary response ending in NUL' do
    expect(parse('dbcapture_1_7_0').fetch(:response).unpack1('H*')).to eq('f57e494a043cf1c86c2edd7644aaad2dbd602400')
  end

  it 'preserves the complete MariaDB binary response ending in NUL' do
    expect(parse('dbcapture_1_8_0').fetch(:response).unpack1('H*')).to eq('f57e494a043cf1c86c2edd7644aaad2dbd602400')
  end

  it 'preserves the complete Oracle binary response ending in space' do
    expect(parse('dbcapture_1_9_0').fetch(:response).unpack1('H*')).to eq('59bc6733b87bf2b66dcea5bb37fbd0fff063df20')
  end

  it 'preserves the complete MariaDB binary response ending in space' do
    expect(parse('dbcapture_1_10_0').fetch(:response).unpack1('H*')).to eq('59bc6733b87bf2b66dcea5bb37fbd0fff063df20')
  end

  it 'does not invent a hash for the actual Oracle empty-password response' do
    expect(parse('dbcapture_1_11_0')[:response]).to be_nil
  end

  it 'retains an actual login that omits the database' do
    expect(parse('dbcapture_1_5_0')[:database]).to be_nil
  end

  it 'reports the full actual response and database proof' do
    deliver('dbcapture_1_7_0')

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_tail0', password: 'capture_tail0:$mysql$112233445566778899aabbccddeeff1122334455$f57e494a043cf1c86c2edd7644aaad2dbd602400', proof: 'capture database'))
  end

  it 'appends both exact actual binary responses to the John file' do
    Dir.mktmpdir('mysql-capture') do |folder|
      prefix = File.join(folder, 'hashes')
      mod.datastore['JOHNPWFILE'] = prefix
      2.times { deliver('dbcapture_1_9_0') }

      expect(File.binread(prefix + '_mysqlna')).to eq("capture_tail32:$mysqlna$112233445566778899aabbccddeeff1122334455*59bc6733b87bf2b66dcea5bb37fbd0fff063df20\n" * 2)
    end
  end

  it 'accepts the actual twenty-byte native seed containing zero' do
    allow(mod).to receive(:exploit)
    mod.datastore['CHALLENGE'] = fixture.fetch('native_seed').fetch('seed')
    mod.run

    expect(mod).to have_received(:exploit)
  end

  it 'rejects a derived short challenge' do
    reject_challenge('112233445566778899AABBCCDDEEFF112233445')
  end

  it 'rejects a derived non-hexadecimal challenge' do
    reject_challenge('g12233445566778899AABBCCDDEEFF1122334455')
  end

  it 'rejects a derived challenge followed by a newline' do
    reject_challenge("112233445566778899AABBCCDDEEFF1122334455\n")
  end

  def capture(name)
    fixture.fetch('captures').find { |row| row.fetch('case') == name }
  end

  def packet(name)
    Base64.decode64(capture(name).fetch('client_stream_base64'))
  end

  def parse(name)
    info = { errors: [] }
    mod.mysql_process_login(packet(name), info)
    info
  end

  def deliver(name)
    allow(client).to receive(:get_once) { packet(name) }
    mod.on_client_data(client)
  end

  def reject_challenge(value)
    allow(mod).to receive(:exploit)
    mod.datastore['CHALLENGE'] = value
    mod.run

    expect(mod).not_to have_received(:exploit)
  end
end
