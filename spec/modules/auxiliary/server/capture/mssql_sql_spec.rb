require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'MSSQL capture genuine SQL LOGIN7 bytes' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/mssql') }

  let(:fixture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/mssql_sql.json'))) }
  let(:client) { double('genuine FreeTDS client', peerhost: '192.0.2.42', peerport: 49152, put: nil, close: nil) }
  let(:password) { capture('dbcapture_1_1_0').fetch('independent_decoded').fetch('password') }
  let(:sent) { [] }

  before do
    mod.datastore['CHALLENGE'] = '1020304050607080'
    mod.datastore['SRVPORT'] = 11433
    mod.datastore['DOMAIN_NAME'] = 'MODULETARGET'
    allow(mod).to receive(:exploit)
    allow(mod).to receive(:report_cred)
    allow(client).to receive(:put) { |bytes| sent << bytes }
    mod.run
    mod.instance_variable_set(:@state, { client => { name: '192.0.2.42:49152', ip: '192.0.2.42' } })
  end

  it 'decodes the actual TDS7.1 SQL fields' do
    expect(parse_login('dbcapture_1_1_0')).to include(user: 'capture user', pass: password, srvname: 'capture')
  end

  it 'decodes the actual TDS7.4 SQL fields' do
    expect(parse_login('dbcapture_1_2_0')).to include(user: 'capture user', pass: password, srvname: 'capture')
  end

  it 'decodes the actual empty TDS7.1 password as an empty string' do
    expect(parse_login('dbcapture_1_4_0')).to include(user: 'capture_empty', pass: '')
  end

  it 'decodes the actual empty TDS7.4 password as an empty string' do
    expect(parse_login('dbcapture_1_5_0')).to include(user: 'capture_empty', pass: '')
  end

  it 'reports the actual empty SQL password without inventing placeholder bytes' do
    deliver(packet('dbcapture_1_4_0', 16))

    expect(mod).to have_received(:report_cred).with(hash_including(user: 'capture_empty', password: '', type: :password))
  end

  it 'does not capture credentials from the actual PRELOGIN-only request' do
    deliver(packet('dbcapture_1_10_0', 18))

    expect(mod).not_to have_received(:report_cred)
  end

  it 'rejects a derived truncated LOGIN7 body without capturing it' do
    deliver(packet('dbcapture_1_1_0', 16)[0...-2])

    expect(mod).not_to have_received(:report_cred)
  end

  def capture(name)
    fixture.fetch('captures').find { |row| row.fetch('case') == name }
  end

  def packet(name, type)
    data = Base64.decode64(capture(name).fetch('client_stream_base64'))
    until data.empty?
      length = data[2, 2].unpack1('n')
      current = data.slice!(0, length)
      return current if current.getbyte(0) == type
    end
    raise ArgumentError, "Missing native packet #{type}"
  end

  def parse_login(name)
    mod.mssql_parse_reply(packet(name, 16), {})
  end

  def deliver(bytes)
    allow(client).to receive(:get_once) { bytes.dup }
    mod.on_client_data(client)
  end

  def challenge_flags
    bytes = sent.last
    offset = bytes.index('NTLMSSP')
    bytes[offset + 20, 4].unpack1('V')
  end
end
