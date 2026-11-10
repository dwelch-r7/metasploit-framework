require 'rspec'
require 'json'
require 'base64'
require 'tmpdir'

RSpec.describe 'MSSQL capture genuine NTLM bytes' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'server/capture/mssql') }

  let(:fixture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/server/capture/mssql_ntlm.json'))) }
  let(:client) { double('genuine FreeTDS client', peerhost: '192.0.2.42', peerport: 49152, put: nil, close: nil) }
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

  it 'reports the actual independently verified NTLMv1 response bytes' do
    deliver(packet('dbcapture_1_8_0', 17))

    expect(mod).to have_received(:report_cred).with(hash_including(password: capture('dbcapture_1_8_0').fetch('independent_decoded').fetch('private_data'), jtr_format: 'netntlm'))
  end

  it 'reports the actual NTLMv2 hash with its MSSQL listener identity and domain proof' do
    deliver(packet('dbcapture_1_6_0', 17))

    expect(mod).to have_received(:report_cred).with(hash_including(ip: '192.0.2.42', port: 11433, sname: 'mssql_client', user: 'capture_user', password: capture('dbcapture_1_6_0').fetch('independent_decoded').fetch('private_data'), proof: 'DOMAIN=MODULETARGET', type: :nonreplayable_hash, jtr_format: 'netntlmv2'))
  end

  it 'appends exact actual NTLMv1 John lines after distinct listener restarts' do
    Dir.mktmpdir('mssql-capture') do |folder|
      prefix = File.join(folder, 'hashes')
      mod.datastore['JOHNPWFILE'] = prefix
      2.times do
        mod.run
        deliver(packet('dbcapture_1_8_0', 17))
      end

      line = capture('dbcapture_1_8_0').fetch('independent_decoded').fetch('john').fetch('_netntlm')
      expect(File.binread(prefix + '_netntlm')).to eq((line + "\n") * 2)
    end
  end

  it 'writes both exact actual NTLMv2 John formats' do
    Dir.mktmpdir('mssql-capture') do |folder|
      prefix = File.join(folder, 'hashes')
      mod.datastore['JOHNPWFILE'] = prefix
      deliver(packet('dbcapture_1_6_0', 17))
      actual = Dir.glob(prefix + '_*').to_h { |path| [path.delete_prefix(prefix), File.binread(path)] }
      expected = capture('dbcapture_1_6_0').fetch('independent_decoded').fetch('john').transform_values { |line| line + "\n" }

      expect(actual).to eq(expected)
    end
  end

  it 'sets the extended-session negotiation bit when the option is enabled' do
    mod.datastore['SMB_EXTENDED_SECURITY'] = true
    mod.run
    mod.mssql_send_ntlm_challenge(client, {})

    expect(challenge_flags & 0x80000).to eq(0x80000)
  end

  it 'omits the extended-session negotiation bit when the option is disabled' do
    mod.datastore['SMB_EXTENDED_SECURITY'] = false
    mod.run
    mod.mssql_send_ntlm_challenge(client, {})

    expect(challenge_flags & 0x80000).to eq(0)
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
