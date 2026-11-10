require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'SMB pipe auditor bind delivery defaults' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/smb/pipe_dcerpc_auditor') }

  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/smb_directory/native.json'))).fetch('rpc') }

  it 'uses whole default bind writes without changing the inherited maximum' do
    expect([mod.datastore['SMB::pipe_write_min_size'], mod.datastore['SMB::pipe_write_max_size']]).to eq([1024, 1024])
  end

  it 'fits the largest genuine default multi-context BIND in one write' do
    bytes = Base64.strict_decode64(capture.fetch('largest_default_bind').fetch('request'))
    expect(bytes.bytesize).to eq(732)
    expect(mod.datastore['SMB::pipe_write_min_size']).to be >= bytes.bytesize
  end

  it 'retains an explicit operator write minimum' do
    mod.datastore['SMB::pipe_write_min_size'] = 1

    expect(mod.datastore['SMB::pipe_write_min_size']).to eq(1)
  end

  it 'retains an explicit operator write maximum' do
    mod.datastore['SMB::pipe_write_max_size'] = 2048

    expect(mod.datastore['SMB::pipe_write_max_size']).to eq(2048)
  end

  it 'preserves the inherited multi-context option' do
    expect(mod.datastore['DCERPC::fake_bind_multi']).to be(true)
  end

  it 'matches the captured maximum to the existing default generator bounds' do
    # Default prepend rand(6)+10, append0: at most16 contexts of44 bytes,
    # plus28 bytes. Explicit evasion overrides may generate larger packets.
    packet, = Rex::Proto::DCERPC::Packet.make_bind_fake_multi('12345778-1234-abcd-ef00-0123456789ac', '1.0', 15, 0)

    expect(packet.bytesize).to eq(capture.fetch('default_bind_bound').fetch('maximum_bytes'))
  end
end
