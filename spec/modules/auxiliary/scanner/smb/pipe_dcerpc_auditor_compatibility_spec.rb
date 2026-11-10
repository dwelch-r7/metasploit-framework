require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'SMB pipe auditor explicit write bounds' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/smb/pipe_dcerpc_auditor') }

  let(:minimum) { 'SMB::pipe_write_min_size' }
  let(:maximum) { 'SMB::pipe_write_max_size' }

  it 'keeps an explicit maximum below the normal default valid' do
    mod.datastore[maximum] = 512

    expect([mod.datastore[minimum], mod.datastore[maximum]]).to eq([512, 512])
  end

  it 'passes the actual captured BIND through the existing writer within the explicit maximum' do
    mod.datastore[maximum] = 512
    capture = JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/smb_directory/native.json')))
    bytes = Base64.strict_decode64(capture.fetch('rpc').fetch('largest_default_bind').fetch('request'))
    writes = []
    pipe = Rex::Proto::SMB::SimpleClient::OpenPipe.allocate
    allow(pipe).to receive(:write) do |data|
      writes << data.dup
      data.bytesize
    end
    client = Rex::Proto::DCERPC::Client.allocate
    client.socket = pipe
    client.options = { 'pipe_write_min_size' => mod.datastore[minimum], 'pipe_write_max_size' => mod.datastore[maximum] }

    client.write(bytes)

    expect(writes.map(&:bytesize)).to eq([512, 220])
    expect(writes.join).to eq(bytes)
  end

  it 'keeps an explicit minimum when both operator bounds are supplied' do
    mod.datastore[minimum] = 64
    mod.datastore[maximum] = 512

    expect([mod.datastore[minimum], mod.datastore[maximum]]).to eq([64, 512])
  end

  it 'uses a globally selected maximum when the module minimum is unset' do
    framework.datastore[maximum] = 512

    expect([mod.datastore[minimum], mod.datastore[maximum]]).to eq([512, 512])
  end

  it 'preserves an explicit global minimum before the maximum fallback' do
    framework.datastore[minimum] = 32
    framework.datastore[maximum] = 512

    expect([mod.datastore[minimum], mod.datastore[maximum]]).to eq([32, 512])
  end

  it 'continues following valid operator maxima after a previous lookup' do
    mod.datastore[maximum] = 512
    expect(mod.datastore[minimum]).to eq(512)
    mod.datastore[maximum] = 64

    expect(mod.datastore[minimum]).to eq(64)
  end
end
