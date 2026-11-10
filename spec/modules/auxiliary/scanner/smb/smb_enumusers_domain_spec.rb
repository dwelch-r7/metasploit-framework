require 'rspec'
require 'json'
require 'base64'

RSpec.describe 'SMB workstation user response fields' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/smb/smb_enumusers_domain') }

  let(:capture) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/smb_directory/native.json'))) }
  let(:native) { RubySMB::Dcerpc::Wkssvc::NetrWkstaUserEnumResponse.read(Base64.strict_decode64(capture.fetch('wkssvc').fetch('populated').fetch('ndr_stub_base64'))) }
  let(:entries) { native.user_info.info.wkui1_buffer }
  let(:good) { [] }
  let(:status) { [] }

  before do
    allow(mod).to receive(:session).and_return(nil)
    allow(mod).to receive(:run_rhost).and_return([entries])
    allow(mod).to receive(:print_good) { |message| good << message }
    allow(mod).to receive(:print_status) { |message| status << message }
  end

  it 'prints both native users when other_domains is an NDR null pointer' do
    expect(entries.first.wkui1_oth_domains.is_null_ptr?).to be(true)

    mod.run_host('192.0.2.53')

    expect(good).to eq(['Found user: DIRLAB\\local_alice', 'Found user: DIRLAB\\local_bob'])
  end

  it 'prints native verbose server metadata with an empty optional domain field' do
    mod.datastore['VERBOSE'] = true

    mod.run_host('192.0.2.53')

    expect(status).to eq(["DIRLAB\\local_alice\t(logon_server: *, other_domains: )", "DIRLAB\\local_bob\t(logon_server: *, other_domains: )"])
  end

  it 'keeps the genuinely empty native user response empty' do
    empty = RubySMB::Dcerpc::Wkssvc::NetrWkstaUserEnumResponse.read(Base64.strict_decode64(capture.fetch('wkssvc').fetch('empty').fetch('ndr_stub_base64')))
    allow(mod).to receive(:run_rhost).and_return([empty.user_info.info.wkui1_buffer])

    mod.run_host('192.0.2.53')

    expect(good).to eq([])
  end

  it 'preserves derived nonnull optional text' do
    entries.each { |entry| entry.wkui1_oth_domains = 'SECONDARY' }
    mod.datastore['VERBOSE'] = true

    mod.run_host('192.0.2.53')

    expect(status.first).to eq("DIRLAB\\local_alice\t(logon_server: *, other_domains: SECONDARY)")
  end

  it 'accepts a derived null optional logon server without inventing its text' do
    entries.each do |entry|
      entry.wkui1_oth_domains = 'SECONDARY'
      entry.wkui1_logon_server = :null
    end
    mod.datastore['VERBOSE'] = true

    mod.run_host('192.0.2.53')

    expect(status.first).to eq("DIRLAB\\local_alice\t(logon_server: , other_domains: SECONDARY)")
  end
end
