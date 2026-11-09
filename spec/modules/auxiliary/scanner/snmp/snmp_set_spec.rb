require 'rspec'

RSpec.describe 'SNMP Set Module' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/snmp/snmp_set')
  end

  let(:manager) { instance_double(SNMP::Manager) }
  let(:canonical_oid) { '1.3.6.1.2.1.1.4.0' }
  let(:input_oid) { canonical_oid }
  let(:operations) { [] }
  let(:state) { { canonical_oid => 'root' } }
  let(:error_status) { :noError }

  before do
    mod.datastore['OID'] = input_oid
    mod.datastore['OIDVALUE'] = 'module-write-proof'
    mod.datastore['COMMUNITY'] = 'private'
    allow(mod).to receive(:connect_snmp).and_return(manager)
    allow(mod).to receive(:disconnect_snmp)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_error)
    # Exercise the same numeric parser as Manager#get_value, while the
    # separate Net-SNMP lab verifies actual protocol/write behavior.
    allow(manager).to receive(:get_value) do |oid|
      parsed = SNMP::MIB.new.oid(oid).to_s
      operations << [:get, parsed]
      state.fetch(parsed)
    end
    allow(manager).to receive(:set) do |varbind|
      operations << [:set, varbind.name.to_s, varbind.value.to_s]
      state[varbind.name.to_s] = varbind.value.to_s if error_status == :noError
      double('SNMP response', error_status: error_status)
    end
  end

  ['1.3.6.1.2.1.1.4.0', '.1.3.6.1.2.1.1.4.0'].each do |oid|
    context "with numeric OID #{oid}" do
      let(:input_oid) { oid }

      it 'uses the same canonical object for the initial read, write and readback' do
        mod.run_host('192.0.2.1')

        expect(operations).to eq([
          [:get, canonical_oid],
          [:set, canonical_oid, 'module-write-proof'],
          [:get, canonical_oid]
        ])
      end

      it 'preserves the configured OID for later runs' do
        mod.run_host('192.0.2.1')

        expect(mod.datastore['OID']).to eq(oid)
      end
    end
  end

  ['', '..1.3.6.1.2.1.1.4.0', 'not-an-oid'].each do |oid|
    context "with invalid numeric OID #{oid.inspect}" do
      let(:input_oid) { oid }

      it 'does not issue a SET or claim a changed value' do
        mod.run_host('192.0.2.1')

        expect(manager).not_to have_received(:set)
        expect(mod).not_to have_received(:print_status).with(a_string_including('Check new value'))
        expect(mod).to have_received(:disconnect_snmp)
      end
    end
  end

  context 'when the target denies the write' do
    let(:input_oid) { '.1.3.6.1.2.1.1.4.0' }
    let(:error_status) { :noAccess }

    it 'reports the target denial without claiming successful readback' do
      mod.run_host('192.0.2.1')

      expect(mod).to have_received(:print_status).with(a_string_including('OID not writable or does not provide WRITE access'))
      expect(mod).not_to have_received(:print_status).with(a_string_including('Check new value'))
    end
  end
end
