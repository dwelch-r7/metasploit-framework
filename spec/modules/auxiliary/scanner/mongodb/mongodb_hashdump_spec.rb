require 'rspec'
require 'json'

RSpec.describe 'MongoDB Hash Extractor' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/mongodb/mongodb_hashdump')
  end

  # Public lab accounts only: native mongo shell captures from MongoDB 2.6.12
  # (November 9, 2026) and 4.4.30 (November 8, 2026). The former is an unprojected
  # admin.system.users.find({}); the latter projects user, db and credentials.
  # Images: mongo:2.6.12@sha256:08e199598f4f874d14b4f90727dade0384b0fcfe8479355ed2cc5391c46e8ece
  # and mongo:4.4.30@sha256:4be76f674fc4b27859816811b8baa3c51830eb1dbf4ca81a51e26b79edd662ef.
  let(:native_users) do
    JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/mongodb_system_users.json')))
  end
  let(:documents) { native_users.fetch('2.6.12') }
  let(:stored_credentials) { [] }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['DB'] = 'admin'
    allow(mod).to receive(:mongodb_query_all).and_return(documents)
    allow(mod).to receive(:myworkspace_id).and_return(nil)
    allow(mod).to receive(:create_credential) { |credential| stored_credentials << credential.slice(:username, :private_data) }
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_good)
  end

  describe '#dump_system_users' do
    it 'stores the credential digests from native MongoDB 2.6 user records' do
      mod.dump_system_users

      expect(stored_credentials).to eq([
        { username: 'rootuser', private_data: '97b25313b1738028ec31be085a8b9480' },
        { username: 'testuser', private_data: '19c8747ac7b3654045c99bea032d61be' }
      ])
    end

    it 'prints the native MongoDB 2.6 credential digests with their users' do
      mod.dump_system_users

      expect(mod).to have_received(:print_good).with(a_string_matching(/MONGODB-CR.*rootuser\s+97b25313b1738028ec31be085a8b9480.*MONGODB-CR.*testuser\s+19c8747ac7b3654045c99bea032d61be/m))
    end

    context 'when both legacy credential locations are present' do
      # Synthetic compatibility variant: the native 2.6 record has no pwd field.
      let(:documents) { [native_users.fetch('2.6.12').first.merge('pwd' => 'older-password-digest')] }

      it 'prefers the MONGODB-CR credential over the older pwd field' do
        mod.dump_system_users

        expect(stored_credentials).to eq([{ username: 'rootuser', private_data: '97b25313b1738028ec31be085a8b9480' }])
      end
    end

    context 'when only the older pwd field is present' do
      # Exercise the pre-2.6 fallback without claiming a native pre-2.6 capture.
      let(:documents) do
        [native_users.fetch('2.6.12').first.except('credentials').merge('pwd' => '97b25313b1738028ec31be085a8b9480')]
      end

      it 'continues storing the pwd digest' do
        mod.dump_system_users

        expect(stored_credentials).to eq([{ username: 'rootuser', private_data: '97b25313b1738028ec31be085a8b9480' }])
      end
    end

    context 'when a user has no supported credential' do
      let(:documents) { [native_users.fetch('2.6.12').first.except('credentials')] }

      it 'does not store a credential' do
        mod.dump_system_users

        expect(stored_credentials).to be_empty
      end
    end

    context 'with native MongoDB 4.4 SCRAM credentials' do
      let(:documents) { native_users.fetch('4.4.30') }

      it 'preserves both SCRAM hash formats' do
        mod.dump_system_users

        expect(stored_credentials).to eq([
          { username: 'rootuser', private_data: '$mongodb-scram$*0*cm9vdHVzZXI=*10000*LzPB9KVCpbDieHBrl/2Yhg==*zrhXuqr54Jcd6QVUi5eB6j6lOIk=' },
          { username: 'rootuser', private_data: '$mongodb-scram$*1*cm9vdHVzZXI=*15000*LgFRKmI+2Su9yZP/mAT05H+WbxVZNrv0i/YSnA==*EqgR1z1JnchMGIP8TEJTXK3gJta7wq8YtrkgyDUnFyk=' }
        ])
      end
    end

    context 'when SCRAM-SHA-1 and legacy fields are present' do
      let(:documents) do
        doc = native_users.fetch('2.6.12').first
        scram = native_users.fetch('4.4.30').first.fetch('credentials').slice('SCRAM-SHA-1')
        [doc.merge('credentials' => doc.fetch('credentials').merge(scram), 'pwd' => 'older-password-digest')]
      end

      it 'only stores SCRAM-SHA-1' do
        mod.dump_system_users

        expect(stored_credentials).to eq([
          { username: 'rootuser', private_data: '$mongodb-scram$*0*cm9vdHVzZXI=*10000*LzPB9KVCpbDieHBrl/2Yhg==*zrhXuqr54Jcd6QVUi5eB6j6lOIk=' }
        ])
      end
    end

    context 'when SCRAM-SHA-256 and legacy fields are present' do
      let(:documents) do
        doc = native_users.fetch('2.6.12').first
        scram = native_users.fetch('4.4.30').first.fetch('credentials').slice('SCRAM-SHA-256')
        [doc.merge('credentials' => doc.fetch('credentials').merge(scram), 'pwd' => 'older-password-digest')]
      end

      it 'only stores SCRAM-SHA-256' do
        mod.dump_system_users

        expect(stored_credentials).to eq([
          { username: 'rootuser', private_data: '$mongodb-scram$*1*cm9vdHVzZXI=*15000*LgFRKmI+2Su9yZP/mAT05H+WbxVZNrv0i/YSnA==*EqgR1z1JnchMGIP8TEJTXK3gJta7wq8YtrkgyDUnFyk=' }
        ])
      end
    end
  end
end
