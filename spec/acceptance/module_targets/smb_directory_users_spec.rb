require 'acceptance_spec_helper'

RSpec.describe 'Samba workstation logged-on users', smb_profile: 'users' do
  include_context 'Samba directory target'

  %w[direct session].each do |mode|
    it "enumerates two genuine local logged-on users twice through #{mode}" do
      session_id = smb_session('rpc_admin') if mode == 'session'
      baseline = credentials
      with_local_users do
        2.times do
          output = gather('smb_enumusers_domain', mode, 'rpc_admin', session_id: session_id)
          expect(output.scan(/Found user: ([^\r\n]+)/).flatten.sort).to eq(%w[DIRLAB\local_alice DIRLAB\local_bob])
          %w[local_alice local_bob].each { |user| expect(output).to include("DIRLAB\\#{user}\t(logon_server: *, other_domains: )") }
          expect(credentials).to eq(baseline)
          expect(notes).to eq([])
          verify_ipc_reporting
          verify_session(session_id) if session_id
        end
      end
    end

    it "returns no logged-on user in the genuine empty state through #{mode}" do
      session_id = smb_session('rpc_admin') if mode == 'session'
      baseline = credentials
      2.times do
        output = gather('smb_enumusers_domain', mode, 'rpc_admin', session_id: session_id)
        expect(output).not_to include('Found user:', 'logon_server:')
        expect(credentials).to eq(baseline)
        expect(notes).to eq([])
        verify_ipc_reporting
        verify_session(session_id) if session_id
      end
    end

    it "reports native nonadministrator RPC denial through #{mode}" do
      expect(native_users('directory_reader', expected_exit: 1).join).to include('WERR_ACCESS_DENIED')
      session_id = smb_session('directory_reader') if mode == 'session'
      baseline = credentials
      2.times do
        output = gather('smb_enumusers_domain', mode, 'directory_reader', session_id: session_id, negative: true)
        # ruby_smb 3.3.25 formats this Win32 WERR value through its NTStatus
        # lookup. Native rpcclient separately proves WERR_ACCESS_DENIED (5).
        expect(output).to include('Error returned with netr_wksta_enum_user: 5 -')
        expect(output).not_to include('Found user:')
        expect(credentials).to eq(baseline)
        expect(notes).to eq([])
        verify_ipc_reporting
        verify_session(session_id) if session_id
      end
    end
  end

  [true, false].each do |populated|
    it "enumerates the #{populated ? 'two-user' : 'empty'} state over genuine NetBIOS port139 twice" do
      operation = lambda do
        2.times do
          output = gather('smb_enumusers_domain', 'direct', 'rpc_admin', { 'RPORT' => 139, 'SMBDirect' => false })
          expected = populated ? %w[DIRLAB\local_alice DIRLAB\local_bob] : []
          expect(output.scan(/Found user: ([^\r\n]+)/).flatten.sort).to eq(expected)
          expect(credentials).to eq([])
          expect(notes).to eq([])
          verify_ipc_reporting(139)
        end
      end
      populated ? with_local_users(&operation) : operation.call
    end
  end

  %w[1 2].each do |version|
    it "enumerates the two-user state twice with forced SMB#{version}" do
      with_local_users do
        2.times do
          output = gather('smb_enumusers_domain', 'direct', 'rpc_admin', { 'SMB::ProtocolVersion' => version })
          expect(output.scan(/Found user: ([^\r\n]+)/).flatten.sort).to eq(%w[DIRLAB\local_alice DIRLAB\local_bob])
          expect(credentials).to eq([])
          expect(notes).to eq([])
          verify_ipc_reporting
        end
      end
    end
  end

  it 'rejects a wrong SMB password twice without invented users' do
    2.times do
      output = gather('smb_enumusers_domain', 'direct', 'rpc_admin', { 'SMBPass' => 'public-wrong-password' }, negative: true)
      expect(output).to include('STATUS_LOGON_FAILURE')
      expect(output).not_to include('Found user:')
      expect(credentials).to eq([])
      expect(notes).to eq([])
    end
  end
end
