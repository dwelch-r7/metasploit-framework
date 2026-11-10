require 'acceptance_spec_helper'

RSpec.describe 'Genuine Samba named-pipe interface audit', smb_profile: 'pipes' do
  include_context 'Samba directory target'

  configurations = %w[direct session].product(%w[BROWSER samr module_missing]).map { |mode, pipe| [mode, pipe, nil] }
  configurations += %w[1 2].map { |version| ['direct', 'samr', version] }
  configurations.each do |mode, pipe, version|
    it "audits all215 UUIDs on #{pipe} twice through #{mode}#{version && " SMB#{version}"}" do
      session_id = smb_session('rpc_admin') if mode == 'session'
      baseline = credentials
      expected = @native.fetch('data').fetch('bindings').select { |row| row.fetch('pipe') == pipe && row.fetch('status') == 'OPEN' }.map { |row| [row.fetch('uuid'), row.fetch('version')] }
      original_notes = nil
      2.times do
        options = pipe == 'BROWSER' ? {} : { 'SMBPIPE' => pipe }
        options['SMB::ProtocolVersion'] = version if version
        output = gather('pipe_dcerpc_auditor', mode, 'rpc_admin', options, session_id: session_id)
        attempted = output.scan(/^UUID ([0-9a-f-]+) ([0-9.]+) (?:OPEN VIA|ERROR)/)
        expect(attempted).to eq(JSON.parse(File.read('test/module_targets/smb_directory/pipe_uuids.json')))
        expect(output.scan(/^UUID ([0-9a-f-]+) ([0-9.]+) OPEN VIA #{Regexp.escape(pipe)}$/)).to eq(expected)
        rows = notes
        expect(rows.map { |row| row.fetch('ntype') }).to eq(expected.map { |uuid, interface_version| "UUID #{uuid} #{interface_version}" }.sort)
        rows.each do |row|
          expect(row.values_at('address', 'port', 'proto', 'name')).to eq([target_runtime.fetch('module_endpoints').fetch('samba').fetch('host'), 445, 'tcp', 'smb'])
          expected_data = { uuid: row.fetch('ntype').delete_prefix('UUID '), smb_pipe: pipe }
          # Binary-loaded modules produce binary Strings. Compare the actual
          # serialized Hash values; raw rows must still repeat byte-for-byte.
          # This note comes only from this task-owned daemon and database.
          expect(Marshal.load(Base64.decode64(row.fetch('data')))).to eq(expected_data) # rubocop:disable Security/MarshalLoad
        end
        expect(rows).to eq(original_notes) if original_notes
        original_notes = rows
        expect(credentials).to eq(baseline)
        verify_session(session_id) if session_id
      end
    end
  end

  it 'rejects wrong SMB credentials twice before claiming an open interface' do
    2.times do
      output = gather('pipe_dcerpc_auditor', 'direct', 'rpc_admin', { 'SMBPIPE' => 'samr', 'SMBPass' => 'public-wrong-password' }, negative: true)
      expect(output).to include('STATUS_LOGON_FAILURE')
      expect(output).not_to include('OPEN VIA')
      expect(notes).to eq([])
      expect(credentials).to eq([])
    end
  end
end
