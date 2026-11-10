require 'acceptance_spec_helper'

RSpec.describe 'Real SMB Group Policy Preference files', smb_profile: 'gpp' do
  include_context 'Samba directory target'

  configurations = %w[direct session].product([true, false]).map { |mode, store| [mode, store, nil] }
  configurations += %w[1 2].map { |version| ['direct', true, version] }
  configurations.each do |mode, store, version|
    it "recovers all9 actual policy files and usable passwords twice through #{mode} STORE=#{store}#{version && " SMB#{version}"}" do
      session_id = smb_session('directory_reader') if mode == 'session'
      original = nil
      2.times do
        before = loot_files
        options = { 'STORE' => store }
        options['SMB::ProtocolVersion'] = version if version
        output = gather('smb_enum_gpp', mode, 'directory_reader', options, session_id: session_id)
        expect(output.scan('Group Policy Credential Info').size).to eq(9)
        expect(output.scan(/Parsing file: ([^\r\n]+)/).size).to eq(9)
        # Console buffers are binary. Require the exact UTF-8 password bytes.
        policies.fetch('files').map { |item| item.fetch('password') }.uniq.each { |password| expect(output.b).to include(password.b) }
        expect(output.scan(/DATASOURCE\s+ModuleTargetDSN/).size).to eq(2)
        new_files = loot_files - before
        expected_bytes = store ? policies.fetch('files').flat_map { |item| [item.fetch('sha256')] * 2 } : []
        expect(new_files.map { |path| Digest::SHA256.file(path).hexdigest }.sort).to eq(expected_bytes.sort)
        rows = credentials.select { |row| row.fetch('module_full_name') == 'auxiliary/scanner/smb/smb_enum_gpp' }
        expect(rows.map { |row| row.fetch('username') }).to eq(%w[policy_user unicode_user])
        rows.each do |row|
          expect(row.values_at('password', 'private_type', 'realm', 'status', 'address', 'port', 'proto', 'name')).to eq([accounts.fetch(row.fetch('username')), 'Metasploit::Credential::Password', 'DIRLAB', 'Untried', target_runtime.fetch('module_endpoints').fetch('samba').fetch('host'), 445, 'tcp', 'smb'])
          actual = account_proof(row)
          expect(actual).to eq("Module target native policy account proof\n")
        end
        expect(rows).to eq(original) if original
        original = rows
        expect(notes).to eq([])
        verify_session(session_id) if session_id
      end
    end
  end

  {
    'EMPTY' => 'Could not find the domain folder',
    'EMPTY_POLICIES' => nil,
    'PROTECTED' => 'STATUS_ACCESS_DENIED',
    'MISSING_SHARE' => 'STATUS_BAD_NETWORK_NAME'
  }.each do |share, error|
    it "handles actual #{share} share state twice without credentials or loot" do
      2.times do
        before = loot_files
        output = gather('smb_enum_gpp', 'direct', 'directory_reader', { 'SMBSHARE' => share }, negative: !error.nil?)
        expect(output).to include(error) if error
        expect(output).not_to include('Group Policy Credential Info', 'XML file saved to:')
        expect(loot_files).to eq(before)
        expect(credentials).to eq([])
        expect(notes).to eq([])
      end
    end
  end

  it 'rejects a wrong password twice before reading policies' do
    2.times do
      before = loot_files
      output = gather('smb_enum_gpp', 'direct', 'directory_reader', { 'SMBPass' => 'public-wrong-password' }, negative: true)
      expect(output).to include('STATUS_LOGON_FAILURE')
      expect(output).not_to include('Group Policy Credential Info')
      expect(loot_files).to eq(before)
      expect(credentials).to eq([])
    end
  end

  it 'recovers exact policy files over genuine NetBIOS139 twice' do
    2.times do
      before = loot_files
      output = gather('smb_enum_gpp', 'direct', 'directory_reader', { 'RPORT' => 139, 'SMBDirect' => false })
      expect(output.scan('Group Policy Credential Info').size).to eq(9)
      expect(output.b).to include(accounts.fetch('unicode_user').b)
      expect((loot_files - before).map { |path| Digest::SHA256.file(path).hexdigest }.sort).to eq(policies.fetch('files').flat_map { |item| [item.fetch('sha256')] * 2 }.sort)
      rows = credentials
      expect(rows.map { |row| row.values_at('username', 'password', 'port', 'status') }).to eq(%w[policy_user unicode_user].map { |user| [user, accounts.fetch(user), 139, 'Untried'] })
    end
  end

  def account_proof(row)
    arguments = ['smbclient', '--configfile=/opt/module-target-client.conf', '//samba/SESSION', '-U', "DIRLAB\\#{row.fetch('username')}%#{row.fetch('password')}", '-c', 'get account-proof.txt /dev/stdout']
    output, error, status = Open3.capture3(*target_runtime.fetch('compose'), 'exec', '-T', 'client', *arguments)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-account-proof.jsonl'), 'a') do |log|
      log.puts(JSON.generate(argv: arguments, exitstatus: status.exitstatus, stdout_base64: Base64.strict_encode64(output), stderr_base64: Base64.strict_encode64(error)))
    end
    expect(status.exitstatus).to eq(0), "Account proof SMB read failed (exit #{status.exitstatus}): #{output}#{error}"
    expect(error).to match(%r{\Agetting file \\account-proof\.txt of size 42 as /dev/stdout \([\d.]+ KiloBytes/sec\) \(average [\d.]+ KiloBytes/sec\)\r?\n\z})
    output
  end
end
