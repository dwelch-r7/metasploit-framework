require 'rspec'

RSpec.describe 'OpenSSH credential collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'multi/gather/ssh_creds') }

  let(:session) { double('shell session', type: 'shell') }
  let(:home) { '/home/lab user' }
  let(:path) { "#{home}/.ssh" }
  let(:key) { double('SSH key', key_object: 'native private key bytes') }

  before do
    allow(mod).to receive_messages(session: session, session_db_id: 42, myworkspace_id: 7)
    allow(mod).to receive(:get_users).and_return([{ name: 'labuser', dir: home }])
    allow(mod).to receive(:executable?).with(path).and_return(true)
    allow(mod).to receive(:readable?).and_return(true)
    allow(mod).to receive(:read_file).and_return('native private key bytes')
    allow(mod).to receive(:store_loot).and_return('/loot/ssh_id_rsa')
    allow(mod).to receive(:create_credential)
    allow(session).to receive(:escape_arg).with(path).and_return("'/home/lab user/.ssh'")
    allow(mod).to receive(:cmd_exec).and_return("id_rsa\n")
    allow(SSHKey).to receive(:valid_ssh_public_key?).and_return(false)
    allow(SSHKey).to receive(:new).with('native private key bytes', passphrase: '').and_return(key)
  end

  describe '#download_loot' do
    it 'escapes the actual spaced home before listing a shell directory' do
      expect(mod).to receive(:cmd_exec).with("ls -1 '/home/lab user/.ssh'").and_return("id_rsa\n")

      mod.download_loot([path])
    end

    it 'reports the account name instead of the home basename' do
      expect(mod).to receive(:create_credential).with(hash_including(username: 'labuser', private_data: 'native private key bytes'))

      mod.download_loot([path])
    end

    it 'uses the account name for Meterpreter directory entries too' do
      fs = double('filesystem', file: double(separator: '/'), dir: double(entries: %w[. .. id_rsa]))
      allow(session).to receive_messages(type: 'meterpreter', fs: fs)
      expect(mod).not_to receive(:cmd_exec)
      expect(mod).to receive(:create_credential).with(hash_including(username: 'labuser'))

      mod.download_loot([path])
    end

    it 'retains the home basename for accounts absent from the local account file' do
      allow(mod).to receive(:get_users).and_return([])
      expect(mod).to receive(:create_credential).with(hash_including(username: 'lab user'))

      mod.download_loot([path])
    end

    it 'skips a directory without execute permission' do
      allow(mod).to receive(:executable?).with(path).and_return(false)
      expect(mod).not_to receive(:cmd_exec)
      expect(mod).not_to receive(:store_loot)

      mod.download_loot([path])
    end

    it 'skips a file without read permission' do
      allow(mod).to receive(:readable?).with("#{path}/id_rsa").and_return(false)
      expect(mod).not_to receive(:read_file)
      expect(mod).not_to receive(:create_credential)

      mod.download_loot([path])
    end

    it 'keeps public keys as loot without importing them as private credentials' do
      allow(SSHKey).to receive(:valid_ssh_public_key?).and_return(true)
      expect(mod).to receive(:store_loot)
      expect(mod).not_to receive(:create_credential)

      mod.download_loot([path])
    end

    it 'does not create loot for an empty directory listing' do
      allow(mod).to receive(:cmd_exec).and_return('')
      expect(mod).not_to receive(:store_loot)

      mod.download_loot([path])
    end
  end
end
