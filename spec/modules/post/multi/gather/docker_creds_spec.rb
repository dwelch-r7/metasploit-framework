require 'rspec'

RSpec.describe 'Docker credential collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'multi/gather/docker_creds') }

  let(:target) { '/home/lab user/.docker/config.json' }
  let(:native_config) { File.binread(File.join(FILE_FIXTURES_PATH, 'modules/post/multi/gather/credential_files/docker-config.json')) }

  before do
    allow(mod).to receive_messages(myworkspace_id: 7, fullname: 'post/multi/gather/docker_creds')
    allow(mod).to receive(:read_file).with(target).and_return(native_config)
    allow(mod).to receive(:create_credential)
  end

  describe '#extract' do
    it 'retains every colon in the password written by the Docker client' do
      expect(mod).to receive(:create_credential).with(hash_including(username: 'registry_root', private_data: 'module-target-root:docker:password', realm_value: '127.0.0.1:5000', filename: target))

      mod.extract(target)
    end

    it 'retains a password without a colon' do
      allow(mod).to receive(:read_file).with(target).and_return('{"auths":{"127.0.0.1:5000":{"auth":"dXNlcjpwYXNz"}}}')
      expect(mod).to receive(:create_credential).with(hash_including(username: 'user', private_data: 'pass'))

      mod.extract(target)
    end

    it 'does not import an empty configuration accepted by Docker' do
      allow(mod).to receive(:read_file).with(target).and_return('')
      expect(mod).not_to receive(:create_credential)

      expect { mod.extract(target) }.not_to raise_error
    end

    it 'handles a file becoming unreadable before it is read' do
      allow(mod).to receive(:read_file).with(target).and_return(nil)
      expect(mod).not_to receive(:create_credential)

      expect { mod.extract(target) }.not_to raise_error
    end

    it 'does not import the empty auth map written by Docker logout' do
      allow(mod).to receive(:read_file).with(target).and_return('{"auths":{}}')
      expect(mod).not_to receive(:create_credential)

      mod.extract(target)
    end
  end

  describe '#download_loot' do
    it 'skips a configuration without read permission' do
      allow(mod).to receive(:file?).with(target).and_return(true)
      allow(mod).to receive(:readable?).with(target).and_return(false)
      expect(mod).not_to receive(:extract)

      mod.download_loot(['/home/lab user/.docker'])
    end
  end
end
