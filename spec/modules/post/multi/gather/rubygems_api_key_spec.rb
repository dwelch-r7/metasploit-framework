require 'rspec'

RSpec.describe 'RubyGems credential collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'multi/gather/rubygems_api_key') }

  let(:target) { '/root/.gem/credentials' }
  let(:fixture_dir) { File.join(FILE_FIXTURES_PATH, 'modules/post/multi/gather/credential_files') }

  describe '#extract_key' do
    it 'extracts the exact default key from client-produced YAML with a named host' do
      allow(mod).to receive(:read_file).with(target).and_return(File.binread(File.join(fixture_dir, 'rubygems-legacy.yml')))

      expect(mod.extract_key(target)).to eq('a3ed30e052a10eaa4206cfb528491b37')
    end

    it 'extracts the exact default key from the client-produced XDG file' do
      allow(mod).to receive(:read_file).with(target).and_return(File.binread(File.join(fixture_dir, 'rubygems-xdg.yml')))

      expect(mod.extract_key(target)).to eq('3c21e7c2e93ab8b366a307b4b0df00b0')
    end

    it 'preserves modern prefixed API keys without assuming a hex length' do
      allow(mod).to receive(:read_file).with(target).and_return(":rubygems_api_key: rubygems_0123456789abcdef0123456789abcdef01234567\n")

      expect(mod.extract_key(target)).to eq('rubygems_0123456789abcdef0123456789abcdef01234567')
    end

    it 'retains named-key collection when no default key is present' do
      allow(mod).to receive(:read_file).with(target).and_return(":private_host: test-only-named-key\n")

      expect(mod.extract_key(target)).to eq('test-only-named-key')
    end

    it 'does not return a key for the empty file accepted by the client' do
      allow(mod).to receive(:read_file).with(target).and_return('')

      expect(mod.extract_key(target)).to be_nil
    end

    it 'handles a file becoming unreadable before it is read' do
      allow(mod).to receive(:read_file).with(target).and_return(nil)

      expect(mod.extract_key(target)).to be_nil
    end

    it 'does not instantiate objects from a credential document' do
      allow(mod).to receive(:read_file).with(target).and_return('--- !ruby/object:Object {}')

      expect(mod.extract_key(target)).to be_nil
    end

    it 'handles a malformed credential document' do
      allow(mod).to receive(:read_file).with(target).and_return(':rubygems_api_key: [')

      expect(mod.extract_key(target)).to be_nil
    end
  end

  describe '#run' do
    before do
      allow(mod).to receive(:enum_user_directories).and_return(['/home/lab user'])
      allow(mod).to receive(:file?).and_return(false)
      allow(mod).to receive(:readable?).and_return(true)
    end

    it 'discovers the default XDG credential path used by the current client' do
      path = '/home/lab user/.local/share/gem/credentials'
      allow(mod).to receive(:file?).with(path).and_return(true)
      expect(mod).to receive(:download_key).with([path])

      mod.run
    end

    it 'skips a credential file without read permission' do
      allow(mod).to receive(:file?).with('/home/lab user/.gem/credentials').and_return(true)
      allow(mod).to receive(:readable?).and_return(false)
      expect(mod).not_to receive(:download_key)

      mod.run
    end
  end
end
