require 'msfenv'
require 'msf/base'
require 'rex/text'
require 'rex/parser/ini'

RSpec.describe 'RSYNC credential collection' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = File.expand_path('../../../../../modules/post/multi/gather/rsyncd_creds.rb', __dir__)
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:framework) { double('Framework', datastore: Msf::DataStore.new) }
  let(:session) { double('Command shell session', session_host: '192.0.2.44') }
  let(:credential) { double('Credential core') }
  let(:config_file) { '/etc/rsyncd.conf' }
  let(:fixtures) { File.expand_path('../../../../file_fixtures/modules/post/multi/gather/rsyncd_creds', __dir__) }
  # Exact files read from an Ubuntu 22.04 rsync 3.2.7 daemon on 2026-11-17.
  # Native daemon authenticated download gates passed using these files.
  # Further examples vary these captured inputs explicitly. Session transport,
  # framework access, database persistence and console output are doubled; the
  # owner methods, Rex INI parsing and credential/login construction are real.
  let(:native_config) { File.binread(File.join(fixtures, 'rsyncd.conf')) }
  let(:native_secrets) { File.binread(File.join(fixtures, 'rsyncd.secrets')) }

  before do
    allow(mod).to receive_messages(framework: framework, session: session, session_db_id: 3, myworkspace_id: 7, refname: 'multi/gather/rsyncd_creds')
    allow(mod).to receive(:read_file).and_return(nil)
    allow(mod).to receive(:read_file).with(config_file).and_return(native_config)
    allow(mod).to receive(:read_file).with('/etc/rsyncd.secrets').and_return(native_secrets)
    allow(mod).to receive(:create_credential).and_return(credential)
    allow(mod).to receive(:create_credential_login)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:print_line)
  end

  describe '#dump_rsync_secrets' do
    it 'reads the target configuration through the session before reporting its secret' do
      expect(mod).to receive(:read_file).with(config_file).and_return(native_config)
      expect(mod).to receive(:create_credential).with(hash_including(username: 'labuser', private_data: 'labpassword', realm_value: 'locked')).and_return(credential)

      mod.dump_rsync_secrets(config_file)
    end

    it 'does not open the target configuration on the Framework host' do
      expect(::IO).not_to receive(:readlines).with(config_file)

      mod.dump_rsync_secrets(config_file)
    end

    it 'preserves the session origin and rsync login details' do
      expect(mod).to receive(:create_credential).with(hash_including(origin_type: :session, session_id: 3, post_reference_name: 'multi/gather/rsyncd_creds', private_type: :password, workspace_id: 7)).and_return(credential)
      expect(mod).to receive(:create_credential_login).with({
        address: '192.0.2.44', port: 873, protocol: 'tcp', service_name: 'rsync',
        core: credential, access_level: 'User', status: Metasploit::Model::Login::Status::UNTRIED, workspace_id: 7
      })

      mod.dump_rsync_secrets(config_file)
    end

    it 'skips a missing or unreadable configuration' do
      expect(mod).to receive(:read_file).with(config_file).and_return(nil)
      expect(mod).not_to receive(:create_credential)

      expect { mod.dump_rsync_secrets(config_file) }.not_to raise_error
    end

    it 'skips an empty configuration' do
      expect(mod).to receive(:read_file).with(config_file).and_return('')
      expect(mod).not_to receive(:create_credential)

      expect { mod.dump_rsync_secrets(config_file) }.not_to raise_error
    end

    it 'skips a share without a secrets file directive' do
      allow(mod).to receive(:read_file).with(config_file).and_return(native_config.split("\n[locked]\n").first)
      expect(mod).not_to receive(:read_file).with('/etc/rsyncd.secrets')
      expect(mod).not_to receive(:create_credential)

      mod.dump_rsync_secrets(config_file)
    end

    it 'skips a secrets file that the session cannot read' do
      expect(mod).to receive(:read_file).with('/etc/rsyncd.secrets').and_return(nil)
      expect(mod).not_to receive(:create_credential)

      expect { mod.dump_rsync_secrets(config_file) }.not_to raise_error
    end

    it 'skips an empty secrets file' do
      expect(mod).to receive(:read_file).with('/etc/rsyncd.secrets').and_return('')
      expect(mod).not_to receive(:create_credential)

      mod.dump_rsync_secrets(config_file)
    end

    it 'continues to a readable share after an unreadable secrets file' do
      config = native_config.sub('[locked]', "[unreadable]\nsecrets file = /etc/unreadable.secrets\n\n[locked]")
      allow(mod).to receive(:read_file).with(config_file).and_return(config)
      expect(mod).to receive(:read_file).with('/etc/unreadable.secrets').and_return(nil)
      expect(mod).to receive(:create_credential).with(hash_including(username: 'labuser', private_data: 'labpassword', realm_value: 'locked')).and_return(credential)

      mod.dump_rsync_secrets(config_file)
    end
  end

  describe '#run' do
    before { allow(mod).to receive(:enum_user_directories).and_return(['/root', '/home/lab user']) }

    it 'checks only the configured daemon path when USER_CONFIG is blank' do
      mod.datastore['USER_CONFIG'] = ''
      expect(mod).not_to receive(:enum_user_directories)
      expect(mod).to receive(:read_file).with(config_file).and_return(native_config)
      expect(mod).to receive(:create_credential).with(hash_including(realm_value: 'locked')).and_return(credential)

      mod.setup
      mod.run
    end

    it 'continues from missing default locations to a user configuration' do
      allow(mod).to receive(:read_file).with(config_file).and_return(nil)
      allow(mod).to receive(:read_file).with('/home/lab user/rsyncd.conf').and_return(native_config)
      expect(mod).to receive(:read_file).with('/root/rsyncd.conf').and_return(nil)
      expect(mod).to receive(:create_credential).with(hash_including(realm_value: 'locked')).and_return(credential)

      mod.setup
      mod.run
    end

    it 'uses the selected USER_CONFIG and rereads it on a second execution' do
      mod.datastore['USER_CONFIG'] = '.config/rsyncd.conf'
      allow(mod).to receive(:read_file).with(config_file).and_return(nil)
      expect(mod).to receive(:read_file).with('/root/.config/rsyncd.conf').twice.and_return(native_config)
      expect(mod).to receive(:read_file).with('/home/lab user/.config/rsyncd.conf').twice.and_return(nil)
      expect(mod).to receive(:create_credential).with(hash_including(realm_value: 'locked')).twice.and_return(credential)

      mod.setup
      mod.run
      mod.setup
      mod.run
    end
  end
end
