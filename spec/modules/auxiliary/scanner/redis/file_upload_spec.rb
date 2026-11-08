require 'rspec'

RSpec.describe 'Redis File Upload' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) do
    load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/redis/file_upload')
  end

  let(:ip) { '192.0.2.1' }
  # RESP responses captured from redis:6.2.14 and redis:7.2.4 on November 8, 2026.
  let(:filename_response) { "*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb" }
  let(:protection_response) { '*0' }

  before do
    allow(mod).to receive(:connect)
    allow(mod).to receive(:disconnect)
    allow(mod).to receive(:report_redis)
    allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'dbfilename').and_return(filename_response)
    allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'enable-protected-configs').and_return(protection_response)
    allow(mod).to receive(:redis_command).with('INFO', 'server').and_return(nil)
  end

  it 'exposes the scanner check to the console' do
    expect(mod.has_check?).to be true
  end

  it 'reports readable legacy configuration as Appears without proving a write' do
    expect(mod.check_host(ip).code).to eq('appears')
  end

  it 'only sends read commands during check' do
    expect(mod).not_to receive(:redis_command).with('CONFIG', 'SET', anything, anything)
    mod.check_host(ip)
  end

  context 'when Redis protects snapshot configuration' do
    let(:protection_response) { "*2\r\n$24\r\nenable-protected-configs\r\n$2\r\nno" }

    it 'returns Safe' do
      expect(mod.check_host(ip).code).to eq('safe')
    end
  end

  context 'when protected configuration changes are enabled' do
    let(:protection_response) { "*2\r\n$24\r\nenable-protected-configs\r\n$3\r\nyes" }

    it 'returns Appears' do
      expect(mod.check_host(ip).code).to eq('appears')
    end
  end

  context 'when protected configuration requires a local connection' do
    let(:protection_response) { "*2\r\n$24\r\nenable-protected-configs\r\n$5\r\nlocal" }

    it 'explains the restriction without claiming a verified write' do
      expect(mod.check_host(ip).reason).to include('require a local connection', 'has not been verified')
    end
  end

  context 'when the snapshot configuration request receives no response' do
    let(:filename_response) { nil }

    it 'returns Unknown' do
      expect(mod.check_host(ip).code).to eq('unknown')
    end
  end

  context 'when CONFIG is disabled' do
    let(:filename_response) { "-ERR unknown command 'CONFIG'" }

    it 'returns Safe' do
      expect(mod.check_host(ip).code).to eq('safe')
    end
  end

  context 'when the policy request receives no response' do
    let(:protection_response) { nil }

    it 'returns Unknown' do
      expect(mod.check_host(ip).code).to eq('unknown')
    end
  end

  context 'when configuration data is malformed' do
    let(:filename_response) { '*invalid' }

    it 'returns Unknown' do
      expect(mod.check_host(ip).code).to eq('unknown')
    end
  end

  context 'when configuration data is truncated' do
    let(:filename_response) { "*2\r\n$10\r\ndbfilename" }

    it 'returns Unknown' do
      expect(mod.check_host(ip).code).to eq('unknown')
    end
  end

  context 'when Redis is temporarily unable to answer CONFIG GET' do
    let(:filename_response) { '-LOADING Redis is loading the dataset in memory' }

    it 'returns Unknown' do
      expect(mod.check_host(ip).code).to eq('unknown')
    end
  end

  it 'returns Unknown on a connection error' do
    allow(mod).to receive(:connect).and_raise(Rex::ConnectionRefused)
    expect(mod.check_host(ip).code).to eq('unknown')
  end

  it 'returns Unknown when authentication is required but not configured' do
    allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'dbfilename').and_raise(Msf::Auxiliary::Failed, 'Password unset')
    expect(mod.check_host(ip).code).to eq('unknown')
  end

  it 'disconnects after a failed check' do
    allow(mod).to receive(:connect).and_raise(Rex::ConnectionRefused)
    expect(mod).to receive(:disconnect)
    mod.check_host(ip)
  end

  describe '#run_host' do
    before do
      mod.datastore['LocalFile'] = '/tmp/redis-upload.txt'
      mod.datastore['RemoteFile'] = '/tmp/redis-upload.rdb'
      mod.instance_variable_set(:@upload_content, 'file content')
    end

    it 'uploads when the passive check returns Appears' do
      allow(mod).to receive(:check_host).with(ip).and_return(Msf::Exploit::CheckCode::Appears('Configuration readable'))
      expect(mod).to receive(:send_file).with('/tmp/redis-upload.rdb', 'file content')
      mod.run_host(ip)
    end

    it 'does not upload when protected configuration makes the check Safe' do
      allow(mod).to receive(:check_host).with(ip).and_return(Msf::Exploit::CheckCode::Safe('Configuration protected'))
      expect(mod).not_to receive(:send_file)
      mod.run_host(ip)
    end
  end

  describe '#send_file' do
    let(:temporary_key) { 'module-upload-key' }
    let(:save_error) { '-ERR' }

    before do
      mod.datastore['RHOSTS'] = ip
      allow(Rex::Text).to receive(:rand_text_alpha).with(32).and_return(temporary_key)
      allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'dir').and_return("*2\r\n$3\r\ndir\r\n$5\r\n/data")
      allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'rdbcompression').and_return("*2\r\n$14\r\nrdbcompression\r\n$3\r\nyes")
      allow(mod).to receive(:redis_command).with('CONFIG', 'SET', anything, anything).and_return('+OK')
      allow(mod).to receive(:redis_command).with('SET', temporary_key, 'file content').and_return('+OK')
      allow(mod).to receive(:redis_command).with('SETNX', temporary_key, 'file content').and_return(':1')
      allow(mod).to receive(:redis_command).with('DEL', temporary_key).and_return(':1')
      allow(mod).to receive(:redis_command).with('SAVE').and_return('+OK')
    end

    context 'when saving the uploaded file fails' do
      before do
        allow(mod).to receive(:redis_command).with('SAVE').and_return(save_error)
      end

      it 'restores the snapshot directory' do
        expect(mod).to receive(:redis_command).with('CONFIG', 'SET', 'dir', '/data').and_return('+OK')
        mod.send_file('/proc/upload.rdb', 'file content')
      end

      it 'restores the snapshot filename' do
        expect(mod).to receive(:redis_command).with('CONFIG', 'SET', 'dbfilename', 'dump.rdb').and_return('+OK')
        mod.send_file('/proc/upload.rdb', 'file content')
      end

      it 'restores compression' do
        expect(mod).to receive(:redis_command).with('CONFIG', 'SET', 'rdbcompression', 'yes').and_return('+OK')
        mod.send_file('/proc/upload.rdb', 'file content')
      end

      it 'deletes only the temporary key' do
        expect(mod).to receive(:redis_command).with('DEL', temporary_key).and_return(':1')
        mod.send_file('/proc/upload.rdb', 'file content')
      end

      it 'reports the actual save error' do
        expect(mod).to receive(:print_error).with(include('Failed to save', save_error))
        mod.send_file('/proc/upload.rdb', 'file content')
      end

      it 'continues cleanup after a configuration restore error' do
        allow(mod).to receive(:redis_command).with('CONFIG', 'SET', 'dir', '/data').and_raise(Rex::ConnectionRefused)
        expect(mod).to receive(:redis_command).with('DEL', temporary_key).and_return(':1')
        mod.send_file('/proc/upload.rdb', 'file content')
      end
    end

    it 'restores configuration if setting the destination filename fails' do
      allow(mod).to receive(:redis_command).with('CONFIG', 'SET', 'dbfilename', '..').and_return('-ERR Invalid filename')
      expect(mod).to receive(:redis_command).with('CONFIG', 'SET', 'dir', '/data').and_return('+OK')
      mod.send_file('/tmp/..', 'file content')
    end

    it 'does not delete an existing key when temporary key creation is rejected' do
      allow(mod).to receive(:redis_command).with('SETNX', temporary_key, 'file content').and_return(':0')
      expect(mod).not_to receive(:redis_command).with('DEL', temporary_key)
      mod.send_file('/tmp/upload.rdb', 'file content')
    end

    it 'does not mutate target settings when the original configuration is unavailable' do
      allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'dir').and_return(nil)
      expect(mod).not_to receive(:redis_command).with('CONFIG', 'SET', anything, anything)
      mod.send_file('/tmp/upload.rdb', 'file content')
    end

    it 'leaves compression alone when disabling it was not requested' do
      mod.datastore['DISABLE_RDBCOMPRESSION'] = false
      expect(mod).not_to receive(:redis_command).with('CONFIG', 'GET', 'rdbcompression')
      mod.send_file('/tmp/upload.rdb', 'file content')
    end

    it 'leaves compression alone when it is already disabled' do
      allow(mod).to receive(:redis_command).with('CONFIG', 'GET', 'rdbcompression').and_return("*2\r\n$14\r\nrdbcompression\r\n$2\r\nno")
      expect(mod).not_to receive(:redis_command).with('CONFIG', 'SET', 'rdbcompression', anything)
      mod.send_file('/tmp/upload.rdb', 'file content')
    end

    it 'persists the cleaned dataset only after a successful upload and key removal' do
      expect(mod).to receive(:redis_command).with('SAVE').ordered.and_return('+OK')
      expect(mod).to receive(:redis_command).with('DEL', temporary_key).ordered.and_return(':1')
      expect(mod).to receive(:redis_command).with('SAVE').ordered.and_return('+OK')
      mod.send_file('/tmp/upload.rdb', 'file content')
    end

    it 'does not persist a temporary key when cleanup cannot remove it' do
      allow(mod).to receive(:redis_command).with('DEL', temporary_key).and_return('-NOPERM Permission denied')
      expect(mod).to receive(:redis_command).with('SAVE').once.and_return('+OK')
      mod.send_file('/tmp/upload.rdb', 'file content')
    end
  end
end
