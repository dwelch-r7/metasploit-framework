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
end
