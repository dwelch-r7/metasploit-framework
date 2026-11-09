require 'rspec'
require 'json'

RSpec.describe 'WordPress Multicall version and option boundaries' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/wordpress_multicall_creds') }

  let(:captures) { JSON.parse(File.read(File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/wordpress_multicall_creds/responses.json'))) }
  let(:scanner) { instance_double(Metasploit::Framework::LoginScanner::WordpressMulticall, scan!: nil) }
  let(:host) { '192.0.2.53' }
  let(:scanner_options) { [] }

  before do
    mod.datastore['RHOSTS'] = host
    mod.datastore['USERNAME'] = 'module_admin'
    mod.datastore['USER_FILE'] = nil
    mod.datastore['CHUNKSIZE'] = 2
    allow(mod).to receive(:wordpress_and_online?).and_return(true)
    allow(mod).to receive(:wordpress_xmlrpc_enabled?).and_return(true)
    allow(mod).to receive(:wordpress_version).and_return(captures.fetch('profiles').fetch('vulnerable').fetch('version'))
    allow(mod).to receive(:passwords).and_return(%w[module-target-wrong-password module-target-password].lazy)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_good)
    allow(mod).to receive(:print_error)
    allow(Metasploit::Framework::LoginScanner::WordpressMulticall).to receive(:new) do |options|
      scanner_options << options
      scanner
    end
  end

  [1, 1700].each do |size|
    it "accepts the valid chunk boundary #{size}" do
      mod.datastore['CHUNKSIZE'] = size

      expect { mod.setup }.not_to raise_error
    end
  end

  [0, -1, 1701].each do |size|
    it "refuses invalid CHUNKSIZE #{size} through the configuration contract" do
      mod.datastore['CHUNKSIZE'] = size

      expect { mod.setup }.to raise_error(Msf::Auxiliary::Failed, /CHUNKSIZE.*(?:1|1700)/)
      expect(mod).not_to have_received(:wordpress_version)
    end
  end

  { 'fixed' => '4.4', 'modern' => '6.8.3' }.each do |profile, version|
    it "uses single attempts for captured #{profile} #{version} that latches the second credential" do
      expect(captures.fetch('profiles').fetch(profile).fetch('wrong_then_right').fetch('statuses')).to eq([403, 403])
      allow(mod).to receive(:wordpress_version).and_return(version)

      mod.run_host(host)

      expect(scanner_options.last.fetch(:chunk_size)).to eq(1)
    end
  end

  it 'retains single attempts for the derived 4.4.1 version boundary' do
    allow(mod).to receive(:wordpress_version).and_return('4.4.1')

    mod.run_host(host)

    expect(scanner_options.last.fetch(:chunk_size)).to eq(1)
  end

  it 'retains batching for the captured vulnerable release that accepts the second credential' do
    expect(captures.fetch('profiles').fetch('vulnerable').fetch('wrong_then_right').fetch('statuses')).to eq([403, 'success'])

    mod.run_host(host)

    expect(scanner_options.last.fetch(:chunk_size)).to eq(2)
  end

  %w[4.3.2 4.2.6 4.1.9 4.0.9 3.9.10 3.8.12 3.7.12].each do |version|
    it "preserves existing batching for source-reviewed older release #{version}" do
      review = captures.fetch('reviewed_older_sources').find { |entry| entry.fetch('version') == version }
      expect(review.fetch('auth_failed_mentions')).to eq(0)
      allow(mod).to receive(:wordpress_version).and_return(version)

      mod.run_host(host)

      expect(scanner_options.last.fetch(:chunk_size)).to eq(2)
    end
  end

  %w[4.4 4.4.1 6.8.3].each do |version|
    it "preserves configured CHUNKSIZE while selecting the effective size for #{version}" do
      allow(mod).to receive(:wordpress_version).and_return(version)

      mod.check_setup

      expect(mod.datastore['CHUNKSIZE']).to eq(2)
    end
  end

  it 'resets the effective size for a legacy host after a protected host without changing configuration' do
    allow(mod).to receive(:wordpress_version).and_return('6.8.3', '4.3.1')

    mod.run_host(host)
    mod.run_host(host)

    expect(scanner_options.map { |options| options.fetch(:chunk_size) }).to eq([1, 2])
  end

  it 'honors an explicit single-password chunk on a legacy host' do
    mod.datastore['CHUNKSIZE'] = 1

    mod.run_host(host)

    expect(scanner_options.last.fetch(:chunk_size)).to eq(1)
  end

  it 'retains refusal of an unrelated product before constructing a scanner' do
    allow(mod).to receive(:wordpress_and_online?).and_return(false)

    mod.run_host(host)

    expect(scanner_options).to be_empty
  end

  it 'retains refusal when the XML-RPC helper reports the endpoint unavailable' do
    allow(mod).to receive(:wordpress_xmlrpc_enabled?).and_return(false)

    mod.run_host(host)

    expect(scanner_options).to be_empty
  end
end
