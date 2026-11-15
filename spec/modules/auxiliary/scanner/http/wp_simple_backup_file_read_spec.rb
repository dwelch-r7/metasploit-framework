require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Simple Backup public scanner check contract' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('SIMPLE_BACKUP_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_simple_backup_file_read.rb', __dir__))
    scope.module_eval(File.binread(source), source)
    recorded = requests
    response = version_response
    boundary = Module.new do
      define_method(:send_request_cgi) do |options, *_arguments|
        recorded << { receiver: self, datastore: datastore, options: options }
        response
      end
      %i[setup cleanup report_failure report_wordpress_service].each do |method|
        define_method(method) { nil }
      end
    end
    scope.const_get(:MetasploitModule).tap do |klass|
      klass.include(Msf)
      klass.prepend(boundary)
    end
  end
  let(:version_response) { response(200, "=== Simple Backup ===\r\nStable tag: 2.7.10\r\n") }
  let(:requests) { [] }
  let(:listener) { double('JobListener', waiting: nil, start: nil, completed: nil, failed: nil) }
  let(:events) { double('FrameworkEvents', on_module_run: nil, on_module_complete: nil) }
  let(:framework) { double('Framework', events: events, datastore: Msf::DataStore.new) }

  before do
    allow(owner_class).to receive(:framework).and_return(framework)
    mod.datastore.merge!('RHOSTS' => '192.0.2.10', 'RHOST' => '192.0.2.10', 'RPORT' => 80, 'SSL' => false, 'TARGETURI' => '/')
  end

  # HTTP, setup/cleanup, reporting and framework events are explicit doubles.
  # Capability discovery, public check_simple dispatch, validation, real replicant,
  # WordPress version extraction and Rex::Version comparisons remain real.
  # Affected text is reduced from the official 2.7.10 ZIP, not an HTTP capture:
  # exact name and Stable tag lines retain their original CRLF. Full readme SHA256:
  # 708541021085d98ccbec10a3c2006481c857327c17d35012ad6bb80c8a6878fe.
  # Source: https://downloads.wordpress.org/plugin/simple-backup.2.7.10.zip
  # Fixed 2.7.11, missing and unversioned documents are synthetic boundaries.

  def response(code, body)
    Rex::Proto::Http::Response.new(code).tap { |result| result.body = body }
  end

  def public_check
    Msf::Simple::Auxiliary.check_simple(mod, 'RunAsJob' => false, 'JobListener' => listener)
  end

  it 'advertises check support through the scanner capability API' do
    expect(mod.has_check?).to be(true)
  end

  it 'preserves the direct public check result' do
    expect(mod.check).to eq(Msf::Exploit::CheckCode::Appears)
  end

  it 'dispatches direct check to the version helper on a distinct replicant' do
    mod.check
    expect(requests.first.fetch(:receiver)).not_to equal(mod)
    expect(requests.first.fetch(:datastore)).not_to equal(mod.datastore)
    expect(requests.first.fetch(:options)).to include('uri' => '/wp-content/plugins/simple-backup/readme.txt')
  end

  it 'completes the public scanner check for affected 2.7.10' do
    result = public_check
    expect(result).to eq(Msf::Exploit::CheckCode::Appears)
    expect(listener).to have_received(:completed).with(anything, result, mod)
    expect(listener).not_to have_received(:failed)
  end

  context 'with the synthetic fixed version' do
    let(:version_response) { response(200, 'Stable tag: 2.7.11') }

    it 'returns Safe through the public scanner dispatch' do
      expect(public_check).to eq(Msf::Exploit::CheckCode::Safe)
    end
  end

  context 'without a response' do
    let(:version_response) { nil }

    it 'preserves the version helper Unknown result and readme variants' do
      expect(public_check).to have_attributes(code: 'unknown', reason: 'No response')
      expect(requests.map { |row| row.fetch(:options).fetch('uri') }).to eq(['/wp-content/plugins/simple-backup/readme.txt', '/wp-content/plugins/simple-backup/Readme.txt', '/wp-content/plugins/simple-backup/README.txt'])
    end
  end

  context 'without a version in a successful document' do
    let(:version_response) { response(200, 'No version is available') }

    it 'preserves the version helper Detected result' do
      expect(public_check).to have_attributes(code: 'detected', reason: 'Could not identify the version number')
    end
  end

  it 'preserves selected host, prefix, content directory and operator settings' do
    mod.datastore.merge!('RHOST' => '192.0.2.11', 'TARGETURI' => '/wordpress/', 'WPCONTENTDIR' => 'custom-content')
    # check_simple validates options; compare already-normalized configuration.
    mod.validate
    settings = mod.datastore.to_h.dup
    expect(public_check).to eq(Msf::Exploit::CheckCode::Appears)
    expect(requests.first.fetch(:datastore)['RHOST']).to eq('192.0.2.11')
    expect(requests.first.fetch(:options)).to include('uri' => '/wordpress/custom-content/plugins/simple-backup/readme.txt')
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'creates a fresh replicant for repeated public checks' do
    2.times { expect(public_check).to eq(Msf::Exploit::CheckCode::Appears) }
    expect(requests.map { |row| row.fetch(:receiver).object_id }.uniq.size).to eq(2)
    expect(requests.none? { |row| row.fetch(:receiver).equal?(mod) }).to be(true)
  end
end
