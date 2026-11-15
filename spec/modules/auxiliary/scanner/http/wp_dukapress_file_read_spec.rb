require 'rspec'
require 'msfenv'
require 'msf/base'

RSpec.describe 'DukaPress public scanner check contract' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    scope = Module.new
    source = ENV.fetch('DUKAPRESS_OWNER_SOURCE', File.expand_path('../../../../../modules/auxiliary/scanner/http/wp_dukapress_file_read.rb', __dir__))
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
  let(:version_response) { response(200, 'Stable tag: 2.5.3') }
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
  # The 2.5.3 Stable tag line matches sealed native readme request1 (SHA256
  # 8340994fb7f4a7f1cbdc9e45db566a1f6f34f2ce583bafd88ce02d4b598ab97a).
  # Fixed, missing and unversioned documents are synthetic boundaries.

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
    expect(requests.first.fetch(:options)).to include('uri' => '/wp-content/plugins/dukapress/readme.txt')
  end

  it 'completes the public scanner check for affected 2.5.3' do
    result = public_check
    expect(result).to eq(Msf::Exploit::CheckCode::Appears)
    expect(listener).to have_received(:completed).with(anything, result, mod)
    expect(listener).not_to have_received(:failed)
  end

  context 'with the synthetic fixed version' do
    let(:version_response) { response(200, 'Stable tag: 2.5.4') }

    it 'returns Safe through the public scanner dispatch' do
      expect(public_check).to eq(Msf::Exploit::CheckCode::Safe)
    end
  end

  context 'without a response' do
    let(:version_response) { nil }

    it 'preserves the version helper Unknown result and readme variants' do
      expect(public_check).to have_attributes(code: 'unknown', reason: 'No response')
      expect(requests.map { |row| row.fetch(:options).fetch('uri') }).to eq(['/wp-content/plugins/dukapress/readme.txt', '/wp-content/plugins/dukapress/Readme.txt', '/wp-content/plugins/dukapress/README.txt'])
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
    expect(requests.first.fetch(:options)).to include('uri' => '/wordpress/custom-content/plugins/dukapress/readme.txt')
    expect(mod.datastore.to_h).to eq(settings)
  end

  it 'creates a fresh replicant for repeated public checks' do
    2.times { expect(public_check).to eq(Msf::Exploit::CheckCode::Appears) }
    expect(requests.map { |row| row.fetch(:receiver).object_id }.uniq.size).to eq(2)
    expect(requests.none? { |row| row.fetch(:receiver).equal?(mod) }).to be(true)
  end
end
