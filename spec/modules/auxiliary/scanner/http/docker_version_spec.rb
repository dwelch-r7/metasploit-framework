require 'json'

RSpec.describe 'Docker version response validation' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'scanner/http/docker_version') }

  let(:fixture_directory) { File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/scanner/http/docker_version') }
  let(:response) { Rex::Proto::Http::Response.new(200).tap { |value| value.body = body } }
  let(:body) { File.binread(File.join(fixture_directory, 'modern.json')) }

  before do
    mod.datastore['RHOST'] = '192.0.2.10'
    allow(mod).to receive(:send_request_cgi).and_return(response)
    allow(mod).to receive(:report_note)
    allow(mod).to receive(:report_host)
    allow(mod).to receive(:print_error)
  end

  %w[old modern].each do |profile|
    context "with the actual #{profile} daemon response" do
      let(:body) { File.binread(File.join(fixture_directory, "#{profile}.json")) }

      it 'reports the native version and raw host fields' do
        native = JSON.parse(body)

        mod.run_host('192.0.2.10')

        expect(mod).to have_received(:report_note).with(hash_including(host: '192.0.2.10', data: { version: native.fetch('Version') }))
        expect(mod).to have_received(:report_host).with(hash_including(
          host: '192.0.2.10', arch: native.fetch('Arch'), detected_arch: native.fetch('Arch'), os_family: native.fetch('Os'),
          info: "Docker Server v.#{native.fetch('Version')} Kernel Version: #{native.fetch('KernelVersion')}"
        ))
        expect(mod).not_to have_received(:print_error)
      end
    end
  end

  context 'with actual unrelated Apache HTML and HTTP 200' do
    let(:body) { File.binread(File.join(fixture_directory, 'unrelated.html')) }

    it 'does not invent Docker host or note records' do
      mod.run_host('192.0.2.10')

      expect(mod).not_to have_received(:report_note)
      expect(mod).not_to have_received(:report_host)
      expect(mod).to have_received(:print_error).with(/Docker/i)
    end
  end

  context 'with actual unrelated Apache HTTP 404' do
    let(:body) { File.binread(File.join(fixture_directory, 'missing.html')) }
    let(:response) { Rex::Proto::Http::Response.new(404).tap { |value| value.body = body } }

    it 'does not report a Docker version' do
      mod.run_host('192.0.2.10')

      expect(mod).not_to have_received(:report_note)
    end
  end

  context 'when the server does not respond' do
    let(:response) { nil }

    it 'does not report a Docker version' do
      mod.run_host('192.0.2.10')

      expect(mod).not_to have_received(:report_note)
    end
  end

  {
    'a derived missing version' => ->(document) { document.except('Version') },
    'a derived blank version' => ->(document) { document.merge('Version' => ' ') },
    'a derived numeric version' => ->(document) { document.merge('Version' => 28) },
    'a derived missing API version' => ->(document) { document.except('ApiVersion') },
    'a derived numeric API version' => ->(document) { document.merge('ApiVersion' => 1.48) },
    'a derived malformed API version' => ->(document) { document.merge('ApiVersion' => 'one') },
    'a derived array document' => ->(_document) { [] },
    'a derived string document' => ->(_document) { 'Docker' },
    'a derived null document' => ->(_document) {}
  }.each do |label, transform|
    context "with #{label}" do
      let(:body) { JSON.generate(transform.call(JSON.parse(File.binread(File.join(fixture_directory, 'modern.json'))))) }

      it 'rejects the document without reporting or raising a parser error' do
        mod.run_host('192.0.2.10')

        expect(mod).not_to have_received(:report_note)
        expect(mod).not_to have_received(:report_host)
      end
    end
  end
end
