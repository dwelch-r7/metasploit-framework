require 'rspec'
require 'csv'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Dolibarr contact export and detection contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/http/dolibarr_16_contact_dump.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:contact) do
    {
      'db' => { 'type' => 'mysqli', 'database_name' => 'dolibarr', 'database_user' => 'module_app', 'database_host' => 'database', 'database_port' => '3306' },
      'id' => '1', 'firstname' => 'Alpha Ω', 'lastname' => 'Fixture "Quoted"', 'email' => 'alpha@example.invalid',
      'note_public' => "Public line one\n  line two, \"quoted\"  \n", 'note_private' => "  Private's note Ω  "
    }
  end
  let(:document) { { 'contacts' => [contact] } }
  let(:check_body) do
    <<~HTML
      <meta name="author" content="Dolibarr Development Team">
      <div class="login_table_title center" title="Dolibarr 16.0.4">
      <a class="login_table_title" href="https://www.dolibarr.org" target="_blank" rel="noopener noreferrer external">Dolibarr 16.0.4</a></div>
    HTML
  end
  let(:check_response) { response(200, check_body) }
  let(:loot) { [] }
  let(:requests) { [] }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    allow(mod).to receive_messages(print_good: nil, print_error: nil)
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/loot/dolibarr-export'
    end
    allow(mod).to receive(:send_request_cgi) do |options, *_arguments|
      requests << options
      response(200, document.to_json)
    end
    allow(mod).to receive(:send_request_cgi!) { check_response }
  end

  # Element/scalar projections from the genuine 16.0.4 root capture:
  # tmp/module-target-tests/20261113T002132-ed7996/dolibarr_16_0_4/native-http.jsonl.
  # Contact response SHA256: 2e949e878afc77de419fb5162ef07b8e35fb3115be03a674adefc7335f66da30.
  # The before-owning-call public note has two LF bytes (no literal backslash-n);
  # private notes have outer spaces. Fields not needed by these cases are omitted.
  # HTTP/loot persistence are doubles. Owner init, response JSON parsing and
  # CSV generation/parsing are real; no Framework, database or target runtime.

  def response(status, body)
    Rex::Proto::Http::Response.new(status).tap { |result| result.body = body }
  end

  def csv_export
    mod.run_host('192.0.2.1')
    CSV.parse(loot.find { |entry| entry[1] == 'application/csv' }.fetch(3), headers: true)
  end

  describe 'CSV values' do
    it 'preserves the native private note outer whitespace' do
      expect(csv_export.first['note_private']).to eq(contact.fetch('note_private'))
    end

    it 'preserves native public-note quotes and actual newline bytes' do
      expect(csv_export.first['note_public']).to eq(contact.fetch('note_public'))
    end

    context 'with actual line breaks at scalar boundaries' do
      before { contact['note_public'] = "\n  Synthetic CSV boundary, \"quoted\" Ω\r\n" }

      it 'round-trips the complete scalar through the real CSV parser' do
        expect(csv_export.first['note_public']).to eq(contact.fetch('note_public'))
      end
    end

    it 'keeps connection metadata outside the CSV' do
      expect(csv_export.headers).not_to include('db')
    end

    it 'retains the complete input projection in JSON loot' do
      mod.run_host('192.0.2.1')

      expect(JSON.parse(loot.find { |entry| entry[1] == 'application/json' }.fetch(3))).to eq(document)
    end

    it 'keeps the context prefix, bare-percent request and default port' do
      mod.datastore['TARGETURI'] = '/crm'
      mod.run_host('192.0.2.1')

      expect([requests.first.fetch('uri'), requests.first.fetch('vars_get'), mod.rport]).to eq(['/crm/public/ticket/ajax/ajax.php', { 'action' => 'getContacts', 'email' => '%' }, 80])
    end
  end

  describe 'check results' do
    it 'preserves the native affected-version result' do
      expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Appears.code)
    end

    context 'with the native fixed version' do
      let(:check_body) { super().gsub('16.0.4', '16.0.5') }

      it 'preserves the fixed-version result' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Safe.code)
      end
    end

    context 'with the genuine product marker but no disclosed version' do
      let(:check_body) { '<meta name="author" content="Dolibarr Development Team">' }

      it 'reports Detected with a version-unavailable reason' do
        result = mod.check_host('192.0.2.1')

        expect([result.code, result.reason]).to eq([Msf::Exploit::CheckCode::Detected.code, 'Dolibarr detected, but its version is unavailable'])
      end
    end

    context 'with the genuine unrelated static-site response' do
      # Unchanged native body; SHA256352cf67b00c84c8f97cba71b034c35f6b8d61c42f55982e32507b72b72b3194e.
      let(:check_body) { "<!doctype html><html lang=\"en\"><title>Module target static site</title><body><h1>Unrelated static site</h1></body></html>\n" }

      it 'does not invent Dolibarr detection' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Unknown.code)
      end
    end

    context 'with an incidental product-name mention' do
      let(:check_body) { '<html><body>A guide mentions Dolibarr.</body></html>' }

      it 'requires product-specific evidence' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Unknown.code)
      end
    end

    context 'without a response' do
      let(:check_response) { nil }

      it 'returns Unknown without raising' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Unknown.code)
      end
    end

    context 'with a nullable HTTP200 body' do
      let(:check_body) { nil }

      it 'returns Unknown without raising' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Unknown.code)
      end
    end

    context 'with HTTP403' do
      let(:check_response) { response(403, check_body) }

      it 'does not infer a patched target from an inaccessible page' do
        expect(mod.check_host('192.0.2.1').code).to eq(Msf::Exploit::CheckCode::Unknown.code)
      end
    end

    context 'with HTTP500' do
      let(:check_response) { response(500, check_body) }

      it 'returns Unknown with the failed status' do
        result = mod.check_host('192.0.2.1')

        expect([result.code, result.reason]).to eq([Msf::Exploit::CheckCode::Unknown.code, 'Dolibarr check returned HTTP 500'])
      end
    end
  end
end
