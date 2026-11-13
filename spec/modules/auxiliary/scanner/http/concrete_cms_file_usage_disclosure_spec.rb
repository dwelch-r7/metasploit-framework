require 'rspec'
require 'csv'
require 'msfenv'
require 'msf/base'

RSpec.describe 'Concrete CMS file-usage UTF-8 contracts' do
  subject(:mod) { owner_class.new }

  let(:owner_class) do
    source = File.expand_path('../../../../../modules/auxiliary/scanner/http/concrete_cms_file_usage_disclosure.rb', __dir__)
    scope = Module.new
    scope.module_eval(File.binread(source), source)
    scope.const_get(:MetasploitModule).tap { |klass| klass.include(Msf) }
  end
  let(:native_body) do
    <<~HTML
      <div class="ccm-ui">
          <table class="table table-striped">
              <thead>
                  <tr>
                      <td>
                          Page ID                </td>

                      <td>
                          Version                </td>

                      <td>
                          Handle                </td>

                      <td>
                          Location                </td>
                  </tr>
              </thead>

              <tbody>
      \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
                      <tr>
                          <td>
                              266                    </td>

                          <td>
                              2                    </td>

                          <td>
                              module-target-public                    </td>

                          <td>
                              <a target="_blank" href="http://127.0.0.1:52920/module-target-public">
                                  /module-target-public                        </a>
                          </td>
                      </tr>
      \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
                      <tr>
                          <td>
                              267                    </td>

                          <td>
                              1                    </td>

                          <td>
                              module-target-private-Ω                    </td>

                          <td>
                              <a target="_blank" href="http://127.0.0.1:52920/module-target-private-%CE%A9">
                                  /module-target-private-Ω                        </a>
                          </td>
                      </tr>
                          </tbody>
          </table>
      </div>
    HTML
  end
  let(:expected_rows) do
    [
      ['266', '2', 'module-target-public', '/module-target-public'],
      ['267', '1', 'module-target-private-Ω', '/module-target-private-Ω']
    ]
  end
  let(:loot) { [] }
  let(:requests) { [] }
  let(:reports) { [] }
  let(:reply) { response(200, native_body) }

  before do
    mod.datastore['RHOST'] = '192.0.2.1'
    mod.datastore['FID_START'] = 37
    mod.datastore['COUNT'] = 1
    allow(mod).to receive_messages(print_good: nil, print_error: nil, print_status: nil, print_line: nil)
    allow(mod).to receive(:send_request_cgi) do |options|
      requests << options
      reply
    end
    allow(mod).to receive(:store_loot) do |*arguments|
      loot << arguments
      '/loot/concretecms.csv'
    end
    allow(mod).to receive(:report_vuln) { |arguments| reports << arguments }
  end

  # Unmodified body from the genuine 9.5.0 native-usage/37 response in
  # tmp/module-target-tests/20261113T112656-4c1282/concretecms_9_5_0/native-http.jsonl.
  # SHA256: dd65d40ea2847aa9c0b7ecd239ce210206dafc7f5061c26eb7e196f2d473a3c0.
  # Native Content-Type is text/html; charset=UTF-8, without HTML charset metadata.
  # HTTP transport, loot persistence and reporting are doubles. Response wire
  # parsing, owner initialization, Nokogiri HTML parsing and Rex CSV remain real.

  def response(status, body)
    payload = body.to_s.b
    wire = "HTTP/1.1 #{status} Test\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: #{payload.bytesize}\r\n\r\n".b + payload
    Rex::Proto::Http::Response.new.tap { |result| result.parse(wire) }
  end

  def csv_rows
    mod.run_host('192.0.2.1')
    CSV.parse(loot.fetch(0).fetch(3))
  end

  it 'parses the complete native UTF-8 rows from a binary HTTP response' do
    expect(mod.parse_usage(reply)).to eq(expected_rows)
  end

  it 'preserves native Unicode through the real Rex CSV exporter' do
    expect(csv_rows).to eq([['File ID', 'Page ID', 'Version', 'Handle', 'Location']] + expected_rows.map { |row| ['37'] + row })
  end

  it 'does not mutate the received response body bytes or encoding' do
    original = [reply.body.bytes, reply.body.encoding]
    mod.parse_usage(reply)

    expect([reply.body.bytes, reply.body.encoding]).to eq(original)
  end

  it 'accepts a frozen binary body without changing it' do
    reply.body.freeze

    expect(mod.parse_usage(reply)).to eq(expected_rows)
  end

  it 'retains port 80 and normalizes the configured context prefix' do
    mod.datastore['TARGETURI'] = '/cms/'
    mod.run_host('192.0.2.1')

    expect([mod.rport, requests.map { |request| request.fetch('uri') }]).to eq([80, ['/cms/ccm/system/dialogs/file/usage/37', '/cms/ccm/system/dialogs/file/usage/37']])
  end

  it 'reports the collected row count and CVE after exporting' do
    mod.run_host('192.0.2.1')

    cves = reports.first.fetch(:refs).select { |reference| reference.ctx_id == 'CVE' }.map(&:ctx_val)
    expect([reports.length, reports.first.fetch(:info), cves]).to eq([1, 'Disclosed 2 file usage records via /ccm/system/dialogs/file/usage/<fID>', ['2026-6826']])
  end

  context 'with an ASCII-only projection of the native table' do
    let(:native_body) { super().gsub('Ω', 'omega') }

    it 'retains ordinary ASCII fields' do
      expect(mod.parse_usage(reply)).to eq(expected_rows.map { |row| row.map { |field| field.gsub('Ω', 'omega') } })
    end
  end

  context 'with an actual empty usage table' do
    let(:native_body) { super().sub(%r{<tbody>.*?</tbody>}m, '<tbody></tbody>') }

    it 'returns no rows' do
      expect(mod.parse_usage(reply)).to eq([])
    end

    it 'does not store loot or a vulnerability' do
      mod.run_host('192.0.2.1')

      expect([loot, reports]).to eq([[], []])
    end
  end

  context 'with the removed fixed-release endpoint' do
    let(:reply) { response(404, '<html><body>Not Found</body></html>') }

    it 'does not store an error page or vulnerability' do
      mod.run_host('192.0.2.1')

      expect([loot, reports]).to eq([[], []])
    end
  end

  context 'without a response' do
    let(:reply) { nil }

    it 'returns no parsed rows' do
      expect(mod.parse_usage(reply)).to eq([])
    end
  end

  context 'with a nullable HTTP 200 body' do
    let(:reply) { response(200, '').tap { |result| result.body = nil } }

    it 'returns no parsed rows' do
      expect(mod.parse_usage(reply)).to eq([])
    end
  end

  context 'with an unrelated table' do
    let(:native_body) { '<table><thead><tr><td>One</td></tr></thead><tbody><tr><td>Value</td></tr></tbody></table>' }

    it 'does not infer usage records' do
      expect(mod.parse_usage(reply)).to eq([])
    end
  end
end
