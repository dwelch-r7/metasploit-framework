require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/gopher/acceptance'

RSpec.describe 'Native Gopher menus and service reporting', acceptance: true do
  include_context 'module target'
  include Acceptance::GopherTarget

  before(:all) do
    @native = native_gopher('before')
    expect(report_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    if @native
      current = native_gopher('after')
      %w[responses files source_sha256 identity].each do |field|
        expect(current.fetch(field)).to eq(@native.fetch(field))
      end
    end
  end

  before do |example|
    @workspace = "gopher_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(service_rows).to eq([])
  end

  it 'enumerates and persists the full default root menu twice' do
    2.times { verify_menu }
  end

  it 'enumerates and persists a nested directory twice' do
    2.times { verify_menu('/dir') }
  end

  it 'preserves a directory and file selector containing spaces twice' do
    2.times { verify_menu('/space dir') }
  end

  it 'preserves native information, Unicode, explicit locations and server-normalized errors' do
    verify_menu('/custom')
  end

  it 'accepts a genuinely empty directory twice' do
    2.times { verify_menu('/empty') }
  end

  it 'accepts an explicitly empty custom map twice' do
    2.times { verify_menu('/empty-map') }
  end

  it 'preserves the genuine missing-selector error menu twice' do
    2.times { verify_menu('/missing') }
  end

  it 'enumerates every row of a native menu exceeding one receive block twice' do
    2.times { verify_menu('/large') }
  end

  it 'persists the correct service identity and exact menu without duplicates' do
    first = nil
    2.times do
      verify_menu
      rows = service_rows
      expect(rows.size).to eq(1)
      row = rows.fetch(0)
      endpoint = target_runtime.fetch('module_endpoints').fetch('target')
      expect(row.values_at('host', 'port', 'proto', 'name', 'state')).to eq([endpoint.fetch('host'), endpoint.fetch('port'), 'tcp', 'gopher', 'open'])
      expect(row).to eq(first) if first
      first = row
    end
  end

  it 'exports a genuine persisted service through the normal CSV command' do
    verify_menu
    path = File.join(target_runtime.fetch('artifacts'), 'services.csv')
    expect(console_command("services -o #{path}")).to include("Wrote services to #{path}")
    rows = CSV.read(path, headers: true)
    expect(rows.size).to eq(1)
    expect(rows.first.fetch('name')).to eq('gopher')
    # The standard table exporter intentionally collapses display whitespace.
    expected = @native.fetch('responses').fetch('').fetch('text').strip.gsub(/\s+/, ' ')
    expect(rows.first.fetch('info')).to eq(expected)
  end

  it 'does not identify the native-proven unrelated HTTP service as Gopher twice' do
    2.times do
      output = gopher_call(options: { 'RPORT' => 8080 })
      expect(output).not_to include('[+]')
      expect(service_rows).to eq([])
    end
  end

  it 'handles the same-namespace native-proven refused connection twice' do
    2.times do
      output = gopher_call(options: { 'RPORT' => 1 })
      expect(output).not_to include('[+]')
      expect(service_rows).to eq([])
    end
  end
end
