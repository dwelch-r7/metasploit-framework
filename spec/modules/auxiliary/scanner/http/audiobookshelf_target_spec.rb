require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/audiobookshelf/acceptance'

profile = ENV.fetch('ABS_PROFILE', 'vulnerable')

RSpec.describe 'Genuine Audiobookshelf authentication bypass scanning', acceptance: true do
  include_context 'module target'
  include Acceptance::AudiobookshelfAuth

  before(:all) do
    @app = profile != 'unrelated'
    @vulnerable = %w[vulnerable uninitialized].include?(profile)
    @native = abs_native('before')
    expect(abs_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
    if @native['root_token']
      @headers = File.join(target_runtime.fetch('artifacts'), 'root-auth.headers')
      File.write(@headers, "Authorization: Bearer #{@native.fetch('root_token')}\r\n")
    end
    host = target_runtime.fetch('module_endpoints').fetch('target').fetch('host')
    proof = console_command("irb -e 'begin; Socket.tcp(#{host.inspect}, 1, connect_timeout: 2).close; puts \"ABS_REFUSED=false\"; rescue Errno::ECONNREFUSED; puts \"ABS_REFUSED=true\"; end'")
    expect(proof).to include('ABS_REFUSED=true')
  end

  after(:all) do
    if @native
      current = abs_native('after')
      keys = @app ? %w[files identity database server_status] : %w[identity ordinary_sha256]
      keys.each { |key| expect(current.fetch(key)).to eq(@native.fetch(key)) }
      expect(current.fetch('authenticated_libraries')).to eq(@native.fetch('authenticated_libraries')) if @headers
    end
  end

  before do |example|
    @workspace = "abs_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(abs_reports.values).to all(eq([]))
  end

  after { abs_reports if @workspace }

  if profile != 'unrelated'
    %w[check run].each do |action|
      it "uses the default path for #{action} twice without duplicate vulnerability/service records" do
        original = nil
        2.times do
          rows = abs_positive(action)
          identifiers = rows.transform_values { |values| values.map { |row| row.fetch('id') } }
          expect(identifiers).to eq(original) if original
          original = identifiers
        end
      end

      it "uses the supported application prefix for #{action} twice" do
        2.times { abs_positive(action, 'TARGETURI' => '/audiobookshelf/') }
      end
    end

    it 'retains the actual differential HTTP replies in a traced check and run' do
      %w[check run].each do |action|
        abs_positive(action, 'HttpTrace' => true)
      end
    end

    if profile != 'uninitialized'
      it 'distinguishes a genuinely authenticated baseline from a confirmed bypass' do
        output = abs_call('check', 'HttpRawHeaders' => @headers)
        expect(output).to include(@vulnerable ? 'The target appears to be vulnerable.' : 'The target is not exploitable.')
        prior = abs_assert_reports(vulnerable: @vulnerable)
        output = abs_call('run', 'HttpRawHeaders' => @headers)
        expect(output).to include('not vulnerable (authentication enforced)')
        expect(abs_reports).to eq(prior)
      end
    end
  else
    it 'returns unknown for the unrelated product and does not report a vulnerability' do
      expect(abs_call('check')).to include('Cannot reliably check exploitability.')
      expect(abs_call('run')).to include('Target does not appear to be Audiobookshelf')
      abs_assert_reports(vulnerable: false)
    end
  end

  it 'handles a missing application path without creating service or vulnerability records' do
    options = { 'TARGETURI' => '/module-target-missing' }
    expect(abs_call('check', options)).to include('Cannot reliably check exploitability.')
    expect(abs_call('run', options)).to include('Target does not appear to be Audiobookshelf')
    abs_assert_reports(vulnerable: false)
  end

  it 'handles the native-proven refused port without creating service or vulnerability records' do
    options = { 'RPORT' => 1 }
    expect(abs_call('check', options)).to include('Cannot reliably check exploitability.')
    expect(abs_call('run', options)).to include('Target does not appear to be Audiobookshelf')
    abs_assert_reports(vulnerable: false)
  end
end
