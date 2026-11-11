require 'acceptance_spec_helper'
require 'net/http'
require_relative '../../../../test/module_targets/forgejo_file/acceptance'

RSpec.describe 'Forgejo unrelated Apache control', acceptance: true do
  include_context 'module target'
  include Acceptance::ForgejoFile

  before(:all) do
    @native_http = forgejo_http_native('before')
    expect(forgejo_sql("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").strip).to eq('0')
    connected = console_command('db_connect module_framework:module-target-framework-db-password@reporting_db:5432/module_targets', timeout: 120)
    expect(connected).not_to match(/\[-\]|Error|Exception/)
    expect(console_command('db_status')).to include('Connected to module_targets. Connection type: postgresql.')
  end

  after(:all) do
    if @native_http
      current = forgejo_http_native('after')
      %w[status body identity].each { |key| expect(current.fetch(key)).to eq(@native_http.fetch(key)) }
    end
  end

  before do |example|
    @workspace = "forgejo_#{example.metadata.fetch(:scoped_id).tr(':', '_')}"
    expect(console_command("workspace -a #{@workspace}")).not_to include('[-]')
    expect(forgejo_reports.values).to all(eq([]))
  end

  after { forgejo_reports if @workspace }

  def forgejo_http_native(phase)
    endpoint = target_endpoint('target')
    response = Net::HTTP.get_response(URI("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/"))
    expect(response.code).to eq('200')
    expect(response.body).to include('It works!')
    expect(target_exec('target', 'httpd', '-v')).to include('Apache/2.4.62')
    process = target_exec('target', 'cat', '/proc/1/stat').split
    resource = target_exec('target', 'sh', '-c', 'cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.peak /sys/fs/cgroup/pids.events')
    expect(resource).to include('oom 0', 'oom_kill 0')
    expect(resource.lines.grep(/^max /).map(&:strip)).to all(eq('max 0'))
    data = {
      'status' => response.code, 'headers' => response.to_hash, 'body' => response.body,
      'identity' => { 'pid' => process.fetch(0), 'starttime' => process.fetch(21) }, 'resources' => resource
    }
    File.write(File.join(target_runtime.fetch('artifacts'), "native-http-#{phase}.json"), JSON.pretty_generate(data))
    data
  end

  it 'returns unknown for the genuine unrelated endpoint twice without false service data' do
    2.times do
      output, paths = forgejo_call({}, action: 'check')
      expect(output).to include('Cannot reliably check exploitability.')
      expect(paths).to eq([])
      forgejo_assert_reports(service: false)
    end
  end

  it 'refuses automatic reads twice without file loot or vulnerabilities' do
    2.times do
      output, paths = forgejo_call
      expect(output).to include('[-]')
      expect(output).not_to include('Successfully read ', 'File saved to: ')
      expect(paths).to eq([])
      forgejo_assert_reports(service: false)
    end
  end
end
