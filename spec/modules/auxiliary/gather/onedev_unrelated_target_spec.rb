require 'acceptance_spec_helper'
require 'net/http'
require_relative '../../../../test/module_targets/onedev_file/acceptance'

RSpec.describe 'OneDev unrelated Apache control', acceptance: true do
  include_context 'module target'
  include Acceptance::OneDevFile

  before(:all) do
    @native_http = onedev_http_native('before')
  end

  after(:all) do
    if @native_http
      current = onedev_http_native('after')
      %w[status body identity].each { |key| expect(current.fetch(key)).to eq(@native_http.fetch(key)) }
    end
  end

  def onedev_http_native(phase)
    endpoint = target_endpoint('target')
    response = Net::HTTP.get_response(URI("http://#{endpoint.fetch('host')}:#{endpoint.fetch('port')}/"))
    expect(response.code).to eq('200')
    expect(response.body).to include('It works!')
    expect(target_exec('target', 'httpd', '-v')).to include('Apache/2.4.62')
    process = target_exec('target', 'cat', '/proc/1/stat').split
    resources = target_exec('target', 'sh', '-c', 'cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/pids.peak /sys/fs/cgroup/pids.events')
    expect(resources).to include('oom 0', 'oom_kill 0')
    expect(resources.lines.grep(/^max /).map(&:strip)).to all(eq('max 0'))
    data = { 'status' => response.code, 'headers' => response.to_hash, 'body' => response.body,
             'identity' => { 'pid' => process.fetch(0), 'starttime' => process.fetch(21) }, 'resources' => resources }
    File.write(File.join(target_runtime.fetch('artifacts'), "native-http-#{phase}.json"), JSON.pretty_generate(data))
    data
  end

  it 'returns unknown for the genuine unrelated HTTP product twice' do
    2.times do
      output, paths = onedev_call({}, action: 'check')
      expect(output).to include("The target isn't a OneDev instance.")
      expect(paths).to eq([])
    end
  end

  it 'refuses automatic exploitation without false file output or loot twice' do
    2.times do
      output, paths = onedev_call({ 'STORE_LOOT' => true })
      expect(output).to include('[-]')
      expect(output).not_to include('file retrieved with success.', 'file stored in loot.')
      expect(paths).to eq([])
    end
  end
end
