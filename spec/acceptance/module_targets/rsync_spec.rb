require 'acceptance_spec_helper'
require 'net/http'

RSpec.describe 'Rsync module targets' do
  include_context 'module target'

  let(:fullname) { 'auxiliary/scanner/rsync/modules_list' }
  let_it_be(:native_rsync) do
    %w[ubuntu debian empty].to_h do |service|
      package = target_exec(service, 'dpkg-query', '-W', '-f=${Version}', 'rsync')
      File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-package-version.txt"), package)
      arguments = service == 'empty' ? ['empty'] : []
      report = JSON.parse(target_exec(service, 'python3', '/opt/native_probe.py', *arguments))
      protocol = service == 'debian' ? 32 : 31
      expect(report.fetch('version')).to start_with("rsync  version 3.2.7  protocol version #{protocol}\n")
      expect(report.fetch('greeting')).to start_with("@RSYNCD: #{protocol}.0 sha512 sha256 sha1 md5 md4\n")
      File.write(File.join(target_runtime.fetch('artifacts'), "#{service}-native-preflight.json"), JSON.pretty_generate(report))
      [service, report]
    end
  end

  before(:all) do
    native_rsync
    endpoint = target_endpoint('apache')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 3
    response = http.get('/')
    expect(response.code).to eq('200')
    expect(response['server']).to start_with('Apache/')
  end

  %w[ubuntu debian].each do |service|
    it "lists actual shares and detects per-share authentication on #{service}" do
      output = run_target_module(fullname, service, {
        'TEST_AUTHENTICATION' => true, 'SHOW_VERSION' => true, 'SHOW_MOTD' => true, 'READ_TIMEOUT' => 1
      })
      protocol = native_rsync.fetch(service).fetch('greeting')[/^@RSYNCD: (\d+(?:\.\d+)?)/, 1]
      expect(protocol).not_to be_nil
      expect(output).to include("rsync protocol version: #{protocol}", 'rsync MOTD: Local rsync module target')
      expect(output).to include('3 rsync modules found: public, locked, blank')
      expect(output).to match(/public\s+open share\s+not required/)
      expect(output).to match(/locked\s+protected share\s+required/)
      expect(output).to match(/blank\s+not required/)
      expect(output).not_to match(/\bhidden\b/)
    end

    it "lists shares without authentication probes or optional banner output on #{service}" do
      output = run_target_module(fullname, service, {
        'TEST_AUTHENTICATION' => false, 'SHOW_VERSION' => false, 'SHOW_MOTD' => false, 'READ_TIMEOUT' => 1
      })
      expect(output).to include('3 rsync modules found: public, locked, blank', 'open share', 'protected share')
      expect(output).not_to include('Authentication', 'rsync protocol version:', 'rsync MOTD:')
      expect(output).not_to match(/\bhidden\b/)
    end
  end

  it 'distinguishes a real daemon with no exported modules' do
    output = run_target_module(fullname, 'empty', { 'TEST_AUTHENTICATION' => true, 'READ_TIMEOUT' => 1 })
    expect(output).to include('no rsync modules found')
    expect(output).not_to include('rsync modules for')
  end

  it 'does not enumerate a real HTTP server as rsync' do
    output = run_target_module(fullname, 'apache', { 'TEST_AUTHENTICATION' => true, 'READ_TIMEOUT' => 1 }, allow_errors: true)
    expect(output).to include('does not appear to be rsync')
    expect(output).not_to include('rsync modules found', 'rsync modules for')
  end
end
