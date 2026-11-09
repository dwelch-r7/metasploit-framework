require 'acceptance_spec_helper'
require 'base64'
require 'net/http'
require 'rbconfig'

RSpec.describe 'Mongobleed module targets' do
  include_context 'module target'
  include_context 'wait_for_expect'

  let(:fullname) { 'auxiliary/scanner/mongodb/cve_2025_14847_mongobleed' }

  before(:all) do
    { 'vulnerable' => 'zlib', 'authenticated' => 'zlib', 'fixed' => 'zlib', 'guarded' => 'snappy' }.each do |service, compressor|
      credentials = service == 'authenticated' ? ['--username', 'labadmin', '--password', 'labpassword', '--authenticationDatabase', 'admin'] : []
      config = target_exec(service, 'mongo', '--quiet', *credentials, '--eval', 'print(JSON.stringify(db.adminCommand({getCmdLineOpts:1}).parsed))')
      parsed = JSON.parse(config)
      expect(parsed.fetch('net').fetch('compression').fetch('compressors')).to eq(compressor)
      if service == 'authenticated'
        expect(parsed.fetch('security').fetch('authorization')).to eq('enabled')
        denied = target_exec(service, 'mongo', '--quiet', '--eval', 'print(JSON.stringify(db.adminCommand({listDatabases:1})))')
        expect(JSON.parse(denied).slice('ok', 'code')).to eq('ok' => 0, 'code' => 13)
      end
      wire = native_wire_probe(service)
      if %w[vulnerable authenticated].include?(service)
        expect(wire.slice('status', 'response_to', 'bson_signature')).to eq('status' => 'reply', 'response_to' => 1, 'bson_signature' => true)
        expect(Base64.strict_decode64(wire.fetch('decoded_base64'))).to include('InvalidBSON')
      else
        expect(wire.fetch('status')).to eq('closed')
      end
    end
    endpoint = target_endpoint('apache')
    http = Net::HTTP.new(endpoint.fetch('host'), endpoint.fetch('port'), nil)
    http.open_timeout = 3
    http.read_timeout = 3
    response = http.get('/')
    expect(response.code).to eq('200')
    expect(response['server']).to start_with('Apache/')
  end

  %w[vulnerable authenticated].each do |service|
    it "confirms the real malformed-compression condition without credentials on #{service}" do
      output = run_target_module(fullname, service, {}, action: 'check')
      expect(output).to include('Server leaks memory via crafted OP_COMPRESSED message (MongoDB 4.4.29)')
    end
  end

  it 'recognizes the fixed release' do
    output = run_target_module(fullname, 'fixed', {}, action: 'check')
    expect(output).to include('Version 4.4.30 is patched')
  end

  it 'recognizes the disabled-compression mitigation on the affected release' do
    output = run_target_module(fullname, 'guarded', {}, action: 'check')
    expect(output).to include('Server does not have zlib compression enabled')
  end

  it 'does not identify a real HTTP service as MongoDB' do
    output = run_target_module(fullname, 'apache', {}, action: 'check', allow_errors: true)
    expect(output).to include('Target does not appear to be a MongoDB service')
  end

  %w[vulnerable authenticated].each do |service|
    [true, false].each do |reuse|
      it "collects real bounded leak data twice on #{service} with connection reuse #{reuse}" do
        2.times do
          output = run_target_module(fullname, service, {
            'MIN_OFFSET' => 20, 'MAX_OFFSET' => 512, 'QUICK_SCAN' => true, 'REPEAT' => 2,
            'REUSE_CONNECTION' => reuse, 'LEAK_THRESHOLD' => 1, 'SAVE_JSON' => true,
            'PROGRESS_INTERVAL' => 0, 'FORCE_EXPLOIT' => false
          })
          binary = File.binread(loot_path(output, 'Leaked data saved to:'))
          report = JSON.parse(File.read(loot_path(output, 'JSON report saved to:')))
          fragments = report.fetch('leaks').map do |leak|
            data = Base64.strict_decode64(leak.fetch('data_base64'))
            expect(data.bytesize).to eq(leak.fetch('length'))
            expect(leak.fetch('offset')).to be_between(20, 512)
            data
          end
          expect(binary).not_to be_empty
          expect(fragments.join).to eq(binary)
          expect(report.fetch('summary').fetch('total_bytes')).to eq(binary.bytesize)
          expect(report.fetch('scan_info').fetch('mongodb_version')).to eq('4.4.29')
          expect(report.fetch('scan_parameters').slice('quick_scan', 'repeat_passes')).to eq('quick_scan' => true, 'repeat_passes' => 2)
          expect(target_exec(service, 'mongo', '--quiet', '--eval', 'print(db.version())').strip).to eq('4.4.29')
        end
      end
    end
  end

  %w[fixed guarded].each do |service|
    it "does not create leak loot on #{service} with the normal safeguards" do
      original_loot = Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]
      output = run_target_module(fullname, service, { 'FORCE_EXPLOIT' => false, 'QUICK_SCAN' => true, 'MAX_OFFSET' => 512 }, allow_errors: true)
      expected = service == 'fixed' ? 'Version 4.4.30 appears to be PATCHED' : 'Server does not support zlib compression'
      expect(output).to include(expected)
      expect(output).not_to include('Leaked data saved to:', 'JSON report saved to:')
      expect(Dir[File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot', '*')]).to eq(original_loot)
    end
  end

  def native_wire_probe(service)
    endpoint = target_endpoint(service)
    command = [RbConfig.ruby, File.expand_path('test/module_targets/mongobleed/native_probe.rb'), endpoint.fetch('host'), endpoint.fetch('port').to_s]
    output, error, status = Open3.capture3(*command)
    File.open(File.join(target_runtime.fetch('artifacts'), 'native-wire.jsonl'), 'a') do |file|
      file.puts(JSON.generate(service: service, argv: command, output: output, error: error, exitstatus: status.exitstatus))
    end
    expect(status.success?).to be(true), error
    JSON.parse(output)
  end

  def loot_path(output, label)
    path = output[/#{Regexp.escape(label)} (.+)$/, 1]&.strip
    expect(path).not_to be_nil, output
    expect(File.expand_path(path)).to start_with(File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'loot/'))
    path
  end
end
