require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native NTP control-query targets' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/ntp/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ntp-before.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-ntp-command.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native_profiles = JSON.parse(stdout).fetch('profiles')
    expect(target_runtime.fetch('transports').values.uniq).to eq(['udp'])
    observer = 'test/module_targets/ntp/report_observer.rb'
    code = "load #{observer.inspect}; framework.modules.create(\"auxiliary/scanner/ntp/ntp_readvar\").class.prepend(ModuleTargetNtpReports)"
    output = console_command("irb -e '#{code}'")
    expect(output).not_to match(/Error|Exception/)
    @report_path = File.join(ENV.fetch('MSF_CFGROOT_CONFIG'), 'ntp-reports.jsonl')
  end

  [2, 3, 4].each do |version|
    it "gathers actual native properties and packet accounting twice with version #{version}" do
      2.times { verify_information(version) }
    end
  end

  it 'gathers the same native information twice through an explicit local interface' do
    2.times { verify_information(2, 'CHOST' => listener_host) }
  end

  it 'does not report gathered properties or a vulnerability when the real server refuses queries' do
    output, reports = scan('closed')
    expect(output).not_to include('Vulnerable to', 'module-target-native-ntp-proof')
    expect(reports).to be_empty
  end

  it 'does not report unrelated real UDP DNS as NTP' do
    output, reports = scan('unrelated')
    expect(output).not_to include('Vulnerable to', 'module-target-native-ntp-proof')
    expect(reports).to be_empty
  end

  def verify_information(version, options = {})
    native = @native_profiles.fetch('open').fetch(version.to_s)
    output, reports = scan('open', { 'VERSION' => version }.merge(options))
    services = reports.select { |record| record.fetch('kind') == 'service' }
    expect(services.size).to eq(1)
    service = services.first.fetch('options')
    endpoint = target_runtime.fetch('module_endpoints').fetch('open')
    expect(service).to include('name' => 'ntp', 'proto' => 'udp', 'port' => endpoint.fetch('port'), 'host' => endpoint.fetch('host'))
    native.fetch('properties').each_value { |value| expect(service.fetch('info')).to include(value) }
    wire = native.fetch('wire')
    packets = wire.fetch('packets').size
    bytes = wire.fetch('response_bytes')
    request_bytes = wire.fetch('request_bytes')
    packet_proof = packets > 1 ? "#{packets}x packet amplification" : 'No packet amplification'
    expect(output).to include("#{packet_proof} and a #{bytes / request_bytes}x, #{bytes - request_bytes}-byte bandwidth amplification")
    vulnerabilities = reports.select { |record| record.fetch('kind') == 'vulnerability' }
    expect(vulnerabilities.size).to eq(1)
    expect(vulnerabilities.first.fetch('options')).to include('name' => 'NTP Mode 6 READVAR DRDoS')
  end

  def scan(service, options = {})
    File.write(@report_path, '')
    output = run_target_module('auxiliary/scanner/ntp/ntp_readvar', service, { 'ScannerRecvWindow' => 1, 'THREADS' => 1, 'BATCHSIZE' => 1 }.merge(options))
    reports = File.readlines(@report_path).map { |line| JSON.parse(line) }
    [output, reports]
  end
end
