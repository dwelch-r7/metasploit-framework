require 'acceptance_spec_helper'

RSpec.describe 'SNMP module targets' do
  include_context 'module target'

  let_it_be(:native_snmp) do
    package = target_exec('agent', 'dpkg-query', '-W', '-f=${Version}', 'snmpd')
    File.write(File.join(target_runtime.fetch('artifacts'), 'snmpd-package-version.txt'), package)
    report = JSON.parse(target_exec('agent', 'python3', '/opt/native_probe.py'))
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-snmp-preflight.json'), JSON.pretty_generate(report))
    expect(report.fetch('profiles').map { |profile| profile.fetch('name') }.uniq).to eq(['module-target-snmp'])
    expect(report.fetch('profiles').map { |profile| profile.fetch('description') }.uniq).to eq(['Linux module-target-net-snmp'])
    report
  end

  before(:all) { native_snmp }

  %w[udp tcp].each do |transport|
    %w[1 2c all].each do |version|
      { 'public' => 'read-only', 'private' => 'read-write' }.each do |community, access|
        it "identifies #{community} as #{access} over #{transport} with version #{version}" do
          before_value = native_value('1', 'public', '.1.3.6.1.2.1.1.1.0')
          output = run_target_module('auxiliary/scanner/snmp/snmp_login', 'agent', login_options.merge(
            'PROTOCOL' => transport, 'VERSION' => version, 'PASSWORD' => community
          ))
          expect(output).to include("Login Successful: #{community} (Access level: #{access})", 'Proof (sysDescr.0): Linux module-target-net-snmp')
          expect(output.scan("Login Successful: #{community} (Access level: #{access})").size).to eq(version == 'all' ? 2 : 1)
          expect(native_value('1', 'public', '.1.3.6.1.2.1.1.1.0')).to eq(before_value)
        end
      end
    end

    it "does not report an unknown community as successful over #{transport}" do
      output = run_target_module('auxiliary/scanner/snmp/snmp_login', 'agent', login_options.merge(
        'PROTOCOL' => transport, 'VERSION' => 'all', 'PASSWORD' => 'wrong-community'
      ), allow_errors: true)
      expect(output).not_to include('Login Successful:')
    end
  end

  %w[1 2c].each do |version|
    it "enumerates actual Linux host, interface and process data with version #{version}" do
      output = run_target_module('auxiliary/scanner/snmp/snmp_enum', 'agent', snmp_options(version, 'public'))
      expect(output).to match(/Hostname\s+: module-target-snmp/)
      expect(output).to match(/Description\s+: Linux module-target-net-snmp/)
      expect(output).to include('Network interfaces', 'eth0', 'Processes', 'snmpd')
    end

    it "changes canonical and leading-dot OIDs twice with version #{version} and restores the value" do
      original = native_value(version, 'public', contact_oid)
      begin
        [contact_oid, ".#{contact_oid}"].each do |oid|
          %w[first second].each do |iteration|
            marker = "module-snmp-#{version}-#{iteration}"
            output = run_target_module('auxiliary/scanner/snmp/snmp_set', 'agent', snmp_options(version, 'private').merge(
              'OID' => oid, 'OIDVALUE' => marker
            ))
            expect(output).to include("Check new value : OID #{contact_oid} => #{marker}")
            expect(native_value(version, 'public', contact_oid)).to eq(marker)
          end
        end
      ensure
        native_set(version, original)
      end
      expect(native_value(version, 'public', contact_oid)).to eq(original)
    end

    it "preserves the value when the community is read-only with version #{version}" do
      original = native_value(version, 'public', contact_oid)
      output = run_target_module('auxiliary/scanner/snmp/snmp_set', 'agent', snmp_options(version, 'public').merge(
        'OID' => ".#{contact_oid}", 'OIDVALUE' => 'forbidden-change'
      ))
      expect(output).to include('OID not writable or does not provide WRITE access')
      expect(native_value(version, 'public', contact_oid)).to eq(original)
    end

    it "preserves the value after an unknown community times out with version #{version}" do
      original = native_value(version, 'public', contact_oid)
      output = run_target_module('auxiliary/scanner/snmp/snmp_set', 'agent', snmp_options(version, 'wrong-community').merge(
        'OID' => ".#{contact_oid}", 'OIDVALUE' => 'forbidden-change'
      ), allow_errors: true)
      expect(output).to include("SNMP request timeout with community 'wrong-community'")
      expect(native_value(version, 'public', contact_oid)).to eq(original)
    end
  end

  def contact_oid
    '1.3.6.1.2.1.1.4.0'
  end

  def native_value(version, community, oid)
    target_exec('agent', 'snmpget', "-v#{version}", '-c', community, '-t', '1', '-r', '0', '-Oqv', '127.0.0.1', oid).strip.delete_prefix('"').delete_suffix('"')
  end

  def native_set(version, value)
    target_exec('agent', 'snmpset', "-v#{version}", '-c', 'private', '-t', '1', '-r', '0', '-Oqv', '127.0.0.1', contact_oid, 's', value)
  end

  def snmp_options(version, community)
    { 'VERSION' => version, 'COMMUNITY' => community, 'TIMEOUT' => 1, 'RETRIES' => 0 }
  end

  def login_options
    { 'PASS_FILE' => nil, 'BLANK_PASSWORDS' => false, 'STOP_ON_SUCCESS' => false, 'BRUTEFORCE_SPEED' => 5 }
  end
end
