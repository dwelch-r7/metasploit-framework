# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare owning JRMP calls/reporting with actual JVM SDK operations and proofs.
  module JavaRmi
    OWNERS = {
      'registry' => 'auxiliary/gather/java_rmi_registry',
      'jmx' => 'auxiliary/scanner/misc/java_jmx_server',
      'rmi' => 'auxiliary/scanner/misc/java_rmi_server'
    }.freeze

    def java_native_phase(phase)
      output = +''
      directory = target_runtime.fetch('artifacts')
      endpoints = target_runtime.fetch('module_endpoints').map { |role, endpoint| "#{role}=#{endpoint.fetch('host')}" }.join(',')
      argv = target_runtime.fetch('compose') + ['exec', '-T', '--env', "JAVA_NATIVE_ENDPOINTS=#{endpoints}", ENV.fetch('JAVA_RMI_NATIVE_MODE', 'all') == 'jmx' ? 'open' : 'enabled', 'bash', '/lab/native.sh', ENV.fetch('JAVA_RMI_NATIVE_MODE', 'all')]
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(directory, "native-#{phase}.log"), timeout: 180, capture: output, quiet: true)
      File.write(File.join(directory, "native-#{phase}.json"), output)
      expect(passed).to be(true), output
      native = JSON.parse(output)
      expect(native.fetch('status')).to eq('native_passed')
      native.fetch('profiles').each do |role, data|
        expect(data.fetch('ip')).to eq(target_runtime.fetch('module_endpoints').fetch(role).fetch('host'))
      end
      native
    end

    def java_rows(name)
      path = File.join(target_runtime.fetch('artifacts'), 'msf-config', name)
      File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
    end

    def java_scan(kind, role, options = {}, allow_errors: false)
      @java_call = (@java_call || 0) + 1
      example = RSpec.current_example.id.split('[', 2).last.delete_suffix(']').tr(':', '-')
      name = format('owning-%<example>s-%<call>02d.json', example: example, call: @java_call)
      reports_before = java_rows('ntp-reports.jsonl').size
      wire_before = java_rows('rmi-wire.jsonl').size
      defaults = { 'ConnectTimeout' => 3 }
      defaults['THREADS'] = 1 unless kind == 'registry'
      # Serialized Java exceptions can be expected protocol results. Retain the
      # real console/wire output before checking for unhandled module failures.
      endpoint = target_runtime.fetch('module_endpoints').fetch(role)
      console_command('back')
      selected = console_command("use #{OWNERS.fetch(kind)}")
      expect(selected).not_to match(/Failed to load|Unknown command|No results/)
      datastore = { 'RHOSTS' => endpoint.fetch('host'), 'RPORT' => endpoint.fetch('port'), 'VERBOSE' => true }.merge(defaults).merge(options)
      output = console_command("run #{format_datastore_options(datastore)}", timeout: 45)
      reports = java_rows('ntp-reports.jsonl').drop(reports_before)
      wire = java_rows('rmi-wire.jsonl').drop(wire_before)
      File.write(File.join(target_runtime.fetch('artifacts'), name), JSON.pretty_generate(
        kind: kind, role: role, options: options, output: output, reports: reports, wire: wire
      ) + "\n")
      expect(output).to include('Auxiliary module execution completed')
      expect(output).not_to match(/Auxiliary failed:|undefined method|Unknown command|Msf::OptionValidateError/)
      expect(output).not_to include('[-]') unless allow_errors
      [output, reports, wire]
    end

    def verify_java_registry(role, multi: false)
      output, reports, = java_scan('registry', role, multi ? { 'RPORT' => 1119 } : {})
      names = multi ? @native.fetch('profiles').fetch(role).fetch('multi_registry').map { |row| row.fetch('name') } : ['jmxrmi']
      expect(output).to include("#{names.size} names found in the Registry")
      names.each { |name| expect(output.b).to include("Name #{name} (".b) }
      services = reports.select { |row| row.fetch('kind') == 'service' }
      expect(services.size).to eq(names.size)
      expected_port = multi ? 1120 : 1100
      services.each do |row|
        expect(row.fetch('options')).to include('host' => role, 'port' => expected_port, 'name' => 'java-rmi')
        expect(names.any? { |name| row.fetch('options').fetch('info').b.include?("Name: #{name},".b) }).to be(true)
      end
    end

    def verify_java_jmx(role)
      output, reports, = java_scan('jmx', role, {}, allow_errors: role == 'guarded')
      if role == 'guarded'
        expect(output).to include('Java JMX MBean authentication required')
        expect(reports).to be_empty
      else
        expect(output).to include("Handshake with JMX MBean server on #{role}:1100")
        expect(reports.count { |row| row['kind'] == 'service' }).to eq(1)
        expect(reports.count { |row| row['kind'] == 'vulnerability' }).to eq(1)
        verify_java_report_endpoints(reports, role)
        expect(@native.fetch('profiles').fetch(role).fetch('jmx_execution').fetch('owned_file_absent')).to be(true)
      end
    end

    def verify_java_report_endpoints(reports, role)
      address = target_runtime.fetch('module_endpoints').fetch(role).fetch('host')
      reports.each do |row|
        expect(row.fetch('options')).to include('host' => address)
        expect(row.fetch('options')).to include('port' => 1099, 'name' => 'java-rmi') if row.fetch('kind') == 'service'
      end
    end

    def verify_java_rmi(role)
      output, reports, = java_scan('rmi', role)
      enabled = role == 'enabled'
      expect(output).to include("Java RMI Endpoint Detected: Class Loader #{enabled ? 'Enabled' : 'Disabled'}")
      expect(reports.count { |row| row['kind'] == 'service' }).to eq(1)
      expect(reports.count { |row| row['kind'] == 'vulnerability' }).to eq(enabled ? 1 : 0)
      verify_java_report_endpoints(reports, role)
      expect(reports.find { |row| row['kind'] == 'service' }.fetch('options').fetch('info')).to eq("Class Loader: #{enabled ? 'Enabled' : 'Disabled'}")
      expect(@native.fetch('profiles').fetch(role).fetch('dgc').fetch('executed', false)).to be(enabled)
    end
  end
end
