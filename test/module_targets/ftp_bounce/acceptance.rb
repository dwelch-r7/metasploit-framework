# frozen_string_literal: true

require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Bind reported ports to genuine cross-host transfers received by Apache.
  module FtpBounce
    OWNER = 'auxiliary/scanner/portscan/ftpbounce'

    def bounce_command(argv, name, timeout: 30)
      output = +''
      passed = ModuleTargetTests.new.send(:command, argv, path: File.join(target_runtime.fetch('artifacts'), name), timeout: timeout, capture: output, quiet: true)
      expect(passed).to be(true), output
      output
    end

    def bounce_destination_rows
      argv = target_runtime.fetch('compose') + ['logs', '--no-color', '--no-log-prefix', 'destination']
      bounce_command(argv, 'destination-observations.log').lines.filter_map do |line|
        match = line.strip.match(/\AMODULE_TARGET_BOUNCE (\S+) (\d+) "(.*)" (\d+)\z/)
        next unless match && match[3].include?('module-target.txt')

        { 'host' => match[1], 'port' => match[2].to_i, 'request' => match[3], 'status' => match[4].to_i }
      end
    end

    def bounce_native_phase(phase)
      before = bounce_destination_rows.size
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'permissive', 'python3', '/opt/bounce_native_probe.py', ENV.fetch('MODULE_TARGET_RUNTIME')]
      output = bounce_command(argv, "native-#{phase}.log", timeout: 90)
      File.write(File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json"), output)
      native = JSON.parse(output)
      expect(native.fetch('status')).to eq('native_passed')
      received = nil
      wait_for_expect(30, 0.1) do
        received = bounce_destination_rows.drop(before)
        expect(received.map { |row| row.fetch('port') }.sort).to eq([8080, 8080, 8082, 8082])
      end
      relay_host = target_runtime.fetch('module_endpoints').fetch('permissive').fetch('host')
      expect(received.map { |row| row.fetch('host') }.uniq).to eq([relay_host])
      expect(received.map { |row| row.fetch('status') }.uniq).to eq([400])
      File.write(File.join(target_runtime.fetch('artifacts'), "native-#{phase}-received.json"), JSON.pretty_generate(received) + "\n")
      native
    end

    def bounce_reports
      path = File.join(target_runtime.fetch('artifacts'), 'msf-config/ntp-reports.jsonl')
      File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
    end

    def verify_bounce(ports, open_ports:, relay: 'permissive', **extra)
      @bounce_call = (@bounce_call || 0) + 1
      example = RSpec.current_example.id.split('[', 2).last.delete_suffix(']').tr(':', '-')
      name = format('owning-%<example>s-%<call>02d.json', example: example, call: @bounce_call)
      before = bounce_destination_rows.size
      report_count = bounce_reports.size
      relay_host = target_runtime.fetch('module_endpoints').fetch(relay).fetch('host')
      destination = target_runtime.fetch('module_endpoints').fetch('destination').fetch('host')
      options = {
        'BOUNCEHOST' => relay_host, 'BOUNCEPORT' => 21, 'PORTS' => ports,
        'FTPUSER' => 'anonymous', 'FTPPASS' => 'module-target@example.test',
        'FTPTimeout' => 4, 'THREADS' => 1, 'DELAY' => 0, 'JITTER' => 0
      }.merge(extra)
      output = run_target_module(OWNER, 'destination', options, endpoint_options: { 'RHOSTS' => destination }, allow_errors: extra['FTPPASS'] == 'wrong-password')
      reports = bounce_reports.drop(report_count)
      received = nil
      begin
        wait_for_expect(30, 0.1) do
          received = bounce_destination_rows.drop(before)
          expect(received.map { |row| row.fetch('port') }.sort).to eq(open_ports.sort)
        end
        expect(received.map { |row| row.fetch('host') }.uniq).to eq(open_ports.empty? ? [] : [relay_host])
        expect(received.map { |row| row.fetch('status') }.uniq).to eq(open_ports.empty? ? [] : [400])
        reported_ports = reports.select { |row| row.fetch('kind') == 'service' && row.dig('options', 'host') == destination }.map { |row| row.fetch('options').fetch('port') }
        expect(reported_ports.sort).to eq(open_ports.sort)
        expect(output.scan(/TCP OPEN #{Regexp.escape(destination)}:(\d+)/).flatten.map(&:to_i).sort).to eq(open_ports.sort)
        expect(reports.count { |row| row.dig('options', 'host') == relay_host && row.dig('options', 'name') == 'ftp' }).to eq(1)
        expect(output).to include('The server rejected our password') if extra['FTPPASS'] == 'wrong-password'
      ensure
        File.write(File.join(target_runtime.fetch('artifacts'), name), JSON.pretty_generate(
          'options' => options, 'output' => output, 'reports' => reports, 'destination_rows' => received,
          'expected_open_ports' => open_ports, 'destination_host' => destination
        ) + "\n")
      end
    end
  end
end
