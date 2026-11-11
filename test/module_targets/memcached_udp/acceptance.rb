# frozen_string_literal: true

require 'base64'
require_relative '../../../tools/dev/run_module_target_tests'

module Acceptance
  # Compare public module output/reporting with native and passively captured traffic.
  module MemcachedUdp
    OWNERS = %w[auxiliary/scanner/memcached/memcached_udp_version auxiliary/scanner/memcached/memcached_amp].freeze

    def memcached_native_phase(phase)
      output = +''
      path = File.join(target_runtime.fetch('artifacts'), "native-#{phase}.json")
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/memcached_udp/native_probe.rb', ENV.fetch('MODULE_TARGET_RUNTIME')]
      passed = ModuleTargetTests.new.send(:command, argv, path: "#{path}.log", timeout: 35, capture: output, quiet: true)
      File.write(path, output)
      expect(passed).to be(true), output
      native = JSON.parse(output)
      expect(native.fetch('status')).to eq('native_passed')
      native
    end

    def memcached_reports
      path = File.join(target_runtime.fetch('artifacts'), 'msf-config/ntp-reports.jsonl')
      File.file?(path) ? File.readlines(path).map { |line| JSON.parse(line) } : []
    end

    def memcached_scan(owner, services, port: 11211)
      @memcached_call = (@memcached_call || 0) + 1
      example = RSpec.current_example.id.split('[', 2).last.delete_suffix(']').tr(':', '-')
      stem = File.join(target_runtime.fetch('artifacts'), format('owning-wire-%<example>s-%<call>02d', example: example, call: @memcached_call))
      raise 'Owning wire capture already exists' if File.exist?("#{stem}.json")

      before = memcached_reports.size
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/memcached_udp/capture.rb', ENV.fetch('MODULE_TARGET_RUNTIME')]
      text = nil
      raw = nil
      Open3.popen3(*argv) do |input, output, errors, wait|
        begin
          expect(IO.select([output], nil, nil, 8)).not_to be_nil
          expect(output.gets).to eq("MEMCACHED_CAPTURE_READY\n")
          hosts = services.map { |service| target_runtime.fetch('module_endpoints').fetch(service).fetch('host') }
          text = run_target_module(owner, services.first, {
            'RHOSTS' => hosts.join(' '), 'RPORT' => port,
            'ScannerRecvWindow' => 1, 'THREADS' => 1, 'BATCHSIZE' => 256
          })
        ensure
          begin
            input.puts('STOP')
          rescue Errno::EPIPE, IOError
            # Preserve the observer's own terminal/error output below.
          end
          input.close
          unless wait.join(5)
            Process.kill('TERM', wait.pid)
            wait.join(3)
          end
          raw = output.read
          error = errors.read
          File.write("#{stem}.json", raw)
          File.write("#{stem}.stderr", error)
        end
        expect(wait.value.success?).to be(true), File.read("#{stem}.stderr")
      end
      packets = JSON.parse(raw).fetch('packets')
      reports = memcached_reports.drop(before)
      File.write("#{stem}-module.json", JSON.pretty_generate(owner: owner, services: services, port: port, output: text, reports: reports) + "\n")
      [text, packets, reports]
    end

    def verify_memcached_scan(owner, services, port: 11211, positive: true)
      output, packets, reports = memcached_scan(owner, services, port: port)
      command = owner.end_with?('memcached_amp') ? "stats\r\n" : "version\r\n"
      requests = packets.select { |packet| packet.fetch('direction') == 'request' }
      expect(requests.size).to eq(services.size)
      reports_per_host = command == "stats\r\n" ? 2 : 1
      expect(reports.size).to eq(positive ? services.size * reports_per_host : 0)
      services.each do |service|
        host = target_runtime.fetch('module_endpoints').fetch(service).fetch('host')
        request = requests.select { |packet| packet.fetch('destination') == host }
        expect(request.size).to eq(1)
        request = request.first
        raw = Base64.strict_decode64(request.fetch('udp_payload_base64'))
        identifier, sequence, count, reserved = raw.unpack('n4')
        expect([sequence, count, reserved, raw.byteslice(8..)]).to eq([0, 1, 0, command])
        expect(request.fetch('destination_port')).to eq(port)
        responses = packets.select { |packet| packet.fetch('direction') == 'response' && packet.fetch('source') == host }
        unless positive
          expect(responses).to be_empty
          expect(output).not_to include('memcached version', 'Vulnerable to memcached')
          next
        end

        expect(responses).not_to be_empty
        fragments = responses.map do |packet|
          expect(packet.fetch('source_port')).to eq(port)
          expect(packet.fetch('destination_port')).to eq(request.fetch('source_port'))
          bytes = Base64.strict_decode64(packet.fetch('udp_payload_base64'))
          reply_id, index, total, reply_reserved = bytes.unpack('n4')
          expect([reply_id, reply_reserved]).to eq([identifier, 0])
          expect(packet.fetch('udp_payload_bytes')).to eq(bytes.bytesize)
          [index, total, bytes.byteslice(8..)]
        end
        expect(fragments.map { |fragment| fragment[1] }.uniq).to eq([fragments.size])
        expect(fragments.map(&:first).sort).to eq((0...fragments.size).to_a)
        body = fragments.sort_by(&:first).map(&:last).join
        version = @native.fetch('profiles').fetch(service).fetch('version')
        service_report = reports.select { |record| record['kind'] == 'service' && record.dig('options', 'host') == host }
        expect(service_report.size).to eq(1)
        expect(service_report.first.fetch('options')).to include('host' => host, 'port' => port, 'proto' => 'udp', 'name' => 'memcached')
        if command == "version\r\n"
          expect(body).to eq("VERSION #{version}\r\n")
          expect(output).to include("#{host}:#{port}/udp memcached version #{version}")
          expect(service_report.first.fetch('options')).to include('info' => version)
        else
          expect(body).to start_with('STAT pid ').and end_with("END\r\n")
          expect(body.lines).to include("STAT version #{version}\r\n")
          total = responses.sum { |packet| packet.fetch('udp_payload_bytes') }
          proof = fragments.size > 1 ? "#{fragments.size}x packet amplification" : 'No packet amplification'
          proof += " and a #{total / raw.bytesize}x, #{total - raw.bytesize}-byte bandwidth amplification"
          expect(output).to include("#{host}:#{port} - Vulnerable to memcached stats amplification: #{proof}")
          vulnerabilities = reports.select { |record| record['kind'] == 'vulnerability' && record.dig('options', 'host') == host }
          expect(vulnerabilities.size).to eq(1)
          expect(vulnerabilities.first.fetch('options')).to include('host' => host, 'port' => port, 'proto' => 'udp', 'name' => 'memcached stats amplification')
        end
      end
    end
  end
end
