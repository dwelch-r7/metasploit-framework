# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'open3'
require 'openssl'

module Acceptance
  # Independent native, packet and database observations of public console calls.
  module Heartbleed
    OWNER = 'auxiliary/scanner/ssl/openssl_heartbleed'

    def hb_journal(name, data)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(data)) }
    end

    def hb_sql(query)
      JSON.parse(target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query))
    end

    def hb_reports
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Ahb_[0-9_]+\z/)

      rows = hb_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT v.id,v.name,v.info,v.service_id,host(h.address) AS address,s.port,s.proto FROM vulns v JOIN hosts h ON h.id=v.host_id JOIN workspaces w ON w.id=h.workspace_id LEFT JOIN services s ON s.id=v.service_id WHERE w.name='#{@workspace}' ORDER BY v.id) row")
      hb_journal('vulnerability-snapshots.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def hb_loot
      rows = hb_sql("SELECT coalesce(json_agg(row),'[]'::json) FROM (SELECT l.id,l.ltype,l.path,l.content_type,l.info,host(h.address) AS address FROM loots l JOIN workspaces w ON w.id=l.workspace_id LEFT JOIN hosts h ON h.id=l.host_id WHERE w.name='#{@workspace}' ORDER BY l.id) row")
      hb_journal('loot-snapshots.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def hb_native(phase)
      data = JSON.parse(target_exec('target', 'python3', '-W', 'ignore::DeprecationWarning', '/opt/heartbleed-lab/calibrate.py', phase))
      hb_journal('native-controls.jsonl', phase: phase, data: data)
      expect(data.fetch('status')).to eq('passed')
      expected = phase == 'after' ? { 'native_probe.py' => 8, 'conditioned_probe.py' => 8, 'starttls_probe.py' => 12, 'ec_probe.py' => 2 } : { 'native_probe.py' => 24, 'conditioned_probe.py' => 24, 'starttls_probe.py' => 24, 'ec_probe.py' => 2 }
      expect(data.fetch('controls').transform_values { |row| row.fetch('cases').length }).to eq(expected)
      expect(data.fetch('controls').fetch('conditioned_probe.py').fetch('boundary_cases').length).to eq(phase == 'after' ? 0 : 8)
      data
    end

    def hb_json(expression)
      output = console_command("irb -e #{("puts 'HEARTBLEED_JSON=' + (#{expression}).to_json").inspect}")
      rows = output.lines.grep(/^HEARTBLEED_JSON=/)
      expect(rows.length).to eq(1), output
      JSON.parse(rows.first.delete_prefix('HEARTBLEED_JSON='))
    end

    def hb_state
      JSON.parse(target_exec('target', 'python3', '/opt/heartbleed-lab/state.py'))
    end

    def hb_idle
      wait_for_expect(15, 0.1) do
        state = hb_state
        expect(state.fetch('processes')).to eq(@idle.fetch('processes'))
        expect(state.fetch('connections')).to eq([])
      end
      expect(hb_json('{ sessions: framework.sessions.keys, jobs: framework.jobs.keys }')).to eq('sessions' => [], 'jobs' => [])
    end

    def hb_resources
      rows = %w[target framework reporting_db].to_h do |service|
        counters = %w[memory.events pids.events].to_h do |name|
          values = target_exec(service, 'cat', '/sys/fs/cgroup/' + name).lines.to_h do |line|
            key, value = line.split
            [key, Integer(value, 10)]
          end
          [name, values]
        end
        [service, counters]
      end
      hb_journal('resource-counters.jsonl', rows)
      rows.each_value do |counters|
        %w[oom oom_kill oom_group_kill].each { |name| expect(counters.fetch('memory.events').fetch(name, 0)).to eq(0) }
        expect(counters.fetch('pids.events').fetch('max')).to eq(0)
      end
    end

    def hb_streams(packets)
      groups = packets.reject { |p| Base64.strict_decode64(p.fetch('payload_base64')).empty? }.group_by do |packet|
        packet.values_at('direction', 'source', 'source_port', 'destination', 'destination_port')
      end
      groups.map do |key, fragments|
        position = fragments.map { |p| p.fetch('sequence') }.min
        bytes = ''.b
        fragments.sort_by { |p| p.fetch('sequence') }.each do |packet|
          sequence = packet.fetch('sequence')
          raise 'Gap in captured TCP stream' if sequence > position

          payload = Base64.strict_decode64(packet.fetch('payload_base64'))
          skipped = position - sequence
          bytes << payload.byteslice(skipped..) if skipped < payload.bytesize
          position = [position, sequence + payload.bytesize].max
        end
        { direction: key[0], source_port: key[2], destination_port: key[4], bytes: bytes }
      end
    end

    def hb_records(bytes)
      records = []
      until bytes.empty?
        raise 'Truncated captured TLS header' if bytes.bytesize < 5

        type, version, length = bytes.unpack('Cnn')
        raise 'Truncated captured TLS body' if bytes.bytesize < 5 + length

        records << { type: type, version: version, body: bytes.byteslice(5, length) }
        bytes = bytes.byteslice(5 + length..)
      end
      records
    end

    def hb_call(options = {}, action: 'run')
      @calls = (@calls || 0) + 1
      port = options.fetch('RPORT', 10000)
      stem = "#{@workspace}-#{@calls}"
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/heartbleed/capture.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), port.to_s]
      output = raw = errors = nil
      status = nil
      begin
        Open3.popen3(*argv) do |input, captured, error, wait|
          error_reader = Thread.new { error.read }
          expect(IO.select([captured], nil, nil, 8)).not_to be_nil
          expect(captured.gets).to eq("HEARTBLEED_CAPTURE_READY\n")
          output = run_target_module(OWNER, 'target', { 'ACTION' => 'SCAN', 'THREADS' => 1, 'ConnectTimeout' => 2, 'RESPONSE_TIMEOUT' => 3, 'VERBOSE' => true }.merge(options), action: action, allow_errors: true)
        ensure
          begin
            input.puts('STOP')
          rescue Errno::EPIPE, IOError
            # Retain the observer's actual terminal output and error below.
          end
          input.close
          # Drain arbitrary memory captures before joining: pipe capacity may be
          # smaller than one 64 KiB leak encoded as JSON/base64.
          raw = captured.read
          errors = error_reader.value
          status = wait.value.exitstatus
        end
      ensure
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.json'), raw.to_s)
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.stderr'), errors.to_s)
        hb_journal('owning-calls.jsonl', workspace: @workspace, options: options, action: action, output_base64: Base64.strict_encode64(output || console.all_data), capture_actual_exit: status)
      end
      expect(status).to eq(0), errors
      expect(output).not_to match(/Auxiliary failed|Call stack:|Unknown datastore option/)
      streams = hb_streams(JSON.parse(raw).fetch('packets'))
      [output, streams]
    end

    def hb_payloads(streams, complete: true)
      streams.select { |s| s.fetch(:direction) == 'response' }.filter_map do |stream|
        records = hb_records(hb_tls_stream(stream).last)
        data = records.select { |r| r.fetch(:type) == 24 }.map { |r| r.fetch(:body) }.join.b
        next if data.empty?

        expect(data.getbyte(0)).to eq(2)
        length = data.byteslice(1, 2).unpack1('n')
        expect(data.bytesize).to be >= 3
        expect(data.bytesize).to be >= 3 + length if complete
        data.byteslice(3, length)
      end
    end

    def hb_tls_stream(stream)
      data = stream.fetch(:bytes)
      port = stream.fetch(:direction) == 'request' ? stream.fetch(:destination_port) : stream.fetch(:source_port)
      return [''.b, data] unless [*10400.step(10900, 100), *11400.step(11900, 100)].include?(port)

      offset = data.index(/\x16\x03[\x00-\x03]/n)
      expect(offset).not_to be_nil, "No TLS handshake observed after upgrade on #{port}"
      [data.byteslice(0, offset), data.byteslice(offset..)]
    end

    def hb_verify_upgrade(streams, protocol)
      request = streams.find { |row| row.fetch(:direction) == 'request' }
      response = streams.find { |row| row.fetch(:direction) == 'response' }
      expect(request).not_to be_nil
      expect(response).not_to be_nil
      sent = hb_tls_stream(request).first
      received = hb_tls_stream(response).first
      case protocol
      when 'SMTP'
        expect(sent).to match(/\AEHLO [a-zA-Z]{10}\r\nSTARTTLS\r\n\z/)
        expect(received).to include("220 Ready to start TLS\r\n")
      when 'IMAP'
        expect(sent).to eq("a001 CAPABILITY\r\na002 STARTTLS\r\n")
        expect(received).to include("a002 OK Begin TLS negotiation now\r\n")
      when 'POP3'
        expect(sent).to eq("CAPA\r\nSTLS\r\n")
        expect(received).to include("+OK Begin TLS negotiation\r\n")
      when 'FTP'
        expect(sent).to eq("AUTH TLS\r\n")
        expect(received).to include("234 AUTH TLS successful\r\n")
      when 'POSTGRES'
        expect(sent).to eq([8, 80_877_103].pack('N2'))
        expect(received).to eq('S')
      when 'JABBER'
        expect(sent).to include("to='localhost'>", "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        expect(received).to end_with("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
      end
      hb_journal('upgrade-wire-proofs.jsonl', workspace: @workspace, protocol: protocol, sent_base64: Base64.strict_encode64(sent), received_base64: Base64.strict_encode64(received))
    end

    def hb_verify_leak(options, dump:, complete: true, expected_length: nil, expected_loot: nil)
      2.times do
        previous = hb_loot.map { |row| row.fetch('id') }
        output, streams = hb_call(options.merge('ACTION' => dump ? 'DUMP' : 'SCAN'))
        expect(output).to include('Heartbeat response with leak,')
        hb_verify_upgrade(streams, options.fetch('TLS_CALLBACK')) if options.key?('TLS_CALLBACK')
        payloads = hb_payloads(streams, complete: complete)
        expect(payloads.length).to eq(options.fetch('LEAK_COUNT', 1))
        payloads.each { |payload| expect(payload.bytesize).to eq(expected_length || options.fetch('HEARTBEAT_LENGTH', 65535)) }
        current = hb_loot.reject { |row| previous.include?(row.fetch('id')) }
        if dump
          expect(current.length).to eq(1)
          row = current.first
          expect(row).to include('ltype' => 'openssl.heartbleed.server', 'content_type' => 'application/octet-stream', 'address' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'))
          actual = Base64.strict_decode64(target_exec('framework', 'base64', '-w0', row.fetch('path')))
          expected = expected_loot.nil? ? payloads.join : expected_loot
          hb_journal('loot-wire-comparisons.jsonl', id: row.fetch('id'), actual_bytes: actual.bytesize, expected_bytes: expected.bytesize, actual_sha256: Digest::SHA256.hexdigest(actual), expected_sha256: Digest::SHA256.hexdigest(expected), exact: actual == expected)
          expect(Base64.strict_encode64(actual)).to eq(Base64.strict_encode64(expected))
        else
          expect(current).to eq([])
        end
        expect(hb_reports).to contain_exactly(include('port' => options.fetch('RPORT', 10000), 'proto' => 'tcp', 'service_id' => be_a(Integer)))
      end
    end

    def hb_keys(found:)
      2.times do |iteration|
        previous = hb_loot.map { |row| row.fetch('id') }
        output, streams = hb_call({ 'ACTION' => 'KEYS', 'RPORT' => 11100, 'MAX_KEYTRIES' => 1, 'HEARTBEAT_LENGTH' => found ? 65535 : 1 })
        expect(hb_payloads(streams).map(&:bytesize)).to eq([found ? 65535 : 1])
        rows = hb_loot.reject { |row| previous.include?(row.fetch('id')) }
        if found
          expect(output).to include('Got the private key')
          expect(rows).to contain_exactly(include('content_type' => 'text/plain', 'ltype' => 'openssl.heartbleed.server'))
          pem = target_exec('framework', 'cat', rows.first.fetch('path'))
          private_key = OpenSSL::PKey::RSA.new(pem)
          certificate = OpenSSL::X509::Certificate.new(@native.fetch('certificates').fetch('cert.pem'))
          challenge = "Heartbleed #{@workspace} #{iteration}"
          signature = private_key.sign(OpenSSL::Digest.new('SHA256'), challenge)
          verified = certificate.public_key.verify(OpenSSL::Digest.new('SHA256'), signature, challenge)
          hb_journal('key-proofs.jsonl', loot_id: rows.first.fetch('id'), certificate_sha256: Digest::SHA256.hexdigest(certificate.to_der), private_key_sha256: Digest::SHA256.hexdigest(pem), challenge: challenge, signature_base64: Base64.strict_encode64(signature), verified_against_native_certificate: verified)
          expect(verified).to be(true)
        else
          expect(output).to include('Private key not found.')
          expect(rows).to eq([])
        end
        expect(hb_reports).to contain_exactly(include('port' => 11100, 'proto' => 'tcp', 'service_id' => be_a(Integer)))
      end
    end
  end
end
