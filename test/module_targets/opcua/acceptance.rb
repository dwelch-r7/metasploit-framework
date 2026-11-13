# frozen_string_literal: true

require_relative '../freeswitch_execution/acceptance'

module Acceptance
  # Reuse the qualified SQL, capture reassembly, journals and resource controls.
  module Opcua
    include FreeSwitchExecution

    OPCUA_OWNER = 'auxiliary/scanner/scada/opcua_enum'

    def opcua_native(phase)
      argv = ['framework', 'ruby', 'test/module_targets/opcua/native_probe.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      protocol = JSON.parse(target_exec(*argv))
      clients = [4840, 4841, 5840].map do |port|
        output = target_exec('target', '/opt/opcua-bin/opcua-lab-client', "opc.tcp://127.0.0.1:#{port}")
        expect(output).to include('OPCUA_NATIVE_ENDPOINT_STATUS=Good', 'OPCUA_NATIVE_SESSION_STATUS=Good', 'OPCUA_NATIVE_VERSION=1.5.10')
        { port: port, output: output }
      end
      rejected = target_exec('target', '/opt/opcua-bin/opcua-lab-client', 'opc.tcp://127.0.0.1:5841', expected_exit: 1)
      expect(rejected).not_to include('OPCUA_NATIVE_VERSION=')
      identity = target_exec('target', 'python3', '-c', 'import json,pathlib;p=pathlib.Path("/tmp/opcua-lab");print(json.dumps([{ "pid":i,"stat":pathlib.Path(f"/proc/{i}/stat").read_text()} for i in json.loads((p/"pids.json").read_text())]))')
      checksum = target_exec('target', 'sh', '-c', 'cd /opt/opcua-bin && sha256sum -c binaries.sha256')
      expect(checksum.lines.size).to eq(2)
      packages = target_exec('target', 'cat', '/opt/runtime-packages.tsv')
      record = { protocol: protocol, clients: clients, truncated_native_client: rejected, identity: JSON.parse(identity).map { |row| [row.fetch('pid'), row.fetch('stat').split(') ', 2).last.split.fetch(19)] }, binary_manifest: target_exec('target', 'cat', '/opt/opcua-bin/binaries.sha256'), packages_sha256: Digest::SHA256.hexdigest(packages) }
      fx_record('opcua-native-phases.jsonl', phase: phase, native: record)
      record
    end

    def opcua_services
      raise ArgumentError, 'Invalid controlled workspace' unless @workspace.match?(/\Aopcua_[0-9_]+\z/)

      rows = JSON.parse(fs_sql("SELECT coalesce(json_agg(row ORDER BY row.port),'[]'::json) FROM (SELECT service.id,host(host.address) AS host,service.port,service.proto,service.name,service.state,service.info FROM services service JOIN hosts host ON host.id=service.host_id JOIN workspaces workspace ON workspace.id=host.workspace_id WHERE workspace.name='#{@workspace}') row"))
      fx_record('opcua-service-snapshots.jsonl', workspace: @workspace, rows: rows)
      rows
    end

    def opcua_call(port)
      @call = (@call || 0) + 1
      stem = "#{@workspace}-#{@call}"
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/freeswitch/capture.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), port.to_s]
      output = nil
      Open3.popen3(*argv) do |input, capture, errors, wait|
        expect(IO.select([capture], nil, nil, 8)).not_to be_nil
        expect(capture.gets).to eq("FREESWITCH_CAPTURE_READY\n")
        begin
          output = run_target_module(OPCUA_OWNER, 'target', { 'RPORT' => port, 'THREADS' => 1, 'ConnectTimeout' => 2 }, allow_errors: true)
        ensure
          input.puts('STOP')
          input.close
          expect(wait.join(10)).not_to be_nil
          raw = capture.read
          File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.json'), raw)
          expect(wait.value.exitstatus).to eq(0), errors.read
          packets = JSON.parse(raw).fetch('packets')
          streams = fs_streams(packets).map do |stream|
            bytes = stream.delete(:text)
            stream.merge(base64: Base64.strict_encode64(bytes), sha256: Digest::SHA256.hexdigest(bytes))
          end
          fx_record('opcua-owning-calls.jsonl', workspace: @workspace, call: @call, port: port, output: output || console.all_data, streams: streams)
          request = streams.select { |stream| stream.fetch(:direction) == 'request' }.map { |stream| Base64.strict_decode64(stream.fetch(:base64)) }.join
          if port == 1
            expect(packets.any? { |packet| (packet.fetch('flags') & 4).positive? }).to be(true)
          else
            expect(request).to start_with('HELF')
            expect(request.bytesize).to eq(request.byteslice(4, 4).unpack1('V'))
          end
        end
      end
      output.dup.force_encoding(Encoding::UTF_8)
    end

    def opcua_expected(port)
      row = @native.fetch(:protocol).fetch('records').fetch(port.to_s)
      if row.fetch('type') == 'ACK'
        values = row.fetch('ack')
        ['ACK', "ProtocolVersion=#{values.fetch('protocol_version')} RecvBuf=#{values.fetch('receive_buffer')} SendBuf=#{values.fetch('send_buffer')}"]
      else
        ['ERR', row.fetch('status_code')]
      end
    end

    def opcua_verify(port)
      type, info = opcua_expected(port)
      output = opcua_call(port)
      expect(output).to include("OPC-UA server detected (#{type}) - #{info}")
      expect(opcua_services).to include(include('host' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => port, 'proto' => 'tcp', 'name' => 'opc-ua', 'state' => 'open', 'info' => "OPC-UA server (#{type}): #{info}"))
    end
  end
end
