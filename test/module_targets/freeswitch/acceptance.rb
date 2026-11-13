# frozen_string_literal: true

require 'base64'
require 'digest'
require 'json'
require 'open3'
require 'socket'

module Acceptance
  # Genuine wire, process, configuration and persisted-credential controls.
  module FreeSwitch
    OWNER = 'auxiliary/scanner/misc/freeswitch_event_socket_login'

    def fs_journal(name, record)
      File.open(File.join(target_runtime.fetch('artifacts'), name), 'a') { |file| file.puts(JSON.generate(record)) }
    end

    def fs_sql(query)
      target_exec('reporting_db', 'env', 'PGPASSWORD=module-target-framework-db-password', 'psql', '-h', '127.0.0.1', '-U', 'module_framework', '-d', 'module_targets', '-v', 'ON_ERROR_STOP=1', '-Atc', query)
    end

    def fs_credentials
      raise ArgumentError, 'Invalid lab workspace' unless @workspace.match?(/\Afs_[0-9_]+\z/)

      rows = JSON.parse(fs_sql(<<~SQL))
        SELECT coalesce(json_agg(row ORDER BY row.core_id,row.login_id), '[]'::json) FROM (
          SELECT c.id AS core_id,p.username,secret.data AS private_data,secret.type AS private_type,
            l.id AS login_id,l.status,l.last_attempted_at,l.access_level,host(h.address) AS address,
            s.port,s.proto,s.name,o.module_full_name AS module_fullname
          FROM metasploit_credential_cores c JOIN workspaces w ON w.id=c.workspace_id
          LEFT JOIN metasploit_credential_publics p ON p.id=c.public_id
          LEFT JOIN metasploit_credential_privates secret ON secret.id=c.private_id
          LEFT JOIN metasploit_credential_logins l ON l.core_id=c.id
          LEFT JOIN services s ON s.id=l.service_id LEFT JOIN hosts h ON h.id=s.host_id
          LEFT JOIN metasploit_credential_origin_services o ON o.id=c.origin_id AND c.origin_type='Metasploit::Credential::Origin::Service'
          WHERE w.name='#{@workspace}'
        ) row
      SQL
      fs_journal('native-credential-snapshots.jsonl', workspace: @workspace, credentials: rows)
      rows
    end

    def fs_native_phase(phase)
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'env', "FREESWITCH_MODE=#{@mode}", "FREESWITCH_PASSWORD=#{@password}", 'ruby', 'test/module_targets/freeswitch/native_probe.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), phase]
      output, error, status = Open3.capture3(*argv)
      fs_journal('native-controls.jsonl', argv: argv, actual_exit: status.exitstatus, stdout: output, stderr: error)
      expect(status.success?).to be(true), output + error
      native = JSON.parse(output)
      expect(native.fetch('status')).to eq('native_passed')
      expect(native.fetch('refused_port')).to be(true)
      return native if @mode == 'unrelated'

      expect(target_exec('target', 'sha256sum', '-c', '/lab/binaries.sha256').lines.length).to eq(6)
      version = target_exec('target', 'freeswitch', '-version')
      expect(version).to include('1.10.10-release', '4cb05e7f4a')
      local = target_exec('target', 'fs_cli', '-p', @password, '-x', 'status')
      expect(local).to include('FreeSWITCH (Version 1.10.10-release', '0 session(s) since startup', '0 session(s) - peak 0')
      expect(target_exec('target', 'fs_cli', '-p', @password, '-x', 'module_exists mod_event_socket').strip).to eq('true')
      native
    end

    def fs_state
      return target_exec('target', 'cat', '/proc/1/stat').split(') ', 2).last.split.fetch(19) if @mode == 'unrelated'

      target_exec('target', '/bin/sh', '-c', 'pid=$(cat /tmp/module-target-engine.pid); readlink /proc/"$pid"/exe; cat /proc/"$pid"/stat; sha256sum /usr/local/freeswitch/conf/autoload_configs/event_socket.conf.xml /usr/local/freeswitch/conf/autoload_configs/acl.conf.xml').lines.then do |lines|
        expect(lines.first.strip).to eq('/usr/local/freeswitch/bin/freeswitch')
        [lines[0], lines[1].split(') ', 2).last.split.fetch(19), *lines.drop(2)]
      end
    end

    def fs_streams(packets)
      groups = packets.reject { |packet| Base64.strict_decode64(packet.fetch('payload_base64')).empty? }.group_by do |packet|
        packet.values_at('direction', 'source', 'source_port', 'destination', 'destination_port')
      end
      groups.map do |key, fragments|
        position = fragments.map { |packet| packet.fetch('sequence') }.min
        bytes = ''.b
        fragments.sort_by { |packet| packet.fetch('sequence') }.each do |packet|
          sequence = packet.fetch('sequence')
          raise 'Gap in captured TCP stream' if sequence > position

          payload = Base64.strict_decode64(packet.fetch('payload_base64'))
          skipped = position - sequence
          bytes << payload.byteslice(skipped..) if skipped < payload.bytesize
          position = [position, sequence + payload.bytesize].max
        end
        { direction: key[0], source: key[1], source_port: key[2], destination: key[3], destination_port: key[4], text: bytes.force_encoding(Encoding::UTF_8) }
      end
    end

    def fs_call(options = {}, action: 'run')
      @call = (@call || 0) + 1
      stem = "#{@workspace}-#{@call}"
      port = options.fetch('RPORT', target_runtime.fetch('module_endpoints').fetch('target').fetch('port'))
      argv = target_runtime.fetch('compose') + ['exec', '-T', 'framework', 'ruby', 'test/module_targets/freeswitch/capture.rb', ENV.fetch('MODULE_TARGET_RUNTIME'), port.to_s]
      output = nil
      raw = nil
      wait_status = nil
      capture_errors = nil
      begin
        Open3.popen3(*argv) do |input, captured, errors, wait|
          expect(IO.select([captured], nil, nil, 8)).not_to be_nil
          expect(captured.gets).to eq("FREESWITCH_CAPTURE_READY\n")
          output = run_target_module(OWNER, 'target', { 'PASS_FILE' => '', 'THREADS' => 1, 'BRUTEFORCE_SPEED' => 5, 'ConnectTimeout' => 3 }.merge(options), action: action, allow_errors: true, command_timeout: 40)
        ensure
          begin
            input.puts('STOP')
          rescue Errno::EPIPE, IOError
            # Retain the observer's actual terminal output below.
          end
          input.close
          unless wait.join(5)
            Process.kill('TERM', wait.pid)
            wait.join(3)
          end
          raw = captured.read
          capture_errors = errors.read
          wait_status = wait.value.exitstatus
        end
      ensure
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.json'), raw.to_s)
        File.write(File.join(target_runtime.fetch('artifacts'), stem + '-wire.stderr'), capture_errors.to_s)
        fs_journal('owning-calls.jsonl', workspace: @workspace, owner: OWNER, action: action, options: options, output: (output || console.all_data).dup.force_encoding(Encoding::UTF_8), wrapper_returned: !output.nil?, capture_actual_exit: wait_status)
      end
      expect(wait_status).to eq(0), capture_errors
      expect(capture_errors).to eq('')
      packets = JSON.parse(raw).fetch('packets')
      streams = fs_streams(packets)
      fs_journal('verified-wire.jsonl', workspace: @workspace, action: action, options: options, streams: streams, packets: packets.length)
      [output.dup.force_encoding(Encoding::UTF_8), streams]
    end

    def fs_verify(options = {}, action: 'run', expected_password: nil, attempts: nil, check_reason: nil)
      identities = []
      2.times do
        output, streams = fs_call(options, action: action)
        expect(output).not_to match(/Auxiliary failed|Call stack:|Unknown datastore option/)
        expect(output).to include(check_reason) if check_reason
        requests = streams.select { |row| row.fetch(:direction) == 'request' }.map { |row| row.fetch(:text) }
        expect(requests).to eq(attempts.map { |password| "auth #{password}\n\n" }) if attempts
        replies = streams.select { |row| row.fetch(:direction) == 'response' }.map { |row| row.fetch(:text) }
        credentials = fs_credentials
        if expected_password
          expect(output).to include("Login Successful: #{expected_password}")
          expect(replies.count { |text| text.include?('Reply-Text: +OK accepted') }).to eq(1)
          expect(credentials.length).to eq(1)
          row = credentials.first
          expect(row.slice('username', 'private_data', 'private_type', 'status', 'address', 'port', 'proto', 'name', 'module_fullname')).to eq(
            'username' => nil, 'private_data' => expected_password, 'private_type' => 'Metasploit::Credential::Password', 'status' => 'Successful',
            'address' => target_runtime.fetch('module_endpoints').fetch('target').fetch('host'), 'port' => 8021, 'proto' => 'tcp', 'name' => 'freeswitch', 'module_fullname' => OWNER
          )
          expect(row.fetch('last_attempted_at')).not_to be_nil
          identities << row.values_at('core_id', 'login_id')
        else
          expect(output).not_to include('Login Successful:')
          expect(replies.join).not_to include('Reply-Text: +OK accepted')
          expect(credentials).to eq([])
        end
      end
      expect(identities.uniq.length).to eq(1) if expected_password
    end
  end
end
