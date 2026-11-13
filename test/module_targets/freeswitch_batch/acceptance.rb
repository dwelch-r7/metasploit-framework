# frozen_string_literal: true

require_relative '../freeswitch/acceptance'

module Acceptance
  # Keep each genuine service's native result and persisted identity distinct.
  module FreeSwitchBatch
    include Acceptance::FreeSwitch

    def batch_host(role)
      return @refused_host if role == 'refused'

      target_runtime.fetch('module_endpoints').fetch(role).fetch('host')
    end

    def batch_native_phase(phase)
      %w[target second].each do |role|
        mode = @batch_mode == 'acl' && role == 'second' ? 'acl' : 'allowed'
        password = role == 'second' && @batch_mode == 'passwords' ? 'module-target-Ω spaced' : 'ClueCon'
        runtime = target_runtime.merge('module_endpoints' => target_runtime.fetch('module_endpoints').merge('target' => target_runtime.fetch('module_endpoints').fetch(role)))
        path = File.join(target_runtime.fetch('artifacts'), "native-#{role}-runtime.json")
        File.write(path, JSON.generate(runtime))
        output = target_exec('framework', 'env', "FREESWITCH_MODE=#{mode}", "FREESWITCH_PASSWORD=#{password}", 'ruby', 'test/module_targets/freeswitch/native_probe.rb', path, "#{phase}-#{role}")
        native = JSON.parse(output)
        expect(native.fetch('status')).to eq('native_passed')
        expect(native.fetch('refused_port')).to be(true)
        expect(target_exec(role, 'sha256sum', '-c', '/lab/binaries.sha256').lines.length).to eq(6)
        status = target_exec(role, 'fs_cli', '-p', password, '-x', 'status')
        expect(status).to include('FreeSWITCH (Version 1.10.10-release', '0 session(s) since startup', '0 session(s) - peak 0')
        fs_journal('batch-native-controls.jsonl', phase: phase, role: role, mode: mode, native: native)
      end
      code = 'ip=Addrinfo.tcp("reporting_db",8021).ip_address; begin; Socket.tcp(ip,8021,connect_timeout:3).close; raise "Unexpected event-socket listener"; rescue Errno::ECONNREFUSED; puts JSON.generate(host:ip,port:8021,refused:true); end'
      refused = JSON.parse(target_exec('framework', 'ruby', '-rjson', '-rsocket', '-e', code))
      expect(refused.fetch('refused')).to be(true)
      @refused_host = refused.fetch('host')
      fs_journal('batch-native-controls.jsonl', phase: phase, role: 'reporting_db', native: refused)
    end

    def batch_state
      %w[target second].to_h do |role|
        lines = target_exec(role, '/bin/sh', '-c', 'pid=$(cat /tmp/module-target-engine.pid); readlink /proc/"$pid"/exe; cat /proc/"$pid"/stat; sha256sum /usr/local/freeswitch/conf/autoload_configs/event_socket.conf.xml /usr/local/freeswitch/conf/autoload_configs/acl.conf.xml').lines
        expect(lines.first.strip).to eq('/usr/local/freeswitch/bin/freeswitch')
        [role, [lines.first, lines[1].split(') ', 2).last.split.fetch(19), *lines.drop(2)]]
      end
    end

    def batch_capture_runtime
      # This is a packet-filter input derived from real container DNS/native
      # controls. The module and original runtime retain their actual endpoints.
      runtime = target_runtime.merge('module_endpoints' => target_runtime.fetch('module_endpoints').merge('refused' => { 'host' => @refused_host, 'port' => 8021 }))
      path = File.join(target_runtime.fetch('artifacts'), 'batch-capture-runtime.json')
      File.write(path, JSON.generate(runtime))
      path
    end

    def batch_verify(roles = %w[target second], options: {}, successes: {}, attempts: nil, action: 'run', host_file: false)
      hosts = roles.map { |role| batch_host(role) }
      rhosts = hosts.join(' ')
      if host_file
        path = File.join(target_runtime.fetch('artifacts'), 'batch-hosts.txt')
        File.write(path, hosts.join("\n") + "\n")
        rhosts = 'file:' + path
      end
      expected = successes.transform_keys { |role| batch_host(role) }
      identities = []
      2.times do
        output, streams = fs_call({ 'RHOSTS' => rhosts, 'PASSWORD' => 'ClueCon' }.merge(options), action: action, capture_runtime: batch_capture_runtime)
        expect(output).not_to match(/Auxiliary failed|Call stack:|Unknown datastore option/)
        credentials = fs_credentials
        expect(credentials.map { |row| row.fetch('address') }.sort).to eq(expected.keys.sort)
        credentials.each do |row|
          expect(row.slice('username', 'private_data', 'private_type', 'status', 'port', 'proto', 'name', 'module_fullname')).to eq(
            'username' => nil, 'private_data' => expected.fetch(row.fetch('address')), 'private_type' => 'Metasploit::Credential::Password',
            'status' => 'Successful', 'port' => 8021, 'proto' => 'tcp', 'name' => 'freeswitch', 'module_fullname' => Acceptance::FreeSwitch::OWNER
          )
          expect(row.fetch('last_attempted_at')).not_to be_nil
        end
        identities << credentials.map { |row| row.values_at('address', 'core_id', 'login_id') }.sort
        roles.each do |role|
          host = batch_host(role)
          requests = streams.select { |row| row.fetch(:direction) == 'request' && row.fetch(:destination) == host }.map { |row| row.fetch(:text) }
          replies = streams.select { |row| row.fetch(:direction) == 'response' && row.fetch(:source) == host }.map { |row| row.fetch(:text) }
          expect(replies.count { |text| text.include?('Reply-Text: +OK accepted') }).to eq(expected.key?(host) ? 1 : 0)
          if attempts && attempts.key?(role)
            expect(requests).to eq(attempts.fetch(role).map { |password| "auth #{password}\n\n" })
          end
          expect(replies.join).to include('auth/request') if action == 'check' && role != 'refused'
        end
        fs_journal('verified-batch.jsonl', workspace: @workspace, roles: roles, action: action, options: options, expected: expected, credentials: credentials, hosts: hosts)
      end
      expect(identities[0]).to eq(identities[1])
    end
  end
end
